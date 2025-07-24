const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const otplib = require('otplib');
const bcrypt = require('bcrypt');
const qrcode = require('qrcode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid'); 
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

const app = express();

app.use(cookieParser());

const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");

const io = new Server(server, {
    cors: {
      origin: "http://localhost:3001", // client origin
      methods: ["GET", "POST"],
      credentials: true
    }
});

app.use(cors());
app.use(bodyParser.json());
app.use('/auth/login', rateLimit({ windowMs: 1 * 60 * 1000, max: 5 }));

// File paths for storage
const STORAGE_PATH = path.join(__dirname, 'data');
const USERS_FILE = path.join(STORAGE_PATH, 'users.json');
const MESSAGES_FILE = path.join(STORAGE_PATH, 'messages.json');
const SESSIONS_FILE = path.join(STORAGE_PATH, 'sessions.json');
const PUBLIC_KEYS_FILE = path.join(STORAGE_PATH, 'public_keys.json');

// Ensure storage directory exists
if (!fs.existsSync(STORAGE_PATH)) {
    fs.mkdirSync(STORAGE_PATH);
}
// Helper function to read JSON files
function readJSONFile(filePath, defaultValue = {}) {
    try {
        if (fs.existsSync(filePath)) {
            const fileContent = fs.readFileSync(filePath, 'utf8').trim();
            
            // Handle empty files
            if (!fileContent) {
                // Initialize with default value
                fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2));
                return defaultValue;
            }
            
            try {
                return JSON.parse(fileContent);
            } catch (parseError) {
                console.error(`Invalid JSON in ${filePath}, initializing with defaults`);
                // Backup corrupted file
                const backupPath = `${filePath}.corrupted-${Date.now()}`;
                fs.renameSync(filePath, backupPath);
                console.log(`Corrupted file backed up to ${backupPath}`);
                // Initialize with default value
                fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2));
                return defaultValue;
            }
        } else {
            // File doesn't exist, create it with default value
            fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2));
            return defaultValue;
        }
    } catch (err) {
        console.error(`Error handling ${filePath}:`, err);
        return defaultValue;
    }
}

// Helper function to write JSON files
function writeJSONFile(filePath, data) {
    try {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
        return true;
    } catch (err) {
        console.error(`Error writing ${filePath}:`, err);
        return false;
    }
}

// Initialize data stores
let users = readJSONFile(USERS_FILE, {});
let sessions = readJSONFile(SESSIONS_FILE, {});
let userPublicKeys = readJSONFile(PUBLIC_KEYS_FILE, {});
let messages = readJSONFile(MESSAGES_FILE, {});

// Verify and repair data structures on startup
function verifyDataStructures() {
    // Ensure each is an object
    if (typeof users !== 'object') users = {};
    if (typeof sessions !== 'object') sessions = {};
    if (typeof userPublicKeys !== 'object') userPublicKeys = {};
    if (typeof messages !== 'object') messages = {};
    
    // Write corrected structures back to files
    writeJSONFile(USERS_FILE, users);
    writeJSONFile(SESSIONS_FILE, sessions);
    writeJSONFile(PUBLIC_KEYS_FILE, userPublicKeys);
    writeJSONFile(MESSAGES_FILE, messages);
}

// Run verification on startup
verifyDataStructures();

// Persist data to disk periodically
setInterval(() => {
    writeJSONFile(USERS_FILE, users);
    writeJSONFile(SESSIONS_FILE, sessions);
    writeJSONFile(PUBLIC_KEYS_FILE, userPublicKeys);
    writeJSONFile(MESSAGES_FILE, messages);
    console.log('Data persisted to disk');
}, 30000); // Every 30 seconds

const userSockets = {};
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;

    if (users[username]) {
        return res.status(400).json({ error: 'Username taken' });
    }

    // Generate MFA secret
    const mfaSecret = otplib.authenticator.generateSecret();
    const hashedPassword = await bcrypt.hash(password, 12);
    users[username] = { 
        password: hashedPassword, 
        mfaSecret,
        mfaVerified: false,
        publicKeys: null // will be set via WebSocket later
    };
    // Write to disk immediately
    writeJSONFile(USERS_FILE, users);

    // Return QR code for MFA setup
    const otpauth = otplib.authenticator.keyuri(username, 'end2end', mfaSecret);
    const qr = await qrcode.toDataURL(otpauth);

    // Just return the QR code, no session cookie yet
    res.json({ success: true, qr: qr });
});

app.post('/auth/login', async (req, res) => {
    const { username, password, token } = req.body;
    const user = users[username];
    if (!user) {
        return res.status(400).json({ error: "Invalid username or password" });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
        return res.status(400).json({ error: "Invalid username or password" });
    }

    // Validate MFA token
    const isMfaValid = otplib.authenticator.check(token, user.mfaSecret);
    if (!isMfaValid) {
        return res.status(401).json({ error: 'Invalid MFA token' });
    }
    if (req.cookies.sessionToken) {
        delete sessions[req.cookies.sessionToken];
    }

    // Create session
    const sessionToken = createSession(username);
    // Update sessions and save
    sessions[sessionToken] = {
        username,
        expires: Date.now() + 1000 * 60 * 60 * 4 // 4 hours
    };
    writeJSONFile(SESSIONS_FILE, sessions);
    
    // Set secure, HttpOnly cookie
    res.cookie('sessionToken', sessionToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 4, // 4 hours
        path: '/'
    }).json({ 
        success: true,
        token: sessionToken
    });
});

app.post('/auth/verify-mfa', (req, res) => {
    const { username, token } = req.body;

    const user = users[username];
    if (!user || !user.mfaSecret) {
        return res.status(400).json({ error: 'Invalid user or MFA not set up' });
    }

    const isValid = otplib.authenticator.check(token, user.mfaSecret);
    if (!isValid) {
        return res.status(401).json({ error: 'Invalid MFA token' });
    }
    user.mfaVerified = true;

    const sessionToken = createSession(username);
    
    res.cookie('sessionToken', sessionToken, {
        httpOnly: true,
        secure: false, // false for localhost, true in production
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 4, // 4 hours
        path: '/',
    }).json({ 
        success: true, 
        message: 'MFA verified successfully',
        token: sessionToken 
    });
});

app.post('/auth/logout', (req, res) => {
    if (req.cookies.sessionToken) {
        delete sessions[req.cookies.sessionToken];
    }
    res.clearCookie('sessionToken').sendStatus(200);
});

io.use((socket, next) => {
    // Socket.IO cookie parsing
    const cookieHeader = socket.handshake.headers.cookie;
    let token = null;
    
    if (cookieHeader) {
        // Parse cookies manually
        const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
            const [name, value] = cookie.trim().split('=');
            acc[name] = value;
            return acc;
        }, {});
        
        token = cookies.sessionToken;
    }
    
    // Also check if token was passed in auth during connection
    if (!token && socket.handshake.auth?.token) {
        token = socket.handshake.auth.token;
    }
    
    if (!token || !sessions[token] || sessions[token].expires < Date.now()) {
        return next(new Error('Unauthorized'));
    }

    // Refresh session expiration on connection
    sessions[token].expires = Date.now() + 1000 * 60 * 60 * 4; // 4 hours
    socket.username = sessions[token].username;
    socket.token = token;
    next();
});

io.on('connection', (socket) => {
    // All connections here are pre-authenticated
    console.log(`User ${socket.username} connected`);
    socket.on('disconnect', () => {
        console.log('user disconnected!');
        // Remove the socket from userSockets if found
        for (const [username, s] of Object.entries(userSockets)) {
            if (s === socket) {
                delete userSockets[username];
                console.log(`${username} removed from user list.`);
                break;
            }
        }
    });

    socket.on('authenticate', ({ token }) => {
        const session = sessions[token];
        if (!session) return socket.emit('unauthorized');
      
        const username = session.username;
        socket.emit('authenticated');
    });

    // Public keys are registered with the server, but private keys stay exclusively in memory
    socket.on("register keys", ({ username, ecdhPublicKey, signature, ed25519PublicKey }) => {
        socket.username = username;
        userPublicKeys[username] = { 
            ecdhPublicKey, 
            signature, 
            ed25519PublicKey 
        };
        userSockets[username] = socket;
        writeJSONFile(PUBLIC_KEYS_FILE, userPublicKeys);
        console.log(`✅ Updated keys for ${username}`);
    });

    socket.on("get public key bundle", (targetUsername, callback) => {
        const bundle = userPublicKeys[targetUsername];
        if (bundle) {
            callback({
                success: true,
                ...bundle
            });
        } else {
            callback({ success: false });
        }
    });

    socket.on("get users", (callback) => {
        callback(Object.keys(userSockets)); // `users` is a map of username → publicKey
    });

    socket.on('chat message', ({ from, to, timestamp, encryptedMessage, encryptedAESKey, iv, signature }) => {
        // Store the message first
        if (!messages[from]) messages[from] = {};
        if (!messages[from][to]) messages[from][to] = [];

        messages[from][to].push({
            from,
            to,
            timestamp,
            encryptedMessage,
            encryptedAESKey,
            iv,
            signature
        });

        // Also store in reverse for the recipient
        if (!messages[to]) messages[to] = {};
        if (!messages[to][from]) messages[to][from] = [];
        
        messages[to][from].push({
            from,
            to,
            timestamp,
            encryptedMessage,
            encryptedAESKey,
            iv,
            signature
        });

        writeJSONFile(MESSAGES_FILE, messages);

        console.log(`${timestamp} message to ${to}:`, encryptedMessage);
        const recipientSocket = userSockets[to];
        if (recipientSocket) {
            // Forward the message to the recipient only
            recipientSocket.emit('chat message', {
                from,
                to,
                timestamp,
                encryptedMessage,
                encryptedAESKey,
                iv,
                signature
            });
        } else {
            console.log(`User ${to} not connected.`);
        }
    });

    // endpoint to fetch message history
    socket.on('get message history', ({ withUser }, callback) => {
        try {
            if (!socket.username) {
                const error = { success: false, error: 'Not authenticated' };
                if (typeof callback === 'function') {
                    return callback(error);
                }
                return socket.emit('message history response', error);
            }
    
            if (!withUser) {
                const error = { success: false, error: 'Missing withUser parameter' };
                if (typeof callback === 'function') {
                    return callback(error);
                }
                return socket.emit('message history response', error);
            }
    
            // Get messages between current user and target user
            const userMessages = messages[socket.username]?.[withUser] || [];
            
            // Sort messages by timestamp
            const sortedMessages = userMessages.sort((a, b) => 
                new Date(a.timestamp) - new Date(b.timestamp)
            );
            
            const response = { 
                success: true, 
                withUser,
                messages: sortedMessages 
            };
            
            if (typeof callback === 'function') {
                callback(response);
            } else {
                // Emit the response as a regular event
                socket.emit('message history response', response);
            }
        } catch (err) {
            console.error('Error getting message history:', err);
            const error = { success: false, error: 'Server error' };
            if (typeof callback === 'function') {
                callback(error);
            } else {
                socket.emit('message history response', error);
            }
        }
    });
});

server.listen(3001, () => {
    console.log('listening on *:3001');
});

async function validateLogin(username, password, token) {
    const user = users[username];
    if (!user) return false;
  
    return otplib.authenticator.check(token, user.mfaSecret);
}

function createSession(username) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions[token] = {
        username,
        expires: Date.now() + 1000 * 60 * 60 * 4 // 4 hours
    };
    return token;
}

// Cleanup expired sessions
setInterval(() => {
    Object.entries(sessions).forEach(([token, session]) => {
        if (session.expires < Date.now()) delete sessions[token];
    });
    // Write all changes to disk
    writeJSONFile(SESSIONS_FILE, sessions);
    writeJSONFile(MESSAGES_FILE, messages);
}, 1000 * 60 * 30); // Every 30 minutes