const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const otplib = require('otplib');
const bcrypt = require('bcrypt');
const qrcode = require('qrcode');
const crypto = require('crypto');
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

const userPublicKeys = {};
const users = {}; // In-memory: { email: { password, mfaSecret } }
const sessions = {};

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
}, 1000 * 60 * 30); // Every 30 minutes