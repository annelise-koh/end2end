const express = require('express');
const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);
const userPublicKeys = {};
const users = {};

const userSockets = {};
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

io.on('connection', (socket) => {
    console.log('user connected!');
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
    // Register a new user account with username + password + keys
    socket.on('register', async ({ username, password, ecdhPublicKey, signature, ed25519PublicKey }, callback) => {
        if (users[username]) {
            callback({ success: false, message: 'Username already taken' });
            return;
        }
        users[username] = { password, ecdhPublicKey, signature, ed25519PublicKey };
        
        callback({ success: true, message: 'Registered successfully' });
        console.log(`✅ Registered ${username}`);
    });

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

    // Login with username + password
    socket.on('login', ({ username, password }, callback) => {
        const user = users[username];
        if (!user) {
            callback({ success: false, message: 'User does not exist' });
            return;
        }
        if (user.password !== password) {
            callback({ success: false, message: 'Incorrect password' });
            return;
        }
        // Save user's socket and keys on login
        socket.username = username;
        userSockets[username] = socket;
        userPublicKeys[username] = {
            ecdhPublicKey: user.ecdhPublicKey,
            signature: user.signature,
            ed25519PublicKey: user.ed25519PublicKey
        };
        callback({ success: true, message: 'Login successful' });
        console.log(`User logged in: ${username}`);
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