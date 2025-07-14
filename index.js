const express = require('express');
const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);
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
                delete users[username];
                console.log(`${username} removed from user list.`);
                break;
            }
        }
    });

    socket.on('register user', ({ username, publicKey }) => {
        users[username] = publicKey;
        userSockets[username] = socket;
        console.log(`${username} registered`);
    });

    // Allow users to request another user's public key
    socket.on('get public key', (targetUsername, callback) => {
        const key = users[targetUsername];
        if (key) {
            callback({ success: true, publicKey: key });
        } else {
            callback({ success: false, error: "User not found" });
        }
    });

    socket.on("get users", (callback) => {
        callback(Object.keys(users)); // assuming `users` is a map of username → publicKey
    });

    socket.on('chat message', ({ to, from, timestamp, payload }) => {
        console.log(`message to ${to}:`, payload);
        const recipientSocket = userSockets[to];
        if (recipientSocket) {
            // Forward the message to the recipient only
            recipientSocket.emit('chat message', {
                from: from,
                timestamp: timestamp,
                encryptedMessage: payload.encryptedMessage,
                encryptedAESKey: payload.encryptedAESKey,
                iv: payload.iv
            });
        } else {
            console.log(`User ${to} not connected.`);
        }
    });
});

server.listen(3000, () => {
    console.log('listening on *:3000');
});