const express = require('express');
const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);
const userPublicKeys = {};
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

    socket.on("register user", ({ username, ecdhPublicKey, signature, ed25519PublicKey }) => {
        socket.username = username;
        userPublicKeys[username] = { ecdhPublicKey, signature, ed25519PublicKey };
        userSockets[username] = socket;
        console.log(`✅ Registered ${username}`);
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

    socket.on('chat message', ({ to, from, timestamp, payload }) => {
        console.log(`message to ${to}:`, payload);
        const recipientSocket = userSockets[to];
        if (recipientSocket) {
            // Forward the message to the recipient only
            recipientSocket.emit('chat message', {
                from: from,
                timestamp: timestamp,
                payload: payload
            });
        } else {
            console.log(`User ${to} not connected.`);
        }
    });
});

server.listen(3001, () => {
    console.log('listening on *:3001');
});