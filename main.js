
var socket = io();

var form = document.getElementById('form');
var input = document.getElementById('input');
var messages = document.getElementById('messages');

let myKeyPair;
let receiverPublicKey; // placeholder for the recipient’s public key
// let myUsername = prompt("Enter your username:");
let myUsername;
let recipientUsername;

const chatList = document.getElementById('chat-list');
const chatHistory = {}; // key = username, value = array of messages
let currentChat = null;

// Call it as soon as the page loads
// generateKeyPair();
socket.on('connect', () => {
    console.log("Socket connected! Prompting for username...");
    myUsername = prompt("Enter your username:");
    if (!myUsername) {
        alert("Username is required. Reloading...");
        window.location.reload();
        return;
    }
    generateKeyPair(); // Now safe to run
});


// Generate key pair on load
async function generateKeyPair() {
    myKeyPair = await window.crypto.subtle.generateKey(
    {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
    );
    console.log("Key pair generated!");

    const exportedPublicKey = await exportPublicKey(myKeyPair.publicKey);

    // Send your username + public key to the server
    socket.emit("register user", {
        username: myUsername,
        publicKey: exportedPublicKey
    });

    socket.emit("get users", (userList) => {
        const datalist = document.getElementById("users");
        datalist.innerHTML = ""; // Clear old options
        userList.forEach((username) => {
            const option = document.createElement("option");
            option.value = username;
            datalist.appendChild(option);
        });
    });
}

const recipientInput = document.getElementById("recipient");
console.log("📌 Binding recipient input event");
recipientInput.addEventListener("change", async () => {
    const name = recipientInput.value.trim();
    if (!name) return;

    try {
        receiverPublicKey = await getPublicKeyForUser(name);
        recipientUsername = name;
        console.log(`✅ Now messaging ${name}`);
    } catch (err) {
        alert("❌ Could not find that user.");
    }
});

async function exportPublicKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

function getPublicKeyForUser(targetUsername) {
    return new Promise((resolve, reject) => {
        socket.emit('get public key', targetUsername, (response) => {
        if (response.success) {
            const keyBuffer = Uint8Array.from(atob(response.publicKey), c => c.charCodeAt(0));
            crypto.subtle.importKey(
            "spki",
            keyBuffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
            ).then(resolve).catch(reject);
        } else {
            reject("Public key not found");
        }
        });
    });
}

// Before sending a message, encrypt it with a symmetric AES key
async function encryptMessage(plaintext) {
    const enc = new TextEncoder();

    const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        enc.encode(plaintext)
    );

    return { aesKey, iv, ciphertext };
}
// Encrypt the AES key with the receiver's public key
async function encryptAESKey(aesKey, receiverPublicKey) {
    const exportedAESKey = await crypto.subtle.exportKey("raw", aesKey);
    const encryptedKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        receiverPublicKey,
        exportedAESKey
    );
    return encryptedKey;
}

async function decryptAESKey(encryptedKey, myPrivateKey) {
    const decrypted = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        myPrivateKey,
        encryptedKey
    );

    return await crypto.subtle.importKey(
        "raw",
        decrypted,
        { name: "AES-GCM" },
        true,
        ["decrypt"]
    );
    }

    async function decryptMessage(ciphertext, aesKey, iv) {
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        ciphertext
    );
    return new TextDecoder().decode(decrypted);
}

// Add user to chat list (left side)
function addToChatList(username) {
    if (!chatHistory[username]) {
        chatHistory[username] = [];
        const entry = document.createElement('div');
        entry.textContent = username;
        entry.classList.add('chat-entry');
        entry.addEventListener('click', () => {
            recipientUsername = username;
            currentChat = username;
            receiverPublicKey = null; // reset so it fetches fresh
            loadChat(username);
        });
        chatList.appendChild(entry);
    }
}

// Load messages for that chat
function loadChat(username) {
    const messagesEl = document.getElementById('messages');
    messagesEl.innerHTML = '';
    chatHistory[username].forEach((msg) => {
        const item = document.createElement('li');
        item.textContent = msg;
        messagesEl.appendChild(item);
    });
}

form.addEventListener('submit', async function(e) {
    e.preventDefault();
    if (!input.value) return;

    const plaintext = input.value;

    // Step 1: Encrypt the message with AES
    const { aesKey, iv, ciphertext } = await encryptMessage(plaintext);

    // Step 2: Encrypt the AES key with the receiver's RSA public key
    const encryptedKey = await encryptAESKey(aesKey, receiverPublicKey);

    // Step 3: Convert ciphertext, key, iv to base64 for sending
    const payload = {
        encryptedMessage: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        encryptedAESKey: btoa(String.fromCharCode(...new Uint8Array(encryptedKey))),
        iv: btoa(String.fromCharCode(...iv))
    };

    const timestamp = new Date().toISOString();
    
    socket.emit('chat message', {
        to: recipientUsername,
        from: myUsername,
        timestamp,
        payload: {
            encryptedMessage: payload.encryptedMessage,
            encryptedAESKey: payload.encryptedAESKey,
            iv: payload.iv
        }
    });

    input.value = ''; 
});

socket.on('chat message', async function(data) {
    const encryptedMessage = Uint8Array.from(atob(data.encryptedMessage), c => c.charCodeAt(0));
    const encryptedAESKey = Uint8Array.from(atob(data.encryptedAESKey), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));

    const aesKey = await decryptAESKey(encryptedAESKey, myKeyPair.privateKey);
    const message = await decryptMessage(encryptedMessage, aesKey, iv);

    // Format the timestamp
    const time = new Date(data.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const messageString = `[${time}] ${data.from}: ${message}`;

    // Save to history
    if (!chatHistory[data.from]) addToChatList(data.from);
    chatHistory[data.from].push(messageString);

    if (currentChat === data.from || currentChat === null) {
        currentChat = data.from;
        loadChat(data.from);
    }

    window.scrollTo(0, document.body.scrollHeight);
});
