
var socket = io();

var form = document.getElementById('form');
var input = document.getElementById('input');
var messages = document.getElementById('messages');

let receiverPublicKey;
let myUsername;
let recipientUsername;
let myECDHKeyPair;
let mySigningKeyPair;

const chatList = document.getElementById('chat-list');
const chatHistory = {}; // key = username, value = array of messages
const edPublicKeys = {};
let currentChat = null;

// Track connection state
let isConnected = false;
socket.on('connect', async () => {
    console.log("Socket connected!");
    isConnected = true;
    await handleConnection();
});

// Also handle case where connection is already established
if (socket.connected) {
    isConnected = true;
    handleConnection();
}

// Call it as soon as the page loads
async function handleConnection() {
    document.getElementById('register-btn').onclick = async () => {
        await handleRegistration();
        document.getElementById('auth-container').style.display = 'none';
    };

    document.getElementById('login-btn').onclick = async () => {
        await handleLogin();
        document.getElementById('auth-container').style.display = 'none';
    }
};

async function handleLogin() {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    if (!username || !password) return alert("Username and password required");

    socket.emit('login', { username, password }, async (response) => {
        if (response.success) {
            myUsername = username;
            alert("Login successful!");

            // Generate key pairs and register your keys
            await generateKeyPairs();
            const signedECDH = await signECDHPublicKey();
            const rawEdPub = await crypto.subtle.exportKey("raw", mySigningKeyPair.publicKey);
            const ed25519PublicKey = btoa(String.fromCharCode(...new Uint8Array(rawEdPub)));

            socket.emit("register keys", {
                username,
                ecdhPublicKey: signedECDH.rawECDHPubKey,
                signature: signedECDH.signature,
                ed25519PublicKey
            });

            // Hide auth UI, show chat UI
            document.getElementById("auth-container").style.display = "none";
            document.getElementById("chat-container").style.display = "block";

        } else {
            alert("Login failed: " + response.message);
            window.location.reload();
        }
    });
}

async function handleRegistration() {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    if (!username || !password) return alert("Username and password required");

    await generateKeyPairs();
    const signedECDH = await signECDHPublicKey();
    const rawEdPub = await crypto.subtle.exportKey("raw", mySigningKeyPair.publicKey);
    const ed25519PublicKey = btoa(String.fromCharCode(...new Uint8Array(rawEdPub)));

    socket.emit('register', {
        username,
        password,
        ecdhPublicKey: signedECDH.rawECDHPubKey,
        signature: signedECDH.signature,
        ed25519PublicKey
    }, async (response) => {
        if (response.success) {
            alert("Registration successful!");
            await handleLogin(); // Automatically log in
        } else {
            alert("Registration failed: " + response.message);
        }
    });
}

async function generateKeyPairs() {
    // ECDH (key agreement)
    myECDHKeyPair = await crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256"
        },
        true,
        ["deriveKey", "deriveBits"]
    );

    // Ed25519 (signing)
    mySigningKeyPair = await crypto.subtle.generateKey(
        {
            name: "Ed25519",
        },
        true,
        ["sign", "verify"]
    );
}

async function signECDHPublicKey() {
    const rawPubKey = await crypto.subtle.exportKey("raw", myECDHKeyPair.publicKey);
    const signature = await crypto.subtle.sign(
        "Ed25519",
        mySigningKeyPair.privateKey,
        rawPubKey
    );
    return {
        rawECDHPubKey: btoa(String.fromCharCode(...new Uint8Array(rawPubKey))),
        signature: btoa(String.fromCharCode(...new Uint8Array(signature)))
    };
}

async function verifyECDHPublicKey(peerECDHPubBase64, peerSignatureBase64, peerVerifyKey) {
    const rawECDHPub = Uint8Array.from(atob(peerECDHPubBase64), c => c.charCodeAt(0));
    const signature = Uint8Array.from(atob(peerSignatureBase64), c => c.charCodeAt(0));

    const valid = await crypto.subtle.verify(
        "Ed25519",
        peerVerifyKey,
        signature,
        rawECDHPub
    );

    if (!valid) throw new Error("ECDH key signature invalid");

    return await crypto.subtle.importKey(
        "raw",
        rawECDHPub,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
    );
}

const recipientInput = document.getElementById("recipient");
console.log("📌 Binding recipient input event");
recipientInput.addEventListener("change", async () => {
    const name = recipientInput.value.trim();
    if (!name) return;

    socket.emit("get public key bundle", name, async (data) => {
        if (!data.success) {
            alert("❌ Could not fetch recipient's keys.");
            return;
        }

        // Import peer Ed25519 key
        let peerVerifyKey = edPublicKeys[data.from];
        if (!peerVerifyKey) {
            const rawVerifyKey = Uint8Array.from(atob(data.ed25519PublicKey), c => c.charCodeAt(0));
            peerVerifyKey = await crypto.subtle.importKey(
                "raw",
                rawVerifyKey,
                { name: "Ed25519" },
                true,
                ["verify"]
            );
            edPublicKeys[data.from] = peerVerifyKey;
        }

        // Verify peer ECDH public key
        try {
            receiverPublicKey = await verifyECDHPublicKey(data.ecdhPublicKey, data.signature, peerVerifyKey);
            recipientUsername = name;
            console.log(`✅ Now securely messaging ${name}`);
        } catch (err) {
            alert("❌ Could not verify recipient's public key.");
        }
    });
});

async function exportPublicKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
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
    if (chatHistory[username]) {
        chatHistory[username].forEach((msg) => {
            const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const item = document.createElement('li');

            // Format differently based on message direction
            if (msg.direction === 'outgoing') {
                item.textContent = `[${time}] You: ${msg.text}`;
                item.classList.add('outgoing-message');
            } else {
                item.textContent = `[${time}] ${msg.from}: ${msg.text}`;
                item.classList.add('incoming-message');
            }
            
            messagesEl.appendChild(item);
        });
    }
    window.scrollTo(0, document.body.scrollHeight);
}

form.addEventListener('submit', async function(e) {
    e.preventDefault();
    if (!input.value || !recipientUsername) return;

    if (!receiverPublicKey) {
        try {
            receiverPublicKey = await getPublicKeyForUser(recipientUsername);
        } catch (err) {
            alert("❌ Could not fetch recipient's public key.");
            return;
        }
    }

    const plaintext = input.value;

    // Step 1: Encrypt the message with AES
    const { aesKey, iv, ciphertext } = await encryptMessage(plaintext);
    // AESKey was a raw CryptoKey, so it needs to be exported to ArrayBuffer
    const encryptedAESKeyBuffer = await crypto.subtle.exportKey("raw", aesKey); 
    
    // Step 2: Get the shared ECDH-derived Key
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: receiverPublicKey
        },
        myECDHKeyPair.privateKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );

    // Step 3: Use the derived key to encrypted the AES key
    const encryptedAESKey = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv, // reuse the same IV or use a new one for this (ideally a separate one)
        },
        derivedKey,
        encryptedAESKeyBuffer 
    );

    // Step 4: Convert ciphertext and iv to base64 for sending
    const payload = {
        encryptedMessage: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
        encryptedAESKey: btoa(String.fromCharCode(...new Uint8Array(encryptedAESKey))),
        iv: btoa(String.fromCharCode(...iv))
    };

    const timestamp = new Date().toISOString();

    // Store the message in history with direction info
    const messageData = {
        text: plaintext,
        timestamp,
        direction: 'outgoing', // marks this as a sent message
        from: myUsername,
        to: recipientUsername
    };

    // Initialize chat if needed
    if (!chatHistory[recipientUsername]) {
        addToChatList(recipientUsername);
        chatHistory[recipientUsername] = [];
    }
    chatHistory[recipientUsername].push(messageData);

    // Update the UI
    if (currentChat !== recipientUsername) {
        currentChat = recipientUsername;
    }
    loadChat(recipientUsername);
    
    // Sign the JSON string of the message
    const messagePayload = {
        from: myUsername,
        to: recipientUsername,
        timestamp,
        encryptedMessage: payload.encryptedMessage,
        encryptedAESKey: payload.encryptedAESKey,
        iv: payload.iv
    };
    const payloadString = JSON.stringify(messagePayload);
    const signature = await crypto.subtle.sign(
        "Ed25519",
        mySigningKeyPair.privateKey,
        new TextEncoder().encode(payloadString) // message bytes
    );

    socket.emit('chat message', {
        // to: recipientUsername,
        // from: myUsername,
        // timestamp,
        // payload: {
        //     encryptedMessage: payload.encryptedMessage,
        //     encryptedAESKey: payload.encryptedAESKey,
        //     iv: payload.iv
        // },
        ...messagePayload,
        signature: Array.from(new Uint8Array(signature))
    });

    input.value = ''; 
});

socket.on('chat message', async function(data) {
    // Fetch and verify the sender's public key bundle
    socket.emit("get public key bundle", data.from, async (bundle) => {
        if (!bundle.success) {
            console.error("Failed to get sender's key bundle");
            return;
        }

        try {
            // Import their Ed25519 public key
            const rawVerifyKey = Uint8Array.from(atob(bundle.ed25519PublicKey), c => c.charCodeAt(0));
            const peerVerifyKey = await crypto.subtle.importKey(
                "raw",
                rawVerifyKey,
                { name: "Ed25519" },
                true,
                ["verify"]
            );
            // Verify signature
            const reconstructedPayload = {
                from: data.from,
                to: data.to,
                timestamp: data.timestamp,
                encryptedMessage: data.encryptedMessage,
                encryptedAESKey: data.encryptedAESKey,
                iv: data.iv
            };
        
            const payloadBytes = new TextEncoder().encode(JSON.stringify(reconstructedPayload));
            const signatureBytes = new Uint8Array(data.signature);
        
            const isValid = await crypto.subtle.verify(
                "Ed25519",
                peerVerifyKey,
                signatureBytes,
                payloadBytes
            );
        
            if (!isValid) {
                console.error("⚠️ Message signature invalid! Possible forgery.");
                return;
            }

            // Verify and import ECDH key
            const peerECDH = await verifyECDHPublicKey(bundle.ecdhPublicKey, bundle.signature, peerVerifyKey);

            // Derive shared AES key using ECDH
            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: "ECDH",
                    public: peerECDH
                },
                myECDHKeyPair.privateKey,
                {
                    name: "AES-GCM",
                    length: 256
                },
                false,
                ["decrypt"]
            );

            const encryptedAESKeyBytes = Uint8Array.from(atob(data.encryptedAESKey), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));

            // Decrypt the AES key using the derived ECDH key
            const decryptedAESKeyRaw = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv }, // same IV that was used to encrypt it
                derivedKey,
                encryptedAESKeyBytes
            );

            // Import the decrypted AES key
            const aesKey = await crypto.subtle.importKey(
                "raw",
                decryptedAESKeyRaw,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );

            const encryptedMessage = Uint8Array.from(
                atob(data.encryptedMessage),
                c => c.charCodeAt(0)
            );            

            // Decrypt the actual message using the AES key
            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                aesKey,
                encryptedMessage
            );

            const decoder = new TextDecoder();
            const plaintext = decoder.decode(decrypted);

            const messageData = {
                text: plaintext,
                timestamp: data.timestamp,
                direction: 'incoming',
                from: data.from,
                to: myUsername
            };

            if (!chatHistory[data.from]) {
                addToChatList(data.from);
                chatHistory[data.from] = [];
            }

            chatHistory[data.from].push(messageData);

            if (currentChat === data.from || currentChat === null) {
                currentChat = data.from;
                loadChat(data.from);
            }

        } catch (err) {
            console.error("Failed to verify or decrypt message:", err);
        }
    });
});