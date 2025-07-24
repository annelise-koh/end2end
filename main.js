console.log("✅ main.js loaded!");

let socket = null;

var form = document.getElementById('form');
var input = document.getElementById('input');
var messages = document.getElementById('messages');

let receiverPublicKey; // ephemeral session data
let myECDHKeyPair; // private keys never leave memory
let mySigningKeyPair;
let myUsername;
let recipientUsername;

const chatList = document.getElementById('chat-list');
const chatHistory = {}; // key = username, value = array of messages
const edPublicKeys = {};
let currentChat = null;

// When page loads
document.addEventListener('DOMContentLoaded', () => {
    console.log("DOM fully loaded");
    checkAuthStatus();
});

async function checkAuthStatus() {
    const token = sessionStorage.getItem('sessionToken') || getCookie('sessionToken');
    if (token) {
        // User might be already logged in
        await initializeSocket(token);
        document.getElementById("auth-container").style.display = "none";
        document.getElementById("chat-container").style.display = "block";
    } else {
        // Show login form
        document.getElementById("auth-container").style.display = "block";
        setupAuthHandlers();
    }
}

function setupAuthHandlers() {
    document.getElementById('login-btn').addEventListener('click', async (e) => {
        e.preventDefault();
        await handleLogin();
    });

    document.getElementById('register-btn').addEventListener('click', async (e) => {
        e.preventDefault();
        await handleRegistration();
    });
}

async function handleLogin() {
    console.log('Handling login');
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    const mfaToken = document.getElementById('mfaCode').value;

    if (!username || !password || !mfaToken) {
        return alert("Username, password and MFA token required");
    }

    try {
        const response = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            if (!data.success) {
                return alert("Login failed");
            }

            const token = data.token;
            if (!token) {
                alert("Session token not found in response");
                return;
            }

        // Store token temporarily for this session
        sessionStorage.setItem('sessionToken', token);

            // Initialize socket AFTER successful login
            await initializeSocket(token);
            myUsername = username;
            alert("Login successful!");

            // Generate and register keys
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

            // Switch to chat interface
            document.getElementById("auth-container").style.display = "none";
            document.getElementById("chat-container").style.display = "block";
        } else {
            const data = await response.json();
            alert('Login failed: ' + (data.error || 'Unknown error'));
        }
    } catch (err) {
        showError('Login error:' + err);
    }
}

async function handleRegistration() {
    console.log('Handling registration');
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    if (!username || !password) {
        return alert("Username and password required");
    }

    try {
        const response = await fetch('/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
            credentials: 'include'
        });

        const data = await response.json();
        
        if (response.ok && data.qr) {
            // Show MFA setup with QR code
            showMfaSetup(data.qr);
            // Store username for later use
            document.getElementById("username").setAttribute('data-registering', 'true');
        } else {
            alert("Registration failed: " + (data.message || data.error || 'Unknown error'));
        }
    } catch (err) {
        alert(err);
    }
}
function showMfaSetup(qrCodeDataUrl) {
    // Create or select an <img> element to show the QR code
    const qrImg = document.getElementById('qrCode');
    if (qrImg) {
        qrImg.src = qrCodeDataUrl;
        qrImg.style.display = 'block';
    } else {
        // Optionally create one if it doesn't exist
        const img = document.createElement('img');
        img.id = 'qrCode';
        img.src = qrCodeDataUrl;
        document.body.appendChild(img);
    }

    alert('Scan the QR code with your authenticator app');
    document.getElementById('mfaVerification').style.display = 'block';
}


async function verifyMfa() {
    const username = document.getElementById("username").value.trim();
    const mfaCode = document.getElementById("mfaCode").value.trim();

    if (!mfaCode) {
        return alert("Please enter the MFA code");
    }

    try {
        const response = await fetch('/auth/verify-mfa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ username, token: mfaCode })
        });

        const data = await response.json();
        if (response.ok) {
            alert("MFA setup successful! You are now logged in.");
            
            const token = data.token;
            if (!token) {
                alert("Session token not found in response");
                return;
            }

            // Store token temporarily for this session
            sessionStorage.setItem('sessionToken', token);

            // Initialize socket and proceed with login flow
            await initializeSocket(token);
            myUsername = username;

            // Generate and register keys
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

            // Switch to chat interface
            document.getElementById("auth-container").style.display = "none";
            document.getElementById("chat-container").style.display = "block";
            
            // Hide MFA verification UI
            document.getElementById('mfaVerification').style.display = 'none';
        } else {
            alert("Invalid MFA code: " + (data.message || data.error || 'Unknown error'));
        }
    } catch (err) {
        alert(err);
    }
}

async function initializeSocket(token) {
    // Close existing connection if any
    if (socket) {
        socket.disconnect();
    }

    socket = io("http://localhost:3001", {
        withCredentials: true,
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        transports: ['websocket', 'polling'],
        auth: { token } // Send token during handshake
    });

    // Set up socket event listeners
    socket.on('connect', () => {
        console.log('Socket connected');
        isConnected = true;
    });

    socket.on('reconnect_attempt', () => {
        socket.io.opts.transports = ['polling', 'websocket'];
    });

    socket.on('connect_error', (err) => {
        console.error('Connection error:', err);
        isConnected = false;
    });

    socket.on('disconnect', (reason) => {
        console.warn('Disconnected:', reason);
        isConnected = false;
    });

    // Set up your other socket listeners here
    setupSocketListeners();
}

function setupSocketListeners() {
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
    socket.on('message history response', async (data) => {
        const { success, withUser, messages } = data;
        if (!success || !messages || !messages.length) {
            // Clear loading state and show empty chat
            displayChatMessages(withUser, []);
            return;
        }
        // Sort messages by timestamp (oldest first)
        messages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        
        const processedMessages = [];
        
        for (const msg of messages) {
            try {
                // Determine message direction
                const direction = msg.from === myUsername ? 'outgoing' : 'incoming';
                // For signature verification, get the sender's public key (not receiver's)
                const senderUsername = msg.from;
                
                // For outgoing messages, we need to decrypt them too since they're stored encrypted
                let plaintext;
                
                const bundle = await new Promise((resolve) => {
                    socket.emit("get public key bundle", senderUsername, resolve);
                });
                
                if (!bundle.success) {
                    console.error("Failed to get key bundle for historical message");
                    continue;
                }
                
                // Import their Ed25519 public key
                const rawVerifyKey = Uint8Array.from(atob(bundle.ed25519PublicKey), c => c.charCodeAt(0));
                const senderVerifyKey = await crypto.subtle.importKey(
                    "raw",
                    rawVerifyKey,
                    { name: "Ed25519" },
                    true,
                    ["verify"]
                );
                
                // Verify signature
                const reconstructedPayload = {
                    from: msg.from,
                    to: msg.to,
                    timestamp: msg.timestamp,
                    encryptedMessage: msg.encryptedMessage,
                    encryptedAESKey: msg.encryptedAESKey,
                    iv: msg.iv
                };
                
                const payloadBytes = new TextEncoder().encode(JSON.stringify(reconstructedPayload));
                const signatureBytes = new Uint8Array(msg.signature);
                
                const isValid = await crypto.subtle.verify(
                    "Ed25519",
                    senderVerifyKey,
                    signatureBytes,
                    payloadBytes
                );
                
                if (!isValid) {
                    console.error("Historical message signature invalid! Possible forgery.");
                    continue;
                }
                
                // Verify and import ECDH key
                // For ECDH, we need to determine who we're deriving the key with
                let peerUsername, peerECDH;
                
                if (direction === 'outgoing') {
                    // Message sent by us to someone else - use recipient's ECDH key
                    peerUsername = msg.to;
                } else {
                    // Message sent to us by someone else - use sender's ECDH key
                    peerUsername = msg.from;
                }
            
                // Get the peer's key bundle for ECDH
                const peerBundle = await new Promise((resolve) => {
                    socket.emit("get public key bundle", peerUsername, resolve);
                });
                
                if (!peerBundle.success) {
                    console.error(`Failed to get ECDH key bundle for ${peerUsername}`);
                    continue;
                }
            
                // Import peer's Ed25519 public key for ECDH verification
                const rawPeerVerifyKey = Uint8Array.from(atob(peerBundle.ed25519PublicKey), c => c.charCodeAt(0));
                const peerVerifyKey = await crypto.subtle.importKey(
                    "raw",
                    rawPeerVerifyKey,
                    { name: "Ed25519" },
                    true,
                    ["verify"]
                );
            
            // Verify and import peer's ECDH key
            peerECDH = await verifyECDHPublicKey(peerBundle.ecdhPublicKey, peerBundle.signature, peerVerifyKey);
            
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
                
                const encryptedAESKeyBytes = Uint8Array.from(atob(msg.encryptedAESKey), c => c.charCodeAt(0));
                const iv = Uint8Array.from(atob(msg.iv), c => c.charCodeAt(0));
                
                // Decrypt the AES key
                const decryptedAESKeyRaw = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv },
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
                    atob(msg.encryptedMessage),
                    c => c.charCodeAt(0)
                );
                
                // Decrypt the actual message
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv },
                    aesKey,
                    encryptedMessage
                );
                
                const decoder = new TextDecoder();
                plaintext = decoder.decode(decrypted);
                
                // Create message data structure
                const messageData = {
                    text: plaintext,
                    timestamp: msg.timestamp,
                    direction: direction,
                    from: msg.from,
                    to: msg.to
                };
                
                processedMessages.push(messageData);
                
            } catch (err) {
                console.error("Failed to process historical message:", err);
            }
        }
        
        // Initialize chat history if needed
        if (!chatHistory[withUser]) {
            addToChatList(withUser);
            chatHistory[withUser] = [];
        }
        
        // Replace the chat history with processed messages
        chatHistory[withUser] = processedMessages;
        
        // If we're currently viewing this chat, update the UI
        if (currentChat === withUser) {
            displayChatMessages(withUser, processedMessages);
        }
    });
}

function displayChatMessages(username, messages) {
    const messagesEl = document.getElementById('messages');
    messagesEl.innerHTML = ''; // Clear existing messages
    
    if (!messages || messages.length === 0) {
        const emptyMsg = document.createElement('div');
        emptyMsg.textContent = 'No messages yet. Start the conversation!';
        emptyMsg.style.textAlign = 'center';
        emptyMsg.style.color = '#888';
        emptyMsg.style.margin = '20px';
        messagesEl.appendChild(emptyMsg);
        return;
    }
    const sortedMessages = [...messages].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    sortedMessages.forEach((msg) => {
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
    
    // Scroll to bottom
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

// Track connection state
let isConnected = false;

// No persistence of generated keys
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
function getCookie(name) {
    console.log('All cookies:', document.cookie);
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    
    if (parts.length === 2) {
        const cookieValue = parts.pop().split(';').shift();
        console.log(`Found cookie ${name}=${cookieValue}`);
        return cookieValue;
    }
    
    console.log(`Cookie ${name} not found`);
    return null;
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

function loadChat(username) {
    currentChat = username;
    
    // Show loading state
    // const messagesEl = document.getElementById('messages');
    // messagesEl.innerHTML = '';
    // const loading = document.createElement('div');
    // loading.textContent = 'Loading messages...';
    // loading.style.textAlign = 'center';
    // loading.style.color = '#888';
    // loading.style.margin = '20px';
    // messagesEl.appendChild(loading);
    
    // // Request message history from server
    // socket.emit('get message history', { withUser: username });
    
    // // Set recipient for new messages
    // recipientUsername = username;
    // receiverPublicKey = null; // Reset so it fetches fresh
    
    // // Update recipient input
    // const recipientInput = document.getElementById("recipient");
    // if (recipientInput) {
    //     recipientInput.value = username;
    // }
    currentChat = username;
    
    // Set recipient for new messages
    recipientUsername = username;
    receiverPublicKey = null; // Reset so it fetches fresh
    
    // Update recipient input
    const recipientInput = document.getElementById("recipient");
    if (recipientInput) {
        recipientInput.value = username;
    }
    
    // Show current chat history immediately (if any)
    if (chatHistory[username] && chatHistory[username].length > 0) {
        displayChatMessages(username, chatHistory[username]);
    } else {
        // Show loading state only if no local history
        const messagesEl = document.getElementById('messages');
        messagesEl.innerHTML = '';
        const loading = document.createElement('div');
        loading.textContent = 'Loading messages...';
        loading.style.textAlign = 'center';
        loading.style.color = '#888';
        loading.style.margin = '20px';
        messagesEl.appendChild(loading);
    }
    
    // Request message history from server (this will merge with local history)
    socket.emit('get message history', { withUser: username });
}
form.addEventListener('submit', async function(e) {
    e.preventDefault();
    if (!input.value || !recipientUsername) return;

     // Check if key pairs are generated
     if (!myECDHKeyPair || !myECDHKeyPair.privateKey || !mySigningKeyPair || !mySigningKeyPair.privateKey) {
        console.error('Key pairs not generated yet');
        alert('❌ Encryption keys not ready. Please wait a moment and try again.');
        return;
    }

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
            iv: iv,
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

    // Immediately update the UI to show the sent message
    if (currentChat === recipientUsername) {
        displayChatMessages(recipientUsername, chatHistory[recipientUsername]);
    }
    
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
        ...messagePayload,
        signature: Array.from(new Uint8Array(signature))
    });

    input.value = ''; 
});
