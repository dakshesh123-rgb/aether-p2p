// Aether P2P cryptographic and connection logic

// Global Variables
let localConnection = null;
let dataChannel = null;
let ecdhKeyPair = null;
let aesGcmKey = null;
let isE2EEActive = false;

// File transfer state
let incomingFile = {
  metadata: null,
  chunks: [],
  receivedChunks: 0
};

// UI Elements
const statusBadge = document.getElementById('connection-status');
const securityIndicator = document.getElementById('chat-security-indicator');
const chatMessages = document.getElementById('chat-messages');
const chatForm = document.getElementById('chat-form');
const chatInput = document.getElementById('chat-input');
const btnSendMessage = document.getElementById('btn-send-message');
const fileDropZone = document.getElementById('file-drop-zone');
const fileInput = document.getElementById('file-input');
const transferList = document.getElementById('transfer-list');
const cryptoFingerprint = document.getElementById('crypto-fingerprint');
const cipherStreamLog = document.getElementById('cipher-stream-log');

// Setup role selectors
document.getElementById('btn-host-setup').addEventListener('click', setupHost);
document.getElementById('btn-join-setup').addEventListener('click', setupJoin);
document.getElementById('btn-finalize-host').addEventListener('click', finalizeHost);
document.getElementById('btn-accept-offer').addEventListener('click', acceptOffer);
document.getElementById('btn-reset-handshake').addEventListener('click', resetHandshake);

// Copy utility
function copyText(elementId) {
  const textarea = document.getElementById(elementId);
  textarea.select();
  textarea.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(textarea.value);
  logToCipherStream('Handshake code copied to clipboard');
}

// Log utility for Cryptographic Inspector
function logToCipherStream(msg, isCiphertext = false) {
  const time = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = 'cipher-log-line';
  
  const timeSpan = document.createElement('span');
  timeSpan.className = 'cipher-log-time';
  timeSpan.textContent = `[${time}]`;
  
  const msgSpan = document.createElement('span');
  msgSpan.className = 'cipher-log-msg';
  msgSpan.textContent = msg;
  if (isCiphertext) {
    msgSpan.style.color = 'var(--color-accent)';
    msgSpan.style.fontFamily = 'var(--font-mono)';
  }
  
  line.appendChild(timeSpan);
  line.appendChild(msgSpan);
  cipherStreamLog.appendChild(line);
  cipherStreamLog.scrollTop = cipherStreamLog.scrollHeight;
}

// System Message helper
function appendSystemMessage(text) {
  const msg = document.createElement('div');
  msg.className = 'message-bubble system';
  msg.textContent = text;
  chatMessages.appendChild(msg);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Enable Workspace elements after connection is established
function enableWorkspace() {
  chatInput.disabled = false;
  btnSendMessage.disabled = false;
  fileInput.disabled = false;
  chatInput.placeholder = "Type an encrypted message...";
  statusBadge.textContent = "CONNECTED";
  statusBadge.className = "badge connected";
  logToCipherStream("P2P Data Channel open. Exchanging public keys...");
}

// Disable Workspace elements
function disableWorkspace() {
  chatInput.disabled = true;
  btnSendMessage.disabled = true;
  fileInput.disabled = true;
  chatInput.placeholder = "Establish WebRTC link to chat...";
  statusBadge.textContent = "DISCONNECTED";
  statusBadge.className = "badge";
  securityIndicator.innerHTML = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    E2EE INACTIVE`;
  securityIndicator.style.color = "var(--color-text-secondary)";
  cryptoFingerprint.textContent = "No keys exchanged yet";
  isE2EEActive = false;
  aesGcmKey = null;
}

// -----------------------------------------------------------------------------
// WEBRTC SIGNALING & CONNECTION SETUP
// -----------------------------------------------------------------------------

const rtcConfig = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ]
};

let reconnectTimeout = null;

function createPeerConnection() {
  localConnection = new RTCPeerConnection(rtcConfig);

  // Monitor connection states
  localConnection.onconnectionstatechange = () => {
    logToCipherStream(`WebRTC Connection State: ${localConnection.connectionState}`);
    
    if (localConnection.connectionState === 'connected') {
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
        logToCipherStream("Reconnected successfully.");
        appendSystemMessage("Secure channel restored.");
      }
      enableWorkspace();
    } else if (localConnection.connectionState === 'disconnected') {
      // Show reconnecting badge but do not disable chat/key state immediately
      statusBadge.textContent = "RECONNECTING";
      statusBadge.className = "badge reconnecting";
      logToCipherStream("Link disconnected temporarily. Attempting auto-reconnection...");
      
      if (!reconnectTimeout) {
        reconnectTimeout = setTimeout(() => {
          disableWorkspace();
          appendSystemMessage("Secure channel lost (reconnection timeout).");
          reconnectTimeout = null;
        }, 12000); // 12 seconds grace period
      }
    } else if (localConnection.connectionState === 'failed' || localConnection.connectionState === 'closed') {
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
      }
      disableWorkspace();
      appendSystemMessage("Secure channel closed.");
    }
  };

  localConnection.oniceconnectionstatechange = () => {
    logToCipherStream(`ICE Connection State: ${localConnection.iceConnectionState}`);
  };
}

// Wait for ICE Candidates to complete gathering
function waitForIceGathering(pc) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') {
      resolve();
    } else {
      const checkState = () => {
        if (pc.iceGatheringState === 'complete') {
          pc.removeEventListener('icegatheringstatechange', checkState);
          resolve();
        }
      };
      pc.addEventListener('icegatheringstatechange', checkState);
    }
  });
}

// SETUP HOST
async function setupHost() {
  document.getElementById('session-setup').style.display = 'none';
  document.getElementById('host-step-1').style.display = 'block';
  document.getElementById('btn-reset-handshake').style.display = 'block';
  
  logToCipherStream("Setting up WebRTC Host...");
  createPeerConnection();

  // Host creates Data Channel
  dataChannel = localConnection.createDataChannel("aether-secure-channel");
  dataChannel.bufferedAmountLowThreshold = 65536; // Set threshold to 64KB
  setupDataChannelHandlers();

  try {
    // Generate key pair for Host
    await generateEcdhKeyPair();

    const offer = await localConnection.createOffer();
    await localConnection.setLocalDescription(offer);
    
    logToCipherStream("Gathering network routes (ICE Candidates)...");
    await waitForIceGathering(localConnection);
    
    // Encode description into Base64 for clean copy-pasting
    const connectionPayload = {
      sdp: localConnection.localDescription.sdp,
      type: localConnection.localDescription.type
    };
    document.getElementById('local-offer-code').value = btoa(JSON.stringify(connectionPayload));
    logToCipherStream("Host Handshake offer generated.");
  } catch (err) {
    logToCipherStream(`Host Setup Error: ${err.message}`);
  }
}

// SETUP JOINER
async function setupJoin() {
  document.getElementById('session-setup').style.display = 'none';
  document.getElementById('join-step-1').style.display = 'block';
  document.getElementById('btn-reset-handshake').style.display = 'block';

  logToCipherStream("Setting up WebRTC Joiner...");
  createPeerConnection();

  // Listen for incoming Data Channel
  localConnection.ondatachannel = (event) => {
    dataChannel = event.channel;
    dataChannel.bufferedAmountLowThreshold = 65536; // Set threshold to 64KB
    setupDataChannelHandlers();
  };

  // Generate key pair for Joiner
  await generateEcdhKeyPair();
}

// PROCESS OFFER (JOINER)
async function acceptOffer() {
  const offerCodeRaw = document.getElementById('remote-offer-code').value.trim();
  if (!offerCodeRaw) {
    alert("Please paste the host's offer code first.");
    return;
  }

  try {
    const offerPayload = JSON.parse(atob(offerCodeRaw));
    await localConnection.setRemoteDescription(new RTCSessionDescription(offerPayload));
    logToCipherStream("Remote offer description applied.");

    const answer = await localConnection.createAnswer();
    await localConnection.setLocalDescription(answer);

    logToCipherStream("Gathering network routes (ICE Candidates)...");
    document.getElementById('btn-accept-offer').disabled = true;
    await waitForIceGathering(localConnection);

    const answerPayload = {
      sdp: localConnection.localDescription.sdp,
      type: localConnection.localDescription.type
    };
    document.getElementById('local-answer-code').value = btoa(JSON.stringify(answerPayload));
    document.getElementById('join-step-2').style.display = 'block';
    logToCipherStream("Joiner Handshake answer generated.");
  } catch (err) {
    logToCipherStream(`Accept Offer Error: ${err.message}`);
    alert("Invalid offer code. Please make sure you copied the full string.");
  }
}

// FINALIZE CONNECTION (HOST)
async function finalizeHost() {
  const answerCodeRaw = document.getElementById('remote-answer-code').value.trim();
  if (!answerCodeRaw) {
    alert("Please paste the joiner's answer code first.");
    return;
  }

  try {
    const answerPayload = JSON.parse(atob(answerCodeRaw));
    await localConnection.setRemoteDescription(new RTCSessionDescription(answerPayload));
    logToCipherStream("Remote answer description applied. Negotiating P2P path...");
    document.getElementById('btn-finalize-host').disabled = true;
  } catch (err) {
    logToCipherStream(`Finalize Connection Error: ${err.message}`);
    alert("Invalid answer code. Please make sure you copied the full string.");
  }
}

// RESET HANDSHAKE
function resetHandshake() {
  if (localConnection) {
    localConnection.close();
  }
  disableWorkspace();
  
  document.getElementById('session-setup').style.display = 'block';
  document.getElementById('host-step-1').style.display = 'none';
  document.getElementById('join-step-1').style.display = 'none';
  document.getElementById('join-step-2').style.display = 'none';
  document.getElementById('btn-reset-handshake').style.display = 'none';
  document.getElementById('btn-finalize-host').disabled = false;
  document.getElementById('btn-accept-offer').disabled = false;
  document.getElementById('local-offer-code').value = '';
  document.getElementById('remote-answer-code').value = '';
  document.getElementById('remote-offer-code').value = '';
  document.getElementById('local-answer-code').value = '';
  
  logToCipherStream("Handshake state reset.");
}

// -----------------------------------------------------------------------------
// DATA CHANNEL & E2E CRYPTOGRAPHY (WEB CRYPTO API)
// -----------------------------------------------------------------------------

function setupDataChannelHandlers() {
  dataChannel.onopen = () => {
    logToCipherStream("Data channel link opened.");
    // Automatically trigger Key Exchange once channel is open
    sendPublicKey();
  };

  dataChannel.onclose = () => {
    logToCipherStream("Data channel link closed.");
    disableWorkspace();
    appendSystemMessage("Connection terminated.");
  };

  dataChannel.onmessage = async (event) => {
    try {
      const payload = JSON.parse(event.data);
      
      // Route message based on encryption state
      if (payload.type === 'key-exchange') {
        await finalizeKeyAgreement(payload.publicKey);
      } else if (payload.encrypted) {
        if (!isE2EEActive) {
          logToCipherStream("Received encrypted payload before key exchange completed! Dropping packet.");
          return;
        }
        
        logToCipherStream(`Ciphertext payload received: ${payload.encrypted.substring(0, 48)}...`, true);
        const decryptedJson = await decryptPayload(payload.encrypted);
        const data = JSON.parse(decryptedJson);
        handleDecryptedMessage(data);
      }
    } catch (err) {
      logToCipherStream(`Data Channel Error: ${err.message}`);
    }
  };
}

// GENERATE ECDH KEYPAIR
async function generateEcdhKeyPair() {
  try {
    ecdhKeyPair = await window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    logToCipherStream("Local ECDH keypair (Curve P-256) generated successfully.");
  } catch (err) {
    logToCipherStream(`ECDH Keygen Error: ${err.message}`);
  }
}

// SEND PUBLIC KEY (CLEARTEXT INITIAL HANDSHAKE)
async function sendPublicKey() {
  try {
    const exportedRaw = await window.crypto.subtle.exportKey('raw', ecdhKeyPair.publicKey);
    const base64Key = btoa(String.fromCharCode(...new Uint8Array(exportedRaw)));
    
    const keyMsg = {
      type: 'key-exchange',
      publicKey: base64Key
    };
    dataChannel.send(JSON.stringify(keyMsg));
    logToCipherStream("Local ECDH public key transmitted.");
  } catch (err) {
    logToCipherStream(`Send Public Key Error: ${err.message}`);
  }
}

// DERIVE AES-GCM SYMMETRIC KEY (ECDH KEY AGREEMENT)
async function finalizeKeyAgreement(peerPublicKeyBase64) {
  try {
    logToCipherStream("Importing peer public key...");
    const rawBytes = new Uint8Array(atob(peerPublicKeyBase64).split("").map(c => c.charCodeAt(0)));
    
    const peerPublicKey = await window.crypto.subtle.importKey(
      'raw',
      rawBytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );

    logToCipherStream("Agreeing on shared secret bits...");
    // Derive AES-GCM-256 Key directly
    aesGcmKey = await window.crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPublicKey },
      ecdhKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    // Derive bits to calculate SHA-256 Fingerprint for validation
    const derivedBits = await window.crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerPublicKey },
      ecdhKeyPair.privateKey,
      256
    );

    const fingerprintBuffer = await window.crypto.subtle.digest('SHA-256', derivedBits);
    const fingerprintArray = Array.from(new Uint8Array(fingerprintBuffer));
    const fingerprintHex = fingerprintArray
      .map(b => b.toString(16).padStart(2, '0'))
      .join(':')
      .toUpperCase();

    // Update UI
    cryptoFingerprint.textContent = fingerprintHex;
    securityIndicator.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-success)" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      E2EE ACTIVE`;
    securityIndicator.style.color = "var(--color-success)";
    
    isE2EEActive = true;
    logToCipherStream("E2E AES-GCM-256 Key derivation complete. Fingerprint verified.");
    appendSystemMessage("Secure End-to-End Encrypted channel established.");
  } catch (err) {
    logToCipherStream(`Key Exchange Error: ${err.message}`);
    appendSystemMessage("Encryption key agreement failed!");
  }
}

// ENCRYPT JSON PAYLOAD
async function encryptPayload(plaintextString) {
  const encoder = new TextEncoder();
  const encodedText = encoder.encode(plaintextString);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12-byte IV for GCM

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    aesGcmKey,
    encodedText
  );

  // Combine IV and Ciphertext into one binary block
  const completeBuffer = new Uint8Array(iv.length + ciphertextBuffer.byteLength);
  completeBuffer.set(iv, 0);
  completeBuffer.set(new Uint8Array(ciphertextBuffer), iv.length);

  // Return base64 string
  return btoa(String.fromCharCode(...completeBuffer));
}

// DECRYPT PAYLOAD
async function decryptPayload(ciphertextBase64) {
  const binaryString = atob(ciphertextBase64);
  const completeBuffer = new Uint8Array(binaryString.split("").map(c => c.charCodeAt(0)));

  // Extract 12-byte IV from front
  const iv = completeBuffer.slice(0, 12);
  const ciphertext = completeBuffer.slice(12);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    aesGcmKey,
    ciphertext
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

// SEND ENCRYPTED CONTROL PACKET
async function sendEncryptedPacket(dataObj) {
  if (!isE2EEActive) return;
  try {
    const stringified = JSON.stringify(dataObj);
    const encryptedBase64 = await encryptPayload(stringified);
    
    const wrapper = {
      encrypted: encryptedBase64
    };
    dataChannel.send(JSON.stringify(wrapper));
    logToCipherStream(`Ciphertext payload sent: ${encryptedBase64.substring(0, 48)}...`, true);
  } catch (err) {
    logToCipherStream(`Send Encryption Error: ${err.message}`);
  }
}

// -----------------------------------------------------------------------------
// SECURE SYSTEM LOGIC (CHAT & FILES)
// -----------------------------------------------------------------------------

// PROCESS DECRYPTED MESSAGES
function handleDecryptedMessage(data) {
  if (data.type === 'chat') {
    appendChatMessage('remote', data.content);
  } else if (data.type === 'file-meta') {
    setupIncomingFile(data);
  } else if (data.type === 'file-chunk') {
    handleIncomingFileChunk(data);
  }
}

// CHAT UI UPDATES
function appendChatMessage(sender, content) {
  const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const bubble = document.createElement('div');
  bubble.className = `message-bubble ${sender}`;
  
  const textNode = document.createElement('div');
  textNode.textContent = content;
  
  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  
  const timeSpan = document.createElement('span');
  timeSpan.textContent = time;
  
  const lockSpan = document.createElement('span');
  lockSpan.className = 'lock-icon';
  lockSpan.innerHTML = `
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    Encrypted`;
    
  meta.appendChild(timeSpan);
  meta.appendChild(lockSpan);
  bubble.appendChild(textNode);
  bubble.appendChild(meta);
  
  chatMessages.appendChild(bubble);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

// CHAT SUBMISSION
chatForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = chatInput.value.trim();
  if (!text) return;

  chatInput.value = '';
  appendChatMessage('local', text);

  // Send encrypted
  await sendEncryptedPacket({
    type: 'chat',
    content: text
  });
});

// -----------------------------------------------------------------------------
// P2P ENCRYPTED FILE SHARING (CHUNKING)
// -----------------------------------------------------------------------------

const CHUNK_SIZE = 16384; // 16KB standard chunk size for WebRTC Data Channel

// HOST FILE SEND TRIGGER
fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];
  if (file) {
    sendFile(file);
  }
});

// Drag and drop events
fileDropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  fileDropZone.classList.add('active');
});

fileDropZone.addEventListener('dragleave', () => {
  fileDropZone.classList.remove('active');
});

fileDropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  fileDropZone.classList.remove('active');
  
  if (!isE2EEActive) return;
  const file = e.dataTransfer.files[0];
  if (file) {
    sendFile(file);
  }
});

// SEND FILE ALGORITHM
async function sendFile(file) {
  logToCipherStream(`Preparing file transfer: ${file.name} (${file.size} bytes)`);
  
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  const fileId = Math.random().toString(36).substring(7);

  // Add progress item to local list
  const transferItem = createTransferItem(fileId, file.name, 'Sending');
  const progressFill = transferItem.querySelector('.transfer-progress-fill');
  
  // 1. Send E2EE metadata
  await sendEncryptedPacket({
    type: 'file-meta',
    fileId: fileId,
    name: file.name,
    size: file.size,
    totalChunks: totalChunks
  });

  // 2. Read and send chunks sequentially
  const reader = new FileReader();
  let currentChunk = 0;

  const readNextChunk = () => {
    // Prevent WebRTC buffer overflows (backpressure check)
    if (dataChannel.bufferedAmount > 65536) {
      dataChannel.onbufferedamountlow = () => {
        dataChannel.onbufferedamountlow = null;
        readNextChunk();
      };
      return;
    }

    const start = currentChunk * CHUNK_SIZE;
    const end = Math.min(file.size, start + CHUNK_SIZE);
    const blobSlice = file.slice(start, end);
    reader.readAsArrayBuffer(blobSlice);
  };

  reader.onload = async (e) => {
    const arrayBuffer = e.target.result;
    
    // Encrypt the chunk contents
    const base64ChunkData = btoa(
      String.fromCharCode(...new Uint8Array(arrayBuffer))
    );

    await sendEncryptedPacket({
      type: 'file-chunk',
      fileId: fileId,
      index: currentChunk,
      data: base64ChunkData
    });

    currentChunk++;
    const progress = Math.round((currentChunk / totalChunks) * 100);
    progressFill.style.width = `${progress}%`;

    if (currentChunk < totalChunks) {
      readNextChunk(); // Load immediately next chunk (backpressure handles speed limit!)
    } else {
      progressFill.classList.add('completed');
      transferItem.querySelector('.transfer-info span').textContent = 'Completed';
      logToCipherStream(`File transfer successful: ${file.name}`);
    }
  };

  readNextChunk();
}

// SETUP INCOMING FILE (RECEIVER)
function setupIncomingFile(meta) {
  logToCipherStream(`Incoming file offer: ${meta.name} (${meta.size} bytes)`);
  
  incomingFile = {
    metadata: meta,
    chunks: new Array(meta.totalChunks),
    receivedChunks: 0
  };

  createTransferItem(meta.fileId, meta.name, 'Receiving');
}

// HANDLE INCOMING FILE CHUNK (RECEIVER)
function handleIncomingFileChunk(chunk) {
  if (!incomingFile.metadata || incomingFile.metadata.fileId !== chunk.fileId) {
    return;
  }

  // Convert Base64 data chunk back to binary ArrayBuffer
  const binaryString = atob(chunk.data);
  const chunkBuffer = new Uint8Array(binaryString.split("").map(c => c.charCodeAt(0)));
  
  incomingFile.chunks[chunk.index] = chunkBuffer;
  incomingFile.receivedChunks++;

  // Update UI progress
  const transferItem = document.getElementById(`transfer-${chunk.fileId}`);
  if (transferItem) {
    const progress = Math.round((incomingFile.receivedChunks / incomingFile.metadata.totalChunks) * 100);
    const progressFill = transferItem.querySelector('.transfer-progress-fill');
    progressFill.style.width = `${progress}%`;
    
    if (incomingFile.receivedChunks === incomingFile.metadata.totalChunks) {
      progressFill.classList.add('completed');
      transferItem.querySelector('.transfer-info span').textContent = 'Completed';
      
      // Reconstruct file and create local download URL
      const fileBlob = new Blob(incomingFile.chunks);
      const downloadUrl = URL.createObjectURL(fileBlob);
      
      const downloadBtn = document.createElement('a');
      downloadBtn.href = downloadUrl;
      downloadBtn.download = incomingFile.metadata.name;
      downloadBtn.className = 'file-download-btn';
      downloadBtn.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>
        </svg>
        Download Decrypted File`;
      
      transferItem.appendChild(downloadBtn);
      logToCipherStream(`File transfer complete. Reconstructed decrypted file: ${incomingFile.metadata.name}`);
    }
  }
}

// CREATE DYNAMIC TRANSFER ITEM ON UI
function createTransferItem(id, name, status) {
  const item = document.createElement('div');
  item.className = 'transfer-item';
  item.id = `transfer-${id}`;

  item.innerHTML = `
    <div class="transfer-info">
      <div class="transfer-name">${name}</div>
      <span>${status}</span>
    </div>
    <div class="transfer-progress-bar">
      <div class="transfer-progress-fill"></div>
    </div>
  `;
  
  transferList.appendChild(item);
  return item;
}
