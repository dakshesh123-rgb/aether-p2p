// Aether P2P cryptographic and connection logic

// Global Variables
let localConnection = null;
let dataChannel = null;
let ecdhKeyPair = null;
let aesGcmKey = null;
let isE2EEActive = false;
let isPeerVerified = false;
let currentSafetyCode = null;

// Network Sovereignty / ICE Settings State
const ICE_PRESETS = {
  community: {
    label: 'Community Mesh',
    servers: [
      { urls: 'stun:stun.nextcloud.com:443' },
      { urls: 'stun:stun.matrix.org:3478' },
      { urls: 'stun:stun.cloudflare.com:3478' },
      { urls: 'stun:stun.freeswitch.org:3478' }
    ]
  },
  airgap: {
    label: 'Zero STUN (Air-Gapped)',
    servers: []
  },
  custom: {
    label: 'Self-Hosted',
    servers: []
  },
  google: {
    label: 'Google STUN',
    servers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' }
    ]
  }
};

let currentIceMode = 'community';
let customIceConfig = {
  url: '',
  username: '',
  credential: ''
};

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

// Modal & Sovereignty UI Elements
const labelIceMode = document.getElementById('label-ice-mode');
const btnOpenIceSettings = document.getElementById('btn-open-ice-settings');
const iceSettingsModal = document.getElementById('ice-settings-modal');
const btnCloseIceModal = document.getElementById('btn-close-ice-modal');
const btnSaveIceSettings = document.getElementById('btn-save-ice-settings');
const customIceInputs = document.getElementById('custom-ice-inputs');
const customStunUrl = document.getElementById('custom-stun-url');
const customStunUsername = document.getElementById('custom-stun-username');
const customStunCredential = document.getElementById('custom-stun-credential');
const btnExportStandalone = document.getElementById('btn-export-standalone');

// Out-Of-Band Safety Verification Elements
const safetyCodeNumber = document.getElementById('safety-code-number');
const safetyVerificationBadge = document.getElementById('safety-verification-badge');
const btnToggleVerifyPeer = document.getElementById('btn-toggle-verify-peer');

// Setup role selectors
document.getElementById('btn-host-setup').addEventListener('click', setupHost);
document.getElementById('btn-join-setup').addEventListener('click', setupJoin);
document.getElementById('btn-finalize-host').addEventListener('click', finalizeHost);
document.getElementById('btn-accept-offer').addEventListener('click', acceptOffer);
document.getElementById('btn-reset-handshake').addEventListener('click', resetHandshake);

if (btnOpenIceSettings) btnOpenIceSettings.addEventListener('click', openIceModal);
if (btnCloseIceModal) btnCloseIceModal.addEventListener('click', closeIceModal);
if (btnSaveIceSettings) btnSaveIceSettings.addEventListener('click', saveIceSettings);
if (btnExportStandalone) btnExportStandalone.addEventListener('click', exportStandaloneVault);
if (btnToggleVerifyPeer) btnToggleVerifyPeer.addEventListener('click', togglePeerVerification);

// Radio card click handling for ICE Settings
document.querySelectorAll('.radio-card').forEach(card => {
  card.addEventListener('click', () => {
    const radio = card.querySelector('input[type="radio"]');
    if (radio) {
      radio.checked = true;
      updateRadioCardStyles();
    }
  });
});

function updateRadioCardStyles() {
  document.querySelectorAll('.radio-card').forEach(card => {
    const radio = card.querySelector('input[type="radio"]');
    if (radio && radio.checked) {
      card.classList.add('active');
      if (customIceInputs) {
        customIceInputs.style.display = radio.value === 'custom' ? 'flex' : 'none';
      }
    } else {
      card.classList.remove('active');
    }
  });
}

function openIceModal() {
  // Sync form with current state
  const targetRadio = document.querySelector(`input[name="ice-mode"][value="${currentIceMode}"]`);
  if (targetRadio) targetRadio.checked = true;
  if (customStunUrl) customStunUrl.value = customIceConfig.url || '';
  if (customStunUsername) customStunUsername.value = customIceConfig.username || '';
  if (customStunCredential) customStunCredential.value = customIceConfig.credential || '';
  updateRadioCardStyles();
  iceSettingsModal.classList.add('active');
}

function closeIceModal() {
  iceSettingsModal.classList.remove('active');
}

function saveIceSettings() {
  const selectedRadio = document.querySelector('input[name="ice-mode"]:checked');
  if (selectedRadio) {
    currentIceMode = selectedRadio.value;
    if (currentIceMode === 'custom') {
      customIceConfig.url = (customStunUrl ? customStunUrl.value.trim() : '');
      customIceConfig.username = (customStunUsername ? customStunUsername.value.trim() : '');
      customIceConfig.credential = (customStunCredential ? customStunCredential.value.trim() : '');
    }
    saveIceConfig();
    updateIceModeBadge();
    closeIceModal();
    logToCipherStream(`Network Sovereignty updated: ICE mode set to [${ICE_PRESETS[currentIceMode] ? ICE_PRESETS[currentIceMode].label : currentIceMode}].`);
  }
}

function updateIceModeBadge() {
  if (labelIceMode) {
    const label = ICE_PRESETS[currentIceMode] ? ICE_PRESETS[currentIceMode].label : 'Custom';
    labelIceMode.textContent = `ICE: ${label}`;
  }
}

function loadSavedIceConfig() {
  try {
    const saved = localStorage.getItem('aether_ice_config');
    if (saved) {
      const parsed = JSON.parse(saved);
      if (parsed.mode && ICE_PRESETS[parsed.mode]) {
        currentIceMode = parsed.mode;
      }
      if (parsed.custom) {
        customIceConfig = parsed.custom;
      }
    }
  } catch (e) {
    console.warn("Failed to load saved ICE config", e);
  }
  updateIceModeBadge();
}

function saveIceConfig() {
  try {
    localStorage.setItem('aether_ice_config', JSON.stringify({
      mode: currentIceMode,
      custom: customIceConfig
    }));
  } catch (e) {
    console.warn("Failed to save ICE config", e);
  }
}

function getEffectiveRtcConfig() {
  if (currentIceMode === 'airgap') {
    return { iceServers: [] };
  }
  if (currentIceMode === 'custom') {
    if (!customIceConfig.url) {
      return { iceServers: ICE_PRESETS.community.servers };
    }
    const serverObj = { urls: customIceConfig.url.trim() };
    if (customIceConfig.username) serverObj.username = customIceConfig.username.trim();
    if (customIceConfig.credential) serverObj.credential = customIceConfig.credential.trim();
    return { iceServers: [serverObj] };
  }
  if (ICE_PRESETS[currentIceMode]) {
    return { iceServers: ICE_PRESETS[currentIceMode].servers };
  }
  return { iceServers: ICE_PRESETS.community.servers };
}

// Handshake Code Compression (reduces payload by 60-70% for copy-paste resilience)
async function compressHandshake(jsonString) {
  if (typeof CompressionStream !== 'undefined') {
    try {
      const stream = new Blob([jsonString]).stream();
      const compressedStream = stream.pipeThrough(new CompressionStream('deflate'));
      const compressedBlob = await new Response(compressedStream).blob();
      const buffer = await compressedBlob.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return 'aether:z:' + btoa(binary);
    } catch (e) {
      console.warn("Handshake compression fallback:", e);
    }
  }
  return btoa(jsonString);
}

async function decompressHandshake(rawString) {
  const trimmed = rawString.trim().replace(/\s+/g, '');
  if (trimmed.startsWith('aether:z:')) {
    const base64Data = trimmed.substring(9);
    const binary = atob(base64Data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const stream = new Blob([bytes]).stream();
    const decompressedStream = stream.pipeThrough(new DecompressionStream('deflate'));
    const decompressedBlob = await new Response(decompressedStream).blob();
    return await decompressedBlob.text();
  }
  return atob(trimmed);
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
    
    // Encode description into compressed string for clean copy-pasting
    const connectionPayload = {
      sdp: localConnection.localDescription.sdp,
      type: localConnection.localDescription.type
    };
    const code = await compressHandshake(JSON.stringify(connectionPayload));
    document.getElementById('local-offer-code').value = code;
    logToCipherStream("Host Handshake offer generated (compressed).");
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
    const offerJsonString = await decompressHandshake(offerCodeRaw);
    const offerPayload = JSON.parse(offerJsonString);
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
    const answerCode = await compressHandshake(JSON.stringify(answerPayload));
    document.getElementById('local-answer-code').value = answerCode;
    document.getElementById('join-step-2').style.display = 'block';
    logToCipherStream("Joiner Handshake answer generated (compressed).");
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
    const answerJsonString = await decompressHandshake(answerCodeRaw);
    const answerPayload = JSON.parse(answerJsonString);
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

    // Derive 6-digit numeric Safety Code from first 4 bytes of fingerprint
    const view = new DataView(fingerprintBuffer);
    const numVal = Math.abs(view.getUint32(0)) % 1000000;
    currentSafetyCode = String(numVal).padStart(6, '0').replace(/(\d{3})(\d{3})/, '$1-$2');
    isPeerVerified = false;

    // Update UI
    cryptoFingerprint.textContent = fingerprintHex;
    isE2EEActive = true;
    updateVerificationUI();
    
    logToCipherStream(`E2E AES-GCM-256 Key derivation complete. Safety Code: ${currentSafetyCode}`);
    appendSystemMessage(`Secure E2EE established! Compare 6-digit Safety Code (${currentSafetyCode}) with your peer to verify identity.`);
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

// -----------------------------------------------------------------------------
// VERIFICATION, EXPORT & INITIALIZATION
// -----------------------------------------------------------------------------

function updateVerificationUI() {
  if (safetyCodeNumber) {
    safetyCodeNumber.textContent = currentSafetyCode || '------';
  }
  if (btnToggleVerifyPeer) {
    btnToggleVerifyPeer.disabled = !isE2EEActive;
    btnToggleVerifyPeer.textContent = isPeerVerified ? 'Peer Identity Verified (Click to Revoke)' : 'Mark Peer Identity as Verified';
    btnToggleVerifyPeer.className = isPeerVerified ? 'btn btn-primary btn-verify' : 'btn btn-secondary btn-verify';
  }
  if (safetyVerificationBadge) {
    if (!isE2EEActive) {
      safetyVerificationBadge.className = 'safety-badge-status unverified';
      safetyVerificationBadge.innerHTML = 'AWAITING KEY EXCHANGE';
    } else if (isPeerVerified) {
      safetyVerificationBadge.className = 'safety-badge-status verified';
      safetyVerificationBadge.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> VERIFIED SECURE`;
    } else {
      safetyVerificationBadge.className = 'safety-badge-status unverified';
      safetyVerificationBadge.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> UNVERIFIED PEER`;
    }
  }
  if (securityIndicator && isE2EEActive) {
    if (isPeerVerified) {
      securityIndicator.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-success)" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
        E2EE VERIFIED`;
      securityIndicator.style.color = "var(--color-success)";
    } else {
      securityIndicator.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--color-warning)" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        E2EE (UNVERIFIED)`;
      securityIndicator.style.color = "var(--color-warning)";
    }
  }
}

function togglePeerVerification() {
  if (!isE2EEActive) return;
  isPeerVerified = !isPeerVerified;
  updateVerificationUI();
  if (isPeerVerified) {
    logToCipherStream(`Peer verified! Anti-MITM safety code ${currentSafetyCode} confirmed.`);
    appendSystemMessage(`Identity verified: Safety Code (${currentSafetyCode}) confirmed out-of-band.`);
  } else {
    logToCipherStream("Peer verification revoked.");
    appendSystemMessage("Peer verification reset to unverified.");
  }
}

// EXPORT VAULT AS AIR-GAPPED STANDALONE HTML FILE
async function exportStandaloneVault() {
  try {
    logToCipherStream("Generating standalone single-file vault...");
    const [htmlRes, cssRes, jsRes] = await Promise.all([
      fetch('index.html'),
      fetch('styles.css'),
      fetch('script.js')
    ]);
    let htmlText = await htmlRes.text();
    const cssText = await cssRes.text();
    const jsText = await jsRes.text();

    // Inline CSS
    htmlText = htmlText.replace(
      /<link rel="stylesheet" href="styles\.css">/i,
      `<style>\n${cssText}\n</style>`
    );
    // Inline JS
    htmlText = htmlText.replace(
      /<script src="script\.js"><\/script>/i,
      `<script>\n${jsText}\n</script>`
    );
    // Remove manifest link for standalone offline bundle
    htmlText = htmlText.replace(/<link rel="manifest" href="manifest\.json">/i, '');

    const blob = new Blob([htmlText], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'aether-vault-standalone.html';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    logToCipherStream("Standalone single-file vault exported successfully.");
    appendSystemMessage("Offline Vault generated! You can run this single .html file completely air-gapped without any server or internet connection.");
  } catch (err) {
    logToCipherStream(`Export failed: ${err.message}`);
    alert("Could not export standalone file automatically: " + err.message);
  }
}

// Initial bootstrap
loadSavedIceConfig();
updateVerificationUI();

// Register Service Worker for offline PWA operation
if ('serviceWorker' in navigator && window.location.protocol.startsWith('http')) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').then(() => {
      logToCipherStream("Offline PWA service worker registered.");
    }).catch(() => {});
  });
}
