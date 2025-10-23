// script.js - funções comuns para criptografia e manipulação do arquivo data.json
// Usa Web Crypto API (PBKDF2 + AES-GCM)

// ---------------- utilitários ----------------
function buf2b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
function b642buf(b64){ const s = atob(b64); const arr = new Uint8Array(s.length); for (let i=0;i<s.length;i++) arr[i]=s.charCodeAt(i); return arr.buffer; }
function str2ab(str){ const enc = new TextEncoder(); return enc.encode(str); }
function ab2str(buf){ const dec = new TextDecoder(); return dec.decode(buf); }
function escapeHtml(s){ if(!s) return ''; return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function escapeHtmlAttr(s){ if(!s) return ''; return String(s).replace(/"/g,'&quot;'); }

// ---------------- crypto ----------------
async function deriveKeyFromPassword(password, salt) {
  const pwKey = await crypto.subtle.importKey('raw', str2ab(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt,
    iterations: 150000,
    hash: 'SHA-256'
  }, pwKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
}

async function encryptParticipantData(obj, password){
  // obj: { items: [...], meta: '...' }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassword(password, salt);
  const plain = str2ab(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
  return {
    cipherText: buf2b64(cipher),
    salt: buf2b64(salt.buffer),
    iv: buf2b64(iv.buffer)
  };
}

async function decryptParticipant(entry, password){
  // entry: { name, enc (or enc/cipherText), salt, iv }
  // support older key names
  const cipherB64 = entry.enc || entry.cipherText || entry.cipher;
  if (!cipherB64 || !entry.salt || !entry.iv) return null;
  try {
    const saltBuf = b642buf(entry.salt);
    const ivBuf = b642buf(entry.iv);
    const key = await deriveKeyFromPassword(password, saltBuf);
    const plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv: ivBuf }, key, b642buf(cipherB64));
    const json = ab2str(plainBuf);
    return JSON.parse(json);
  } catch (err) {
    // decryption failed
    return null;
  }
}

// ---------------- data helpers ----------------
async function loadDataFile(){
  // fetch data.json relative to site root
  const resp = await fetch('data.json', {cache: "no-store"});
  if (!resp.ok) throw new Error('data.json não encontrado');
  const data = await resp.json();
  return data;
}
