/* =========================================================================
   VAULLET — Digital Document & Card Vault
   Client-side encryption (WebCrypto AES-256-GCM), PIN + WebAuthn biometric
   unlock, IndexedDB local encrypted cache, optional Firebase Firestore sync
   (ciphertext-only). See README for setup, Firestore rules, and threat model.
   ========================================================================= */

const DEFAULT_CATEGORIES = ["Identity","Banking","Cards","Insurance","Vehicle","Education","Employment","Medical","Tax","Personal"];
const ICONS = {Identity:"🪪",Banking:"🏦",Cards:"💳",Insurance:"🛡️",Vehicle:"🚗",Education:"🎓",Employment:"💼",Medical:"⚕️",Tax:"📄",Personal:"🗂️"};

/* ---------------- tiny state ---------------- */
const State = {
  unlocked:false,
  pinBuffer:"",
  mode:null,           // 'setup' | 'unlock'
  masterKey:null,       // CryptoKey, session-only, never persisted
  categories:[...DEFAULT_CATEGORIES],
  documents:[],         // decrypted-in-memory session objects
  favorites:new Set(),
  activeTab:"home",
  activeCategory:"All",
  theme:"dark",
  reminders:{},          // itemId -> days
  firebaseReady:false,
  db:null,
  authCallback:null,
  reauthTarget:null,
};

/* ---------------- toast ---------------- */
function toast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('show'),2400);
}

/* =========================================================================
   CRYPTO MODULE — AES-256-GCM, PBKDF2 key derivation from PIN.
   The PIN itself is NEVER stored. Only a random salt + a non-reversible
   verifier (derived key's hash) are kept, to check unlock attempts.
   ========================================================================= */
const Crypto = {
  enc:new TextEncoder(), dec:new TextDecoder(),

  async deriveKey(pin, saltB64){
    const salt = saltB64 ? this.b64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16));
    const baseKey = await crypto.subtle.importKey("raw", this.enc.encode(pin), "PBKDF2", false, ["deriveKey","deriveBits"]);
    const key = await crypto.subtle.deriveKey(
      {name:"PBKDF2", salt, iterations:210000, hash:"SHA-256"},
      baseKey, {name:"AES-GCM", length:256}, true, ["encrypt","decrypt"]
    );
    return {key, salt: this.bufToB64(salt)};
  },
  async verifierFor(key){
    const bits = await crypto.subtle.exportKey("raw", key);
    const hash = await crypto.subtle.digest("SHA-256", bits);
    return this.bufToB64(hash);
  },
  async encryptStr(key, plaintext){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, this.enc.encode(plaintext));
    return {iv:this.bufToB64(iv), ct:this.bufToB64(ct)};
  },
  async decryptStr(key, {iv, ct}){
    const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:this.b64ToBuf(iv)}, key, this.b64ToBuf(ct));
    return this.dec.decode(pt);
  },
  async encryptBytes(key, arrayBuffer){
    // For file attachments — keeps ciphertext as raw bytes (not base64) so
    // large files aren't bloated ~33% before upload to Drive.
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, arrayBuffer);
    return {iv:this.bufToB64(iv), ciphertext: ct};
  },
  async decryptBytes(key, ivB64, ciphertextArrayBuffer){
    const iv = this.b64ToBuf(ivB64);
    return await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ciphertextArrayBuffer);
  },
  bufToB64(buf){
    // Chunked conversion — avoids "Maximum call stack size exceeded" on large
    // buffers (spreading a big Uint8Array into String.fromCharCode blows the
    // JS engine's argument-count limit, which real attachments easily exceed).
    const bytes = new Uint8Array(buf);
    let binary = '';
    const chunkSize = 0x8000; // 32KB per chunk, safely under engine argument limits
    for(let i=0; i<bytes.length; i+=chunkSize){
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i+chunkSize));
    }
    return btoa(binary);
  },
  b64ToBuf(b64){ return Uint8Array.from(atob(b64), c=>c.charCodeAt(0)); },
};

/* =========================================================================
   LOCAL ENCRYPTED STORE — IndexedDB. Holds: vault config (salt, verifier,
   webauthn credential id) and encrypted document/card blobs. Nothing here
   is ever plaintext except the salt (a salt alone reveals nothing).
   ========================================================================= */
const LocalDB = {
  _db:null,
  open(){
    return new Promise((res,rej)=>{
      const req = indexedDB.open("vaullet", 1);
      req.onupgradeneeded = e=>{
        const db=e.target.result;
        if(!db.objectStoreNames.contains("config")) db.createObjectStore("config",{keyPath:"k"});
        if(!db.objectStoreNames.contains("items")) db.createObjectStore("items",{keyPath:"id"});
      };
      req.onsuccess = e=>{ this._db=e.target.result; res(this._db); };
      req.onerror = ()=>rej(req.error);
    });
  },
  async getConfig(k){
    return new Promise((res)=>{
      const tx=this._db.transaction("config","readonly").objectStore("config").get(k);
      tx.onsuccess=()=>res(tx.result? tx.result.v : null);
      tx.onerror=()=>res(null);
    });
  },
  async setConfig(k,v){
    return new Promise((res)=>{
      const tx=this._db.transaction("config","readwrite").objectStore("config").put({k,v});
      tx.onsuccess=()=>res(true); tx.onerror=()=>res(false);
    });
  },
  async allItems(){
    return new Promise((res)=>{
      const out=[];
      const tx=this._db.transaction("items","readonly").objectStore("items").openCursor();
      tx.onsuccess=e=>{ const c=e.target.result; if(c){out.push(c.value); c.continue();} else res(out); };
      tx.onerror=()=>res(out);
    });
  },
  async putItem(item){
    return new Promise((res, rej)=>{
      let req;
      try{ req = this._db.transaction("items","readwrite").objectStore("items").put(item); }
      catch(e){ rej(e); return; }
      req.onsuccess=()=>res(true);
      req.onerror=()=>rej(req.error || new Error('IndexedDB write failed'));
    });
  },
  async deleteItem(id){
    return new Promise((res)=>{
      const tx=this._db.transaction("items","readwrite").objectStore("items").delete(id);
      tx.onsuccess=()=>res(true); tx.onerror=()=>res(false);
    });
  }
};

/* =========================================================================
   CLOUD SYNC — Firebase Firestore. Vault content is encrypted client-side
   BEFORE it is written; Firestore only ever stores ciphertext + non-
   sensitive metadata (category, timestamps). See README for security rules.
   ========================================================================= */
const Cloud = {
  app:null, db:null, uid:null, configured:false,
  async init(cfg){
    try{
      if(!window.firebase) throw new Error("Firebase SDK not loaded");
      this.app = firebase.apps.length ? firebase.apps[0] : firebase.initializeApp(cfg);
      this.db = firebase.firestore();
      // No Firebase Auth — this app uses Firestore purely as encrypted storage.
      // A random per-device ID (kept locally) scopes each vault's documents.
      this.uid = await LocalDB.getConfig('deviceId');
      if(!this.uid){
        this.uid = 'device_' + Crypto.bufToB64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^a-zA-Z0-9]/g,'');
        await LocalDB.setConfig('deviceId', this.uid);
      }
      this.configured = true;
      return true;
    }catch(e){ console.warn("Cloud sync unavailable:", e.message); this.configured=false; return false; }
  },
  col(){ return this.db.collection("vaults").doc(this.uid).collection("items"); },
  async push(encryptedItem){
    if(!this.configured) return {ok:false, reason:'not-configured'};
    const approxBytes = new Blob([JSON.stringify(encryptedItem)]).size;
    if(approxBytes > 900 * 1024){
      // Firestore hard-caps every document at 1MiB. Encrypted attachments
      // that exceed that stay local-only rather than failing the API call.
      console.warn(`Skipping Firestore sync for "${encryptedItem.id}": ${(approxBytes/1024/1024).toFixed(2)}MB exceeds Firestore's 1MB document limit.`);
      return {ok:false, reason:'too-large', sizeMB:(approxBytes/1024/1024).toFixed(1)};
    }
    try{ await this.col().doc(encryptedItem.id).set(encryptedItem); return {ok:true}; }
    catch(e){ console.warn("sync push failed", e.message); return {ok:false, reason:'error', message:e.message}; }
  },
  async pull(){
    if(!this.configured) return [];
    try{ const snap = await this.col().get(); return snap.docs.map(d=>d.data()); }
    catch(e){ console.warn("sync pull failed", e.message); return []; }
  },
  async remove(id){
    if(!this.configured) return false;
    try{ await this.col().doc(id).delete(); return true; } catch(e){ return false; }
  }
};

/* =========================================================================
   GOOGLE DRIVE — used purely as encrypted blob storage for attachments.
   Files are AES-256-GCM encrypted in the browser before upload; Drive only
   ever stores ciphertext. Firestore/local metadata holds just a small
   pointer (driveFileId) + name/type/size/iv, so document size stays tiny
   regardless of the actual file size — this is what lets large attachments
   sync across devices despite Firestore's 1MB-per-document cap.
   Uses Google Identity Services (GIS) token client + the 'drive.file'
   scope, which only grants access to files this app itself creates —
   Vaullet never sees the rest of your Drive.
   ========================================================================= */
const Drive = {
  tokenClient:null, accessToken:null, tokenExpiry:0, configured:false,
  _resolve:null, _reject:null,

  async ensureReady(){
    if(this.configured) return true;
    const cfg = window.VAULLET_GOOGLE_CONFIG;
    if(!cfg || !cfg.clientId) return false;
    for(let i=0;i<25;i++){ // poll up to ~5s for the async GIS script to load
      if(window.google && google.accounts && google.accounts.oauth2){
        this.tokenClient = google.accounts.oauth2.initTokenClient({
          client_id: cfg.clientId,
          scope: 'https://www.googleapis.com/auth/drive.file',
          callback: (resp)=>{
            if(resp && resp.access_token){
              this.accessToken = resp.access_token;
              this.tokenExpiry = Date.now() + ((resp.expires_in||3600)*1000) - 60000;
              if(this._resolve){ this._resolve(this.accessToken); this._resolve=null; this._reject=null; }
            } else if(this._reject){ this._reject(new Error('Google did not return an access token')); this._resolve=null; this._reject=null; }
          },
          error_callback: (err)=>{ if(this._reject){ this._reject(new Error(err.type||'Google authorization failed')); this._resolve=null; this._reject=null; } }
        });
        this.configured = true;
        return true;
      }
      await new Promise(r=>setTimeout(r,200));
    }
    return false;
  },
  async ensureToken(interactive=true){
    if(this.accessToken && Date.now() < this.tokenExpiry) return this.accessToken;
    const ready = await this.ensureReady();
    if(!ready) throw new Error('Google Drive is not configured (check google_config.js) or still loading — try again in a moment.');
    return new Promise((resolve,reject)=>{
      this._resolve = resolve; this._reject = reject;
      this.tokenClient.requestAccessToken({prompt: interactive ? 'consent' : ''});
    });
  },
  async upload(encryptedArrayBuffer, filename){
    const token = await this.ensureToken();
    const metadata = {name: `vaullet_${filename}.enc`, mimeType: 'application/octet-stream'};
    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(metadata)], {type:'application/json'}));
    form.append('file', new Blob([encryptedArrayBuffer]));
    const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', {
      method:'POST', headers:{Authorization:'Bearer '+token}, body:form
    });
    if(!res.ok) throw new Error(`Drive upload failed (HTTP ${res.status})`);
    const data = await res.json();
    return data.id;
  },
  async download(fileId){
    const token = await this.ensureToken();
    const res = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, {headers:{Authorization:'Bearer '+token}});
    if(!res.ok) throw new Error(`Drive download failed (HTTP ${res.status})`);
    return await res.arrayBuffer();
  },
  async remove(fileId){
    try{
      const token = await this.ensureToken(false);
      await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}`, {method:'DELETE', headers:{Authorization:'Bearer '+token}});
    }catch(e){ console.warn('Drive delete failed (file may need manual removal):', e.message); }
  }
};

/* =========================================================================
   WEBAUTHN — device biometric / platform authenticator as an alternative
   unlock factor. On success we still need the master key, so the PIN-
   derived key is (locally) re-wrapped: biometric only skips PIN *typing*,
   it does not bypass encryption — the underlying key material is the same.
   ========================================================================= */
const Bio = {
  supported(){ return !!(window.PublicKeyCredential); },
  async platformAvailable(){
    if(!window.PublicKeyCredential) return false;
    if(!window.isSecureContext) return false; // WebAuthn requires HTTPS or localhost
    try{ return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); }
    catch(e){ return false; }
  },
  async register(){
    const cred = await navigator.credentials.create({
      publicKey:{
        challenge:crypto.getRandomValues(new Uint8Array(32)),
        rp:{name:"Vaullet"},
        user:{id:crypto.getRandomValues(new Uint8Array(16)), name:"vault-user", displayName:"Vault User"},
        pubKeyCredParams:[{type:"public-key",alg:-7},{type:"public-key",alg:-257}],
        authenticatorSelection:{authenticatorAttachment:"platform", userVerification:"required"},
        timeout:60000,
      }
    });
    return cred ? Crypto.bufToB64(cred.rawId) : null;
  },
  async assert(credIdB64){
    await navigator.credentials.get({
      publicKey:{
        challenge:crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials:[{id:Crypto.b64ToBuf(credIdB64), type:"public-key"}],
        userVerification:"required", timeout:60000,
      }
    });
    return true;
  }
};

/* =========================================================================
   LOCK / UNLOCK FLOW
   ========================================================================= */
function drawDial(){
  const ticks=document.getElementById('ticks');
  ticks.innerHTML='';
  for(let i=0;i<24;i++){
    const a = (i/24)*2*Math.PI;
    const x1=60+44*Math.sin(a), y1=60-44*Math.cos(a), x2=60+50*Math.sin(a), y2=60-50*Math.cos(a);
    ticks.innerHTML += `<line class="dial-tick" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`;
  }
}
function spinNeedle(){
  const n=document.getElementById('needle');
  const deg = Math.floor(Math.random()*360);
  n.style.transform = `rotate(${deg}deg)`;
  setTimeout(()=>{ n.style.transform='rotate(0deg)'; }, 550);
}

function renderPinDots(container, len, filled){
  container.innerHTML='';
  for(let i=0;i<len;i++){
    const d=document.createElement('div');
    d.className='pin-dot'+(i<filled?' filled':'');
    container.appendChild(d);
  }
}
function buildKeypad(el, onDigit, onBack){
  el.innerHTML='';
  const keys=['1','2','3','4','5','6','7','8','9','','0','⌫'];
  keys.forEach(k=>{
    const b=document.createElement('button');
    if(k===''){ b.style.visibility='hidden'; }
    else if(k==='⌫'){ b.className='ghost'; b.textContent=k; b.onclick=onBack; }
    else { b.textContent=k; b.onclick=()=>onDigit(k); }
    el.appendChild(b);
  });
}

let pinTarget = 6;          // exact length required to submit (setup: fixed at 6; unlock: loaded from config)
let setupMinLen = 4;         // during setup, digits below this can't submit early
const SETUP_MAX_LEN = 6;

async function initLock(){
  drawDial();
  const salt = await LocalDB.getConfig('salt');
  const verifier = await LocalDB.getConfig('verifier');
  State.mode = salt && verifier ? 'unlock' : 'setup';

  if(State.mode==='unlock'){
    const storedLen = await LocalDB.getConfig('pinLength');
    pinTarget = storedLen || 6;   // fall back to 6 for vaults created before this fix
  } else {
    pinTarget = SETUP_MAX_LEN;    // setup keypad shows up to 6 dots; Confirm button submits 4-6 early
  }

  document.getElementById('lockTitle').textContent = State.mode==='setup' ? 'Set a vault PIN' : 'Enter your PIN';
  document.getElementById('lockSub').textContent = State.mode==='setup'
    ? 'Choose a 4–6 digit PIN, then tap Confirm (or fill all 6). This unlocks your vault key — Vaullet never stores it.'
    : 'Unlock Vaullet to continue.';
  State.pinBuffer='';
  renderPinDots(document.getElementById('pinDots'), pinTarget, 0);
  buildKeypad(document.getElementById('keypad'), onPinDigit, onPinBack);
  document.getElementById('lockError').textContent='';
  const confirmBtn = document.getElementById('confirmPinBtn');
  confirmBtn.style.visibility='hidden';
  confirmBtn.onclick = ()=>{ if(State.mode==='setup') finishSetup(); };

  const credId = await LocalDB.getConfig('webauthnCredId');
  const bioBtn = document.getElementById('bioBtn');
  if(State.mode==='unlock' && credId && Bio.supported()){
    bioBtn.style.display='inline-flex';
    bioBtn.onclick = async ()=>{
      try{
        await Bio.assert(credId);
        toast('Biometric verified — enter PIN once to finish unlocking this session');
      }catch(e){ toast('Biometric unlock cancelled'); }
    };
  } else bioBtn.style.display='none';
}

async function onPinDigit(d){
  if(State.pinBuffer.length>=pinTarget) return;
  State.pinBuffer+=d;
  renderPinDots(document.getElementById('pinDots'), pinTarget, State.pinBuffer.length);
  updateConfirmVisibility();
  if(State.mode==='setup' && State.pinBuffer.length===SETUP_MAX_LEN) await finishSetup();
  if(State.mode==='unlock' && State.pinBuffer.length===pinTarget) await tryUnlock();
}
function onPinBack(){
  State.pinBuffer = State.pinBuffer.slice(0,-1);
  renderPinDots(document.getElementById('pinDots'), pinTarget, State.pinBuffer.length);
  updateConfirmVisibility();
}
function updateConfirmVisibility(){
  const btn = document.getElementById('confirmPinBtn');
  if(!btn) return;
  btn.style.visibility = (State.mode==='setup' && State.pinBuffer.length>=setupMinLen && State.pinBuffer.length<SETUP_MAX_LEN) ? 'visible' : 'hidden';
}

async function finishSetup(){
  const pin = State.pinBuffer;
  if(pin.length < setupMinLen){ document.getElementById('lockError').textContent = `PIN must be at least ${setupMinLen} digits.`; return; }
  spinNeedle();
  const {key, salt} = await Crypto.deriveKey(pin);
  const verifier = await Crypto.verifierFor(key);
  await LocalDB.setConfig('salt', salt);
  await LocalDB.setConfig('verifier', verifier);
  await LocalDB.setConfig('pinLength', pin.length);
  State.masterKey = key;
  State.pinBuffer='';
  toast('PIN set. Vault created.');
  if(Bio.supported()){
    try{
      const credId = await Bio.register();
      if(credId) await LocalDB.setConfig('webauthnCredId', credId);
    }catch(e){ /* optional, ignore if user declines */ }
  }
  await enterVault();
}

async function tryUnlock(){
  const pin = State.pinBuffer;
  const salt = await LocalDB.getConfig('salt');
  const verifier = await LocalDB.getConfig('verifier');
  const {key} = await Crypto.deriveKey(pin, salt);
  const check = await Crypto.verifierFor(key);
  if(check===verifier){
    spinNeedle();
    State.masterKey = key;
    State.pinBuffer='';
    document.getElementById('lockError').textContent='';
    await enterVault();
  } else {
    document.getElementById('lockError').textContent='Incorrect PIN. Try again.';
    State.pinBuffer='';
    renderPinDots(document.getElementById('pinDots'), pinTarget, 0);
    const dial=document.querySelector('.dial'); dial.style.animation='none';
    requestAnimationFrame(()=>{ dial.style.animation='shake .3s'; });
  }
}

/* ---------------- keyboard input for PIN screens ---------------- */
document.addEventListener('keydown', (e)=>{
  const lockVisible = document.getElementById('lock').style.display !== 'none';
  const authVisible = document.getElementById('authModal').classList.contains('active');
  if(!lockVisible && !authVisible) return;
  if(e.key >= '0' && e.key <= '9'){
    e.preventDefault();
    if(authVisible){
      const btn = [...document.querySelectorAll('#authKeypad button')].find(b=>b.textContent===e.key);
      if(btn) btn.click();
    } else if(lockVisible){
      const btn = [...document.querySelectorAll('#keypad button')].find(b=>b.textContent===e.key);
      if(btn) btn.click();
    }
  } else if(e.key === 'Backspace'){
    e.preventDefault();
    if(authVisible) onAuthBack(); else if(lockVisible) onPinBack();
  } else if(e.key === 'Enter'){
    if(lockVisible && State.mode==='setup' && State.pinBuffer.length>=setupMinLen && State.pinBuffer.length<SETUP_MAX_LEN){
      e.preventDefault(); finishSetup();
    }
  }
});

async function enterVault(){
  document.getElementById('lock').style.display='none';
  document.getElementById('app').classList.add('active');
  try{
    await loadVaultData();
  }catch(e){
    console.error('Vault load failed:', e);
    toast('Some data failed to load — check console for details. Local documents are still shown.');
  }
  renderRail();
  navigate('home');
}

function lockVault(){
  State.unlocked=false;
  State.masterKey=null;
  State.documents=[];
  State.pinBuffer='';
  document.getElementById('app').classList.remove('active');
  document.getElementById('lock').style.display='flex';
  initLock();
}

/* =========================================================================
   DATA LOAD / SAVE — decrypt on load into memory only (session), re-encrypt
   on every save. Cloud sync merges ciphertext both ways.
   ========================================================================= */
async function loadVaultData(){
  const cats = await LocalDB.getConfig('categories');
  State.categories = cats && cats.length ? cats : [...DEFAULT_CATEGORIES];

  let localItems = await LocalDB.allItems();

  const fileCfg = window.VAULLET_FIREBASE_CONFIG;
  const fbCfg = (fileCfg && fileCfg.apiKey) ? fileCfg : await LocalDB.getConfig('firebaseConfig');
  if(fbCfg){
    try{
      const ok = await Cloud.init(fbCfg);
      if(ok){
        toast('Connected to Firestore — syncing…');
        const cloudItems = await Cloud.pull();
        const localIds = new Set(localItems.map(i=>i.id));
        for(const ci of cloudItems){
          if(!localIds.has(ci.id)){
            try{ await LocalDB.putItem(ci); } catch(e){ console.warn('Skipping malformed cloud item', ci.id, e); }
          }
        }
        localItems = await LocalDB.allItems();
      }
    }catch(e){
      console.error('Firestore sync failed, continuing with local data only:', e);
      toast('Firestore sync failed — showing local documents only. See console for details.');
    }
  }

  State.documents = [];
  for(const enc of localItems){
    try{
      const json = await Crypto.decryptStr(State.masterKey, {iv:enc.iv, ct:enc.ct});
      const data = JSON.parse(json);
      State.documents.push({...data, id:enc.id, favorite:!!enc.favorite, updatedAt:enc.updatedAt});
    }catch(e){ console.warn('Could not decrypt item', enc.id); }
  }
}

async function saveDocument(doc){
  const id = doc.id || ('doc_'+Date.now()+'_'+Math.random().toString(36).slice(2,8));
  const payload = {...doc}; delete payload.id; delete payload.favorite; delete payload.updatedAt;
  const {iv, ct} = await Crypto.encryptStr(State.masterKey, JSON.stringify(payload));
  const encItem = {id, iv, ct, category:doc.category, type:doc.type, favorite:doc.favorite||false, updatedAt:Date.now()};
  await LocalDB.putItem(encItem);
  const pushResult = await Cloud.push(encItem);
  await loadVaultData();
  return pushResult;
}

async function deleteDocument(id){
  const d = State.documents.find(x=>x.id===id);
  if(d && d.attachment && d.attachment.storage === 'drive'){
    await Drive.remove(d.attachment.driveFileId);
  }
  await LocalDB.deleteItem(id);
  await Cloud.remove(id);
  await loadVaultData();
  render();
}

async function toggleFavorite(id){
  try{
    const items = await LocalDB.allItems();
    const it = items.find(i=>i.id===id);
    if(!it) return;
    it.favorite = !it.favorite;
    await LocalDB.putItem(it);
    await Cloud.push(it);
    await loadVaultData();
    render();
  }catch(e){
    console.error('Could not update favorite:', e);
    toast('Could not update favorite (see console)');
  }
}

/* =========================================================================
   NAVIGATION / RAIL
   ========================================================================= */
const NAV = [
  {id:'home', label:'Home', icon:'M3 11l9-8 9 8M5 10v10h14V10'},
  {id:'documents', label:'Documents', icon:'M6 2h9l5 5v15H6zM14 2v6h6'},
  {id:'wallet', label:'Wallet', icon:'M3 7h18v13H3zM3 10h18M7 15h4'},
  {id:'search', label:'Search', icon:'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-4.3-4.3'},
  {id:'notifications', label:'Alerts', icon:'M12 3a5 5 0 0 0-5 5v3l-2 4h14l-2-4V8a5 5 0 0 0-5-5zM10 20a2 2 0 0 0 4 0'},
  {id:'settings', label:'Settings', icon:'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z'},
];
function renderRail(){
  const rail = document.getElementById('rail');
  rail.innerHTML = `<svg class="rail-logo" viewBox="0 0 40 40"><rect x="4" y="4" width="32" height="32" rx="9" fill="none" stroke="var(--brass)" stroke-width="2"/><circle cx="20" cy="20" r="5" fill="var(--brass)"/></svg>`;
  NAV.forEach(n=>{
    const b=document.createElement('button');
    b.className='rail-btn'+(State.activeTab===n.id?' active':'');
    b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="${n.icon}"/></svg><span>${n.label}</span>`;
    b.onclick=()=>navigate(n.id);
    rail.appendChild(b);
  });
}
function navigate(tab){
  State.activeTab = tab;
  renderRail();
  render();
}

/* =========================================================================
   RENDER — per-tab view builders
   ========================================================================= */
function fmtDate(d){ if(!d) return '—'; const dt=new Date(d); return dt.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}); }
function daysUntil(d){ if(!d) return Infinity; return Math.ceil((new Date(d) - new Date())/86400000); }
function maskNumber(num){
  if(!num) return '—';
  const clean = num.replace(/\s/g,'');
  if(clean.length<=4) return '••••';
  return 'XXXX '.repeat(Math.max(0,Math.floor((clean.length-4)/4))).trim()+' '+clean.slice(-4);
}

function render(){
  const c = document.getElementById('content');
  const title = document.getElementById('pageTitle');
  const sub = document.getElementById('pageSub');
  const views = {
    home: ()=>{ title.textContent='Home'; sub.textContent='Your vault at a glance'; return renderHome(); },
    documents: ()=>{ title.textContent='Documents'; sub.textContent=`${State.documents.filter(d=>d.type!=='card').length} stored documents`; return renderDocuments(); },
    wallet: ()=>{ title.textContent='Wallet'; sub.textContent='Cards & frequently used IDs'; return renderWallet(); },
    search: ()=>{ title.textContent='Search'; sub.textContent='Find anything in your vault'; return renderSearch(); },
    notifications: ()=>{ title.textContent='Alerts'; sub.textContent='Expiry reminders'; return renderNotifications(); },
    settings: ()=>{ title.textContent='Settings'; sub.textContent='Security, sync & preferences'; return renderSettings(); },
  };
  c.innerHTML = views[State.activeTab]();
  wireContentEvents();
}

function docRowHtml(d){
  const expiring = d.expiry && daysUntil(d.expiry) <= 30 && daysUntil(d.expiry) >= 0;
  const expired = d.expiry && daysUntil(d.expiry) < 0;
  return `<div class="doc-row" data-id="${d.id}" data-action="open">
    <div class="doc-icon">${ICONS[d.category]||'📁'}</div>
    <div class="doc-meta">
      <div class="doc-name">${escapeHtml(d.name)}</div>
      <div class="doc-cat">${escapeHtml(d.category)} ${d.number? '· <span class="mono">'+maskNumber(d.number)+'</span>':''}</div>
    </div>
    ${expired? '<span class="doc-badge badge-warn">Expired</span>' : expiring? `<span class="doc-badge badge-warn">${daysUntil(d.expiry)}d left</span>`:''}
    <button class="btn-ghost" data-action="fav" data-id="${d.id}" style="font-size:15px;">${d.favorite?'<span class="badge-fav">★</span>':'☆'}</button>
  </div>`;
}

function renderHome(){
  const docs = State.documents;
  const recents = [...docs].sort((a,b)=>(b.updatedAt||0)-(a.updatedAt||0)).slice(0,4);
  const favs = docs.filter(d=>d.favorite).slice(0,4);
  const expiring = docs.filter(d=>d.expiry && daysUntil(d.expiry)<=30).sort((a,b)=>daysUntil(a.expiry)-daysUntil(b.expiry)).slice(0,4);

  return `
  <div class="grid">
    <div class="stat-card"><div class="stat-num">${docs.length}</div><div class="stat-label">Total stored</div></div>
    <div class="stat-card"><div class="stat-num">${State.categories.length}</div><div class="stat-label">Categories</div></div>
    <div class="stat-card"><div class="stat-num">${docs.filter(d=>d.favorite).length}</div><div class="stat-label">Favorites</div></div>
    <div class="stat-card"><div class="stat-num" style="color:${expiring.length?'var(--alert)':'inherit'}">${expiring.length}</div><div class="stat-label">Expiring soon</div></div>
  </div>

  <div style="display:flex; gap:10px; margin-top:24px; flex-wrap:wrap;">
    <button class="btn btn-brass" data-action="add-doc">＋ Upload</button>
    <button class="btn" data-action="scan">📷 Scan</button>
    <button class="btn" data-action="goto-search">🔍 Search</button>
    <button class="btn" data-action="add-card">💳 Add card</button>
  </div>

  <div class="section-title">Expiring soon ${expiring.length?`<span class="link" data-action="goto-alerts">View all</span>`:''}</div>
  ${expiring.length? expiring.map(docRowHtml).join('') : '<div class="empty">Nothing expiring in the next 30 days.</div>'}

  <div class="section-title">Recently accessed</div>
  ${recents.length? recents.map(docRowHtml).join('') : '<div class="empty">No documents yet — upload your first one.</div>'}

  <div class="section-title">Favorites</div>
  ${favs.length? favs.map(docRowHtml).join('') : '<div class="empty">Star documents to pin them here.</div>'}
  `;
}

function renderDocuments(){
  const docs = State.documents.filter(d=>d.type!=='card' && (State.activeCategory==='All'||d.category===State.activeCategory));
  const cats = ['All', ...State.categories];
  return `
  <div class="cat-pills">
    ${cats.map(c=>`<button class="cat-pill ${State.activeCategory===c?'active':''}" data-action="filter-cat" data-cat="${escapeHtml(c)}">${escapeHtml(c)}</button>`).join('')}
    <button class="cat-pill" data-action="new-cat" style="border-style:dashed;">＋ New category</button>
  </div>
  <div style="margin-bottom:16px;"><button class="btn btn-brass" data-action="add-doc">＋ Add document</button></div>
  ${docs.length? `<div class="doc-grid">${docs.map(d=>`<div>${docRowHtml(d)}</div>`).join('')}</div>` : '<div class="empty">No documents in this category yet.</div>'}
  `;
}

function renderWallet(){
  const cards = State.documents.filter(d=>d.type==='card');
  return `
  <div style="margin-bottom:18px;"><button class="btn btn-brass" data-action="add-card">＋ Add card</button></div>
  ${cards.length? `<div class="wallet-grid">${cards.map(cardHtml).join('')}</div>` : '<div class="empty">No cards yet. Add a credit, debit, ID or insurance card.</div>'}
  `;
}
function cardHtml(d){
  return `<div class="wallet-card" data-id="${d.id}">
    <div class="wc-top">
      <div class="wc-type">${escapeHtml(d.category)}</div>
      <button class="wc-fav" data-action="fav" data-id="${d.id}">${d.favorite?'★':'☆'}</button>
    </div>
    <div class="wc-number mono" data-masked="true" data-id="${d.id}">${maskNumber(d.number)}</div>
    <div class="wc-bottom">
      <div>
        <div class="wc-label">Name</div>
        <div class="wc-value">${escapeHtml(d.name)}</div>
      </div>
      <button class="wc-reveal" data-action="reveal" data-id="${d.id}">Reveal</button>
    </div>
  </div>`;
}

function renderSearch(){
  return `
  <div class="search-box">
    <span class="search-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM21 21l-4.3-4.3"/></svg></span>
    <input id="searchInput" placeholder="Search by name, category, tag or document number…" autofocus>
  </div>
  <div id="searchResults"><div class="empty">Type to search across your entire vault.</div></div>
  `;
}
function runSearch(q){
  const results = document.getElementById('searchResults');
  if(!q.trim()){ results.innerHTML='<div class="empty">Type to search across your entire vault.</div>'; return; }
  const ql = q.toLowerCase();
  const matches = State.documents.filter(d=>
    d.name?.toLowerCase().includes(ql) ||
    d.category?.toLowerCase().includes(ql) ||
    d.number?.toLowerCase().includes(ql) ||
    (d.tags||[]).some(t=>t.toLowerCase().includes(ql))
  );
  results.innerHTML = matches.length? matches.map(docRowHtml).join('') : '<div class="empty">No matches found.</div>';
}

function renderNotifications(){
  const withExpiry = State.documents.filter(d=>d.expiry).sort((a,b)=>daysUntil(a.expiry)-daysUntil(b.expiry));
  return `
  <div class="help-text" style="margin-bottom:18px;">Reminders are calculated locally in your browser. For real push notifications, wrap this app in the planned Android/iOS client with OS-level scheduled notifications.</div>
  ${withExpiry.length? withExpiry.map(d=>{
    const days = daysUntil(d.expiry);
    const status = days<0? `<span class="doc-badge badge-warn">Expired ${Math.abs(days)}d ago</span>` : days<=30? `<span class="doc-badge badge-warn">${days} days left</span>` : `<span class="doc-badge badge-ok">Valid</span>`;
    return `<div class="doc-row">
      <div class="doc-icon">${ICONS[d.category]||'📁'}</div>
      <div class="doc-meta"><div class="doc-name">${escapeHtml(d.name)}</div><div class="doc-cat">Expires ${fmtDate(d.expiry)} ${d.reminder? '· reminder '+d.reminder+'d before':''}</div></div>
      ${status}
    </div>`;
  }).join('') : '<div class="empty">No documents with expiry dates yet.</div>'}
  `;
}

function renderSettings(){
  return `
  <div class="settings-card">
    <div class="settings-row">
      <div><div class="settings-label">Dark mode</div><div class="settings-sub">Switch between light and dark themes</div></div>
      <label class="switch"><input type="checkbox" id="themeSwitch" ${State.theme==='dark'?'checked':''}><span class="slider"></span></label>
    </div>
    <div class="settings-row">
      <div><div class="settings-label">Biometric unlock</div><div class="settings-sub" id="bioSub">Use Face ID / fingerprint where supported</div></div>
      <label class="switch"><input type="checkbox" id="bioSwitch"><span class="slider"></span></label>
    </div>
    <div class="settings-row">
      <div><div class="settings-label">Auto-lock</div><div class="settings-sub">Lock vault after 2 minutes of inactivity</div></div>
      <label class="switch"><input type="checkbox" id="autolockSwitch" checked><span class="slider"></span></label>
    </div>
  </div>

  <div class="section-title">Cloud sync — Firebase Firestore</div>
  <div class="settings-card" style="padding:18px 22px;">
    ${(window.VAULLET_FIREBASE_CONFIG && window.VAULLET_FIREBASE_CONFIG.apiKey) ? `
    <div class="help-text" style="margin-bottom:6px;">
      Loaded from <span class="mono">firebase_config.js</span> — project
      <strong>${escapeHtml(window.VAULLET_FIREBASE_CONFIG.projectId||'')}</strong>.
      Status: <span style="color:${Cloud.configured?'var(--safe)':'var(--alert)'}">${Cloud.configured?'Connected':'Not connected — check the console for errors'}</span>
    </div>
    <div class="help-text">To change credentials, edit <span class="mono">firebase_config.js</span> directly (keep it out of version control) and reload the app.</div>
    ` : `
    <div class="help-text" style="margin-bottom:12px;">
      Recommended: put your credentials in <span class="mono">firebase_config.js</span>
      (a separate file next to <span class="mono">index.html</span>, kept out of
      source control) — it auto-connects on load. Or paste a config below for a
      quick one-off session. Documents are encrypted in your browser before being
      written to Firestore — set the security rules in the README so only your
      signed-in vault can read/write its own ciphertext.
    </div>
    <div class="field"><label>Firebase config (JSON) — session only, not saved to a file</label><textarea id="fbConfig" rows="5" placeholder='{"apiKey":"...","authDomain":"...","projectId":"...","appId":"..."}'></textarea></div>
    <button class="btn btn-brass" id="saveFbBtn">Connect Firestore</button>
    <span id="fbStatus" class="help-text" style="margin-left:10px;"></span>
    `}
  </div>

  <div class="section-title">File storage — Google Drive</div>
  <div class="settings-card" style="padding:18px 22px;">
    ${(window.VAULLET_GOOGLE_CONFIG && window.VAULLET_GOOGLE_CONFIG.clientId) ? `
    <div class="help-text" style="margin-bottom:6px;">
      Attachments are encrypted, then uploaded to your Google Drive (via the
      restricted <span class="mono">drive.file</span> scope — Vaullet can only
      see files it creates, not your whole Drive). Firestore/local storage
      then holds only a small pointer + metadata, so document size stays tiny
      no matter how large the file is.
      Status: <span id="driveStatus" style="color:${Drive.accessToken?'var(--safe)':'var(--steel)'}">${Drive.accessToken?'Authorized':'Not yet authorized this session'}</span>
    </div>
    <button class="btn btn-brass" id="connectDriveBtn">${Drive.accessToken?'Re-authorize Google Drive':'Connect Google Drive'}</button>
    ` : `
    <div class="help-text">
      Add a Client ID to <span class="mono">google_config.js</span> (a separate
      file next to <span class="mono">index.html</span>) to enable this — see
      the README for the Google Cloud Console setup steps. Without it,
      attachments over ~0.9MB stay local-only (see the Firestore note above).
    </div>
    `}
  </div>

  <div class="section-title">Backup</div>
  <div class="settings-card" style="padding:18px 22px;">
    <div class="help-text" style="margin-bottom:12px;">Export an encrypted backup file (password-protected with your current PIN-derived key). Import it on any device after unlocking with the same PIN.</div>
    <div style="display:flex; gap:10px;">
      <button class="btn" id="exportBtn">⬇ Export encrypted backup</button>
      <button class="btn" id="importBtn">⬆ Import backup</button>
      <input type="file" id="importFile" accept=".vkbak" style="display:none">
    </div>
  </div>

  <div class="section-title">Categories</div>
  <div class="cat-pills">${State.categories.map(c=>`<span class="cat-pill">${escapeHtml(c)}</span>`).join('')}
  <button class="cat-pill" data-action="new-cat" style="border-style:dashed;">＋ New category</button></div>

  <div class="section-title" style="color:var(--alert)">Danger zone</div>
  <div class="settings-card" style="padding:18px 22px;">
    <button class="btn btn-danger" id="wipeBtn">Erase vault from this device</button>
  </div>
  `;
}

function escapeHtml(s){ return (s||'').replace(/[&<>"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

/* =========================================================================
   EVENT WIRING
   ========================================================================= */
function wireContentEvents(){
  document.querySelectorAll('[data-action="add-doc"]').forEach(b=>b.onclick=()=>openDocModal('document'));
  document.querySelectorAll('[data-action="add-card"]').forEach(b=>b.onclick=()=>openDocModal('card'));
  document.querySelectorAll('[data-action="scan"]').forEach(b=>b.onclick=()=>{ openDocModal('document'); setTimeout(()=>document.getElementById('f_file').click(),200); });
  document.querySelectorAll('[data-action="goto-search"]').forEach(b=>b.onclick=()=>navigate('search'));
  document.querySelectorAll('[data-action="goto-alerts"]').forEach(b=>b.onclick=()=>navigate('notifications'));
  document.querySelectorAll('[data-action="filter-cat"]').forEach(b=>b.onclick=()=>{ State.activeCategory=b.dataset.cat; render(); });
  document.querySelectorAll('[data-action="new-cat"]').forEach(b=>b.onclick=()=>document.getElementById('catModal').classList.add('active'));
  document.querySelectorAll('[data-action="fav"]').forEach(b=>b.onclick=(e)=>{ e.stopPropagation(); toggleFavorite(b.dataset.id); });
  document.querySelectorAll('[data-action="reveal"]').forEach(b=>b.onclick=()=>requestReveal(b.dataset.id));
  document.querySelectorAll('.doc-row[data-action="open"]').forEach(r=>r.onclick=(e)=>{ if(e.target.closest('[data-action="fav"]')) return; viewDocument(r.dataset.id); });

  const search = document.getElementById('searchInput');
  if(search) search.oninput = ()=>runSearch(search.value);

  const themeSwitch = document.getElementById('themeSwitch');
  if(themeSwitch) themeSwitch.onchange = ()=>setTheme(themeSwitch.checked?'dark':'light');

  const bioSwitch = document.getElementById('bioSwitch');
  if(bioSwitch){
    LocalDB.getConfig('webauthnCredId').then(id=>bioSwitch.checked=!!id);
    Bio.platformAvailable().then(avail=>{
      const sub = document.getElementById('bioSub');
      if(!avail){
        bioSwitch.disabled = true;
        if(sub) sub.textContent = !window.isSecureContext
          ? 'Requires HTTPS or localhost — open this file via a local server, not file://'
          : 'No fingerprint/Face ID available on this device or browser';
      }
    });
    bioSwitch.onchange = async ()=>{
      if(bioSwitch.checked){
        try{
          const id=await Bio.register();
          await LocalDB.setConfig('webauthnCredId', id);
          toast('Biometric unlock enabled');
        }catch(e){
          bioSwitch.checked=false;
          console.warn('WebAuthn register failed:', e.name, e.message);
          toast('Could not enable biometrics: ' + (e.message || e.name || 'unknown error'));
        }
      } else { await LocalDB.setConfig('webauthnCredId', null); toast('Biometric unlock disabled'); }
    };
  }

  const saveFbBtn = document.getElementById('saveFbBtn');
  if(saveFbBtn) saveFbBtn.onclick = async ()=>{
    const raw = document.getElementById('fbConfig').value.trim();
    const status = document.getElementById('fbStatus');
    try{
      const cfg = JSON.parse(raw);
      status.textContent='Connecting…';
      const ok = await Cloud.init(cfg);
      if(ok){ await LocalDB.setConfig('firebaseConfig', cfg); status.textContent='✓ Connected'; status.style.color='var(--safe)'; toast('Firestore connected — syncing in background'); await loadVaultData(); render(); }
      else { status.textContent='Could not connect — check config'; status.style.color='var(--alert)'; }
    }catch(e){ status.textContent='Invalid JSON'; status.style.color='var(--alert)'; }
  };

  const connectDriveBtn = document.getElementById('connectDriveBtn');
  if(connectDriveBtn) connectDriveBtn.onclick = async ()=>{
    const original = connectDriveBtn.textContent;
    connectDriveBtn.disabled = true; connectDriveBtn.textContent = 'Opening Google sign-in…';
    try{
      await Drive.ensureToken(true);
      toast('Google Drive connected — new attachments will upload there.');
    }catch(e){
      console.error('Drive connect failed:', e);
      toast('Could not connect Google Drive: ' + e.message);
    }finally{
      connectDriveBtn.disabled = false; connectDriveBtn.textContent = original;
      render();
    }
  };

  const exportBtn = document.getElementById('exportBtn');
  if(exportBtn) exportBtn.onclick = exportBackup;
  const importBtn = document.getElementById('importBtn');
  if(importBtn) importBtn.onclick = ()=>document.getElementById('importFile').click();
  const importFile = document.getElementById('importFile');
  if(importFile) importFile.onchange = importBackup;

  const wipeBtn = document.getElementById('wipeBtn');
  if(wipeBtn) wipeBtn.onclick = async ()=>{
    if(confirm('This permanently deletes all locally stored vault data on this device. Continue?')){
      indexedDB.deleteDatabase('vaullet');
      toast('Vault erased. Reloading…');
      setTimeout(()=>location.reload(), 900);
    }
  };
}

function setTheme(t){
  State.theme=t;
  document.documentElement.setAttribute('data-theme', t);
}

/* ---------------- document modal ---------------- */
let editingId = null;
function openDocModal(type){
  editingId = null;
  document.getElementById('docModalTitle').textContent = type==='card' ? 'Add card' : 'Add document';
  document.getElementById('f_name').value='';
  document.getElementById('f_number').value='';
  document.getElementById('f_issue').value='';
  document.getElementById('f_expiry').value='';
  document.getElementById('f_tags').value='';
  document.getElementById('f_notes').value='';
  document.getElementById('f_file').value='';
  document.getElementById('f_reminder').value='';
  document.getElementById('f_type').value=type;
  document.getElementById('existingAttachment').style.display='none';
  const catSel = document.getElementById('f_category');
  catSel.innerHTML = State.categories.map(c=>`<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
  if(type==='card') catSel.value = 'Cards';
  document.getElementById('docModal').classList.add('active');
}
function viewDocument(id){
  const d = State.documents.find(x=>x.id===id);
  if(!d) return;
  editingId = id;
  document.getElementById('docModalTitle').textContent = 'Edit document';
  document.getElementById('f_name').value=d.name||'';
  document.getElementById('f_number').value=d.number||'';
  document.getElementById('f_issue').value=d.issue||'';
  document.getElementById('f_expiry').value=d.expiry||'';
  document.getElementById('f_tags').value=(d.tags||[]).join(', ');
  document.getElementById('f_notes').value=d.notes||'';
  document.getElementById('f_reminder').value=d.reminder||'';
  document.getElementById('f_type').value=d.type||'document';
  const catSel = document.getElementById('f_category');
  catSel.innerHTML = State.categories.map(c=>`<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
  catSel.value = d.category;
  const attSlot = document.getElementById('existingAttachment');
  if(d.attachment){
    attSlot.style.display='block';
    const isPreviewable = /\.(pdf|jpg|jpeg|png)$/i.test(d.attachment.name||'');
    attSlot.innerHTML = `<div class="doc-row" style="margin-bottom:0;">
      <div class="doc-icon">📎</div>
      <div class="doc-meta"><div class="doc-name">${escapeHtml(d.attachment.name||'Attachment')}</div>
      <div class="doc-cat">${d.attachment.storage==='drive'?'Stored on Google Drive (encrypted)':'Stored locally (encrypted)'}</div></div>
      ${isPreviewable?`<button class="btn" data-action="preview-attachment" data-id="${d.id}" type="button">👁 Preview</button>`:''}
      <button class="btn" data-action="download-attachment" data-id="${d.id}" type="button">⬇ Download</button>
    </div>`;
  } else {
    attSlot.style.display='none';
  }
  document.getElementById('docModal').classList.add('active');
}

document.getElementById('saveDocBtn').onclick = async ()=>{
  const btn = document.getElementById('saveDocBtn');
  const originalLabel = btn.textContent;
  btn.disabled = true; btn.textContent = 'Saving…';
  try{
    if(!State.masterKey) throw new Error('Vault key missing — please lock and unlock the vault again.');
    const fileInput = document.getElementById('f_file');
    let attachment = null;
    if(fileInput.files[0]){
      const file = fileInput.files[0];
      if(file.size > 100 * 1024 * 1024) throw new Error(`"${file.name}" is ${(file.size/1024/1024).toFixed(1)}MB — please attach files under 100MB.`);
      const driveReady = window.VAULLET_GOOGLE_CONFIG && window.VAULLET_GOOGLE_CONFIG.clientId && await Drive.ensureReady();
      if(driveReady){
        btn.textContent = 'Encrypting…';
        const rawBytes = await file.arrayBuffer();
        const {iv, ciphertext} = await Crypto.encryptBytes(State.masterKey, rawBytes);
        btn.textContent = 'Uploading to Drive…';
        const driveFileId = await Drive.upload(ciphertext, file.name);
        attachment = {storage:'drive', driveFileId, name:file.name, type:file.type, size:file.size, iv};
        btn.textContent = 'Saving…';
      } else {
        attachment = await fileToBase64(file);
        attachment.storage = 'inline';
      }
    }
    const doc = {
      id: editingId,
      name: document.getElementById('f_name').value.trim() || 'Untitled',
      category: document.getElementById('f_category').value,
      type: document.getElementById('f_type').value,
      number: document.getElementById('f_number').value.trim(),
      issue: document.getElementById('f_issue').value,
      expiry: document.getElementById('f_expiry').value,
      tags: document.getElementById('f_tags').value.split(',').map(t=>t.trim()).filter(Boolean),
      notes: document.getElementById('f_notes').value.trim(),
      reminder: document.getElementById('f_reminder').value,
      attachment: attachment,
      favorite: editingId ? (State.documents.find(x=>x.id===editingId)||{}).favorite : false,
    };
    const pushResult = await saveDocument(doc);
    closeModals();
    render();
    if(pushResult && pushResult.reason === 'too-large'){
      toast(`Saved locally (${pushResult.sizeMB}MB). Too large for Firestore's 1MB document limit — not synced to cloud.`);
    } else if(pushResult && pushResult.reason === 'error'){
      toast('Saved locally. Firestore sync failed: ' + pushResult.message);
    } else {
      toast('Saved — encrypted before storage.');
    }
  }catch(e){
    console.error('Save to vault failed:', e);
    toast('Could not save: ' + (e.message || 'unknown error') + ' (see console for details)');
  }finally{
    btn.disabled = false; btn.textContent = originalLabel;
  }
};

/* ................ preview an attachment (view in modal without download) .............. */
document.getElementById('previewModal').addEventListener('click', async (e)=>{
  if(e.target.closest('[data-action="preview-attachment"]')){
    const id = e.target.closest('[data-action="preview-attachment"]').dataset.id;
    const d = State.documents.find(x=>x.id===id);
    if(!d || !d.attachment) return;
    await previewAttachment(d);
  }
});

async function previewAttachment(d){
  const modal = document.getElementById('previewModal');
  const content = document.getElementById('previewContent');
  const title = document.getElementById('previewTitle');
  const body = document.getElementById('previewBody');
  
  title.textContent = escapeHtml(d.attachment.name || 'Attachment');
  content.innerHTML = '<div style="text-align:center; padding:40px; color:var(--steel);">Loading…</div>';
  modal.classList.add('active');
  
  try{
    let blob;
    const fileName = d.attachment.name || 'attachment';
    
    if(d.attachment.storage === 'drive'){
      content.innerHTML = '<div style="text-align:center; padding:40px; color:var(--steel);">Downloading from Google Drive…</div>';
      const cipherBuf = await Drive.download(d.attachment.driveFileId);
      const plainBuf = await Crypto.decryptBytes(State.masterKey, d.attachment.iv, cipherBuf);
      blob = new Blob([plainBuf], {type: d.attachment.type || 'application/octet-stream'});
    } else {
      const res = await fetch(d.attachment.data);
      blob = await res.blob();
    }
    
    if(/\.pdf$/i.test(fileName) && window.pdfjsLib){
      await renderPdfPreview(blob, body);
    } else if(/\.(jpg|jpeg|png|gif|webp)$/i.test(fileName)){
      renderImagePreview(blob, body);
    } else {
      content.innerHTML = `<div style="text-align:center; padding:40px;"><div style="color:var(--brass); font-size:40px; margin-bottom:12px;">📄</div><div style="color:var(--bone);">Cannot preview this file type</div><div style="color:var(--steel); font-size:12px; margin-top:8px;">${escapeHtml(fileName)}</div></div>`;
    }
  }catch(err){
    console.error('Preview failed:', err);
    content.innerHTML = `<div style="text-align:center; padding:40px; color:var(--alert);"><div style="margin-bottom:10px;">Could not load preview</div><div style="font-size:12px; color:var(--steel);">${escapeHtml(err.message)}</div></div>`;
  }
}

async function renderPdfPreview(blob, container){
  container.innerHTML = '<div id="pdf-viewer" style="height:100%; display:flex; flex-direction:column;"></div>';
  const viewer = document.getElementById('pdf-viewer');
  const arrayBuf = await blob.arrayBuffer();
  const pdf = await window.pdfjsLib.getDocument({data: arrayBuf}).promise;
  viewer.innerHTML = `<div style="padding:12px; border-bottom:1px solid var(--hairline); display:flex; justify-content:space-between; align-items:center;"><div style="font-size:12px; color:var(--steel);">Page <span id="pdf-page">1</span> of ${pdf.numPages}</div><div style="display:flex; gap:6px;"><button class="btn" id="pdf-prev" style="padding:6px 10px; font-size:11px;">← Prev</button><button class="btn" id="pdf-next" style="padding:6px 10px; font-size:11px;">Next →</button></div></div><div id="pdf-canvas-container" style="flex:1; overflow-y:auto; display:flex; align-items:center; justify-content:center;"></div>`;
  let currentPage = 1;
  const renderPage = async (pageNum)=>{
    const page = await pdf.getPage(pageNum);
    const scale = 1.5;
    const viewport = page.getViewport({scale});
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = viewport.width;
    canvas.height = viewport.height;
    await page.render({canvasContext:ctx, viewport}).promise;
    const container = document.getElementById('pdf-canvas-container');
    container.innerHTML = '';
    canvas.style.maxWidth = '100%';
    canvas.style.boxShadow = 'var(--shadow)';
    container.appendChild(canvas);
    document.getElementById('pdf-page').textContent = pageNum;
  };
  renderPage(1);
  document.getElementById('pdf-prev').onclick = ()=>{ if(currentPage>1) renderPage(--currentPage); };
  document.getElementById('pdf-next').onclick = ()=>{ if(currentPage<pdf.numPages) renderPage(++currentPage); };
}

function renderImagePreview(blob, container){
  const url = URL.createObjectURL(blob);
  container.innerHTML = `<div style="padding:20px; text-align:center;"><img src="${url}" style="max-width:100%; max-height:100%; border-radius:12px; box-shadow:var(--shadow);"></div>`;
  setTimeout(()=>URL.revokeObjectURL(url), 300000);
}

/* ---------------- download an attachment (decrypt + save-as) ---------------- */
document.getElementById('existingAttachment').addEventListener('click', async (e)=>{
  const btn = e.target.closest('[data-action="download-attachment"]');
  if(!btn) return;
  const d = State.documents.find(x=>x.id===btn.dataset.id);
  if(!d || !d.attachment) return;
  const original = btn.textContent;
  btn.disabled = true; btn.textContent = 'Decrypting…';
  try{
    let blob;
    if(d.attachment.storage === 'drive'){
      const cipherBuf = await Drive.download(d.attachment.driveFileId);
      const plainBuf = await Crypto.decryptBytes(State.masterKey, d.attachment.iv, cipherBuf);
      blob = new Blob([plainBuf], {type: d.attachment.type || 'application/octet-stream'});
    } else {
      // legacy inline base64 data URL
      const res = await fetch(d.attachment.data);
      blob = await res.blob();
    }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = d.attachment.name || 'attachment';
    a.click();
    setTimeout(()=>URL.revokeObjectURL(a.href), 4000);
  }catch(err){
    console.error('Attachment download failed:', err);
    toast('Could not download attachment: ' + err.message);
  }finally{
    btn.disabled = false; btn.textContent = original;
  }
});

function fileToBase64(file){
  return new Promise((res,rej)=>{
    const r = new FileReader();
    r.onload=()=>res({name:file.name, type:file.type, data:r.result});
    r.onerror=()=>rej(new Error(`Could not read "${file.name}"`));
    r.readAsDataURL(file);
  });
}

/* ---------------- category modal ---------------- */
document.getElementById('saveCatBtn').onclick = async ()=>{
  const name = document.getElementById('f_catname').value.trim();
  if(!name) return;
  if(!State.categories.includes(name)) State.categories.push(name);
  await LocalDB.setConfig('categories', State.categories);
  document.getElementById('f_catname').value='';
  closeModals();
  render();
  toast('Category created');
};

/* ---------------- re-auth to reveal ---------------- */
let authPin='';
let authPinTarget = 6;
let authTargetId = null;
async function requestReveal(id){
  authPin='';
  authTargetId = id;
  authPinTarget = (await LocalDB.getConfig('pinLength')) || 6;
  renderPinDots(document.getElementById('authPinDots'), authPinTarget, 0);
  buildKeypad(document.getElementById('authKeypad'), onAuthDigit, onAuthBack);
  document.getElementById('authError').textContent='';
  document.getElementById('authModal').classList.add('active');
}
function onAuthDigit(d){
  if(authPin.length>=authPinTarget) return;
  authPin+=d;
  renderPinDots(document.getElementById('authPinDots'), authPinTarget, authPin.length);
  if(authPin.length===authPinTarget) tryAuth(authTargetId);
}
function onAuthBack(){
  authPin = authPin.slice(0,-1);
  renderPinDots(document.getElementById('authPinDots'), authPinTarget, authPin.length);
}
async function tryAuth(id){
  const salt = await LocalDB.getConfig('salt');
  const verifier = await LocalDB.getConfig('verifier');
  const {key} = await Crypto.deriveKey(authPin, salt);
  const check = await Crypto.verifierFor(key);
  if(check===verifier){
    document.getElementById('authModal').classList.remove('active');
    const d = State.documents.find(x=>x.id===id);
    const el = document.querySelector(`.wc-number[data-id="${id}"]`);
    if(el && d){ el.textContent = d.number || '—'; el.dataset.masked='false';
      setTimeout(()=>{ el.textContent = maskNumber(d.number); el.dataset.masked='true'; }, 8000);
    }
  } else {
    document.getElementById('authError').textContent='Incorrect PIN.';
    authPin='';
    renderPinDots(document.getElementById('authPinDots'), authPinTarget, 0);
  }
}

/* ---------------- backup / restore ---------------- */
async function exportBackup(){
  const items = await LocalDB.allItems();
  const salt = await LocalDB.getConfig('salt');
  const verifier = await LocalDB.getConfig('verifier');
  const pinLength = await LocalDB.getConfig('pinLength');
  const deviceId = await LocalDB.getConfig('deviceId');
  const categories = State.categories;
  const payload = {version:2, salt, verifier, pinLength, deviceId, categories, items, exportedAt:Date.now()};
  const blob = new Blob([JSON.stringify(payload)], {type:'application/octet-stream'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `vaullet-backup-${new Date().toISOString().slice(0,10)}.vkbak`;
  a.click();
  toast('Encrypted backup exported');
}
async function importBackup(e){
  const file = e.target.files[0];
  if(!file) return;
  const text = await file.text();
  try{
    const payload = JSON.parse(text);
    const existingSalt = await LocalDB.getConfig('salt');
    if(!existingSalt && payload.salt && payload.verifier){
      // Fresh device with no PIN set yet — restore the same PIN setup so the
      // original PIN unlocks this backup. (Never overwrites an already-set-up vault.)
      await LocalDB.setConfig('salt', payload.salt);
      await LocalDB.setConfig('verifier', payload.verifier);
      if(payload.pinLength) await LocalDB.setConfig('pinLength', payload.pinLength);
    }
    for(const it of payload.items) await LocalDB.putItem(it);
    if(payload.categories) await LocalDB.setConfig('categories', payload.categories);
    if(payload.deviceId){
      await LocalDB.setConfig('deviceId', payload.deviceId);
      toast('Backup imported, including this vault\'s Firestore device ID — reconnect Firestore to resume sync.');
    } else {
      toast('Backup imported. Unlock with the PIN used at export time to view items.');
    }
    await loadVaultData();
    render();
  }catch(err){ toast('Invalid backup file'); }
}

/* ---------------- modal close ---------------- */
function closeModals(){ document.querySelectorAll('.overlay').forEach(o=>o.classList.remove('active')); }
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=closeModals);
document.querySelectorAll('.overlay').forEach(o=>o.addEventListener('click', e=>{ if(e.target===o) closeModals(); }));

/* ---------------- shell events ---------------- */
document.getElementById('lockNow').onclick = lockVault;
document.getElementById('themeToggle').onclick = ()=>setTheme(State.theme==='dark'?'light':'dark');

/* ---------------- auto-lock on inactivity ---------------- */
let inactivityTimer;
function resetInactivity(){
  clearTimeout(inactivityTimer);
  if(document.getElementById('app').classList.contains('active')){
    inactivityTimer = setTimeout(()=>{ lockVault(); toast('Locked after inactivity'); }, 120000);
  }
}
['click','keydown','mousemove','touchstart'].forEach(ev=>document.addEventListener(ev, resetInactivity));

/* ---------------- boot ---------------- */
(async function boot(){
  await LocalDB.open();
  await initLock();
  resetInactivity();
})();
