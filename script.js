/* VAULLET — Google Account + PIN Authentication
   Complete rewrite with Firebase Auth integration
*/

const DEFAULT_CATEGORIES = ["Identity","Banking","Cards","Insurance","Vehicle","Education","Employment","Medical","Tax","Personal"];
const ICONS = {Identity:"🪪",Banking:"🏦",Cards:"💳",Insurance:"🛡️",Vehicle:"🚗",Education:"🎓",Employment:"💼",Medical:"⚕️",Tax:"📄",Personal:"🗂️"};

const State = {
  unlocked:false,
  pinBuffer:"",
  masterKey:null,
  googleUser:null,
  categories:[...DEFAULT_CATEGORIES],
  documents:[],
  favorites:new Set(),
  activeTab:"home",
  activeCategory:"All",
  theme:"dark",
  reauthTarget:null,
};

function toast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg; t.classList.add('show');
  clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('show'),2400);
}

/* ===== CRYPTO MODULE ===== */
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
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, arrayBuffer);
    return {iv:this.bufToB64(iv), ciphertext: ct};
  },
  async decryptBytes(key, ivB64, ciphertextArrayBuffer){
    const iv = this.b64ToBuf(ivB64);
    return await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ciphertextArrayBuffer);
  },
  bufToB64(buf){
    const bytes = new Uint8Array(buf);
    let binary = '';
    const chunkSize = 0x8000;
    for(let i=0; i<bytes.length; i+=chunkSize){
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i+chunkSize));
    }
    return btoa(binary);
  },
  b64ToBuf(b64){ return Uint8Array.from(atob(b64), c=>c.charCodeAt(0)); },
};

/* ===== LOCALDB ===== */
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

/* ===== CLOUD (Firebase Auth + Firestore) ===== */
const Cloud = {
  app:null, db:null, auth:null, configured:false,
  async init(cfg){
    try{
      if(!window.firebase) throw new Error("Firebase SDK not loaded");
      this.app = firebase.apps.length ? firebase.apps[0] : firebase.initializeApp(cfg);
      this.auth = firebase.auth();
      this.db = firebase.firestore();
      this.auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL);
      this.configured = true;
      return true;
    }catch(e){ console.warn("Cloud sync unavailable:", e.message); this.configured=false; return false; }
  },
  signInWithGoogle(){
    if(!this.auth) throw new Error("Firebase Auth not initialized");
    const provider = new firebase.auth.GoogleAuthProvider();
    provider.addScope('https://www.googleapis.com/auth/drive.file');
    provider.addScope('profile');
    provider.addScope('email');
    return this.auth.signInWithPopup(provider);
  },
  signOut(){
    return this.auth.signOut();
  },
  getCurrentUser(){
    return this.auth.currentUser;
  },
  onAuthStateChanged(callback){
    return this.auth.onAuthStateChanged(callback);
  },
  col(){ 
    if(!this.auth.currentUser) throw new Error('Not signed in');
    return this.db.collection("vaults").doc(this.auth.currentUser.uid).collection("items"); 
  },
  async push(encryptedItem){
    if(!this.configured || !this.auth.currentUser) return {ok:false};
    const approxBytes = new Blob([JSON.stringify(encryptedItem)]).size;
    if(approxBytes > 900 * 1024){
      console.warn(`Skipping Firestore sync for "${encryptedItem.id}": ${(approxBytes/1024/1024).toFixed(2)}MB exceeds Firestore's 1MB document limit.`);
      return {ok:false, reason:'too-large', sizeMB:(approxBytes/1024/1024).toFixed(1)};
    }
    try{ await this.col().doc(encryptedItem.id).set(encryptedItem); return {ok:true}; }
    catch(e){ console.warn("sync push failed", e.message); return {ok:false, reason:'error', message:e.message}; }
  },
  async pull(){
    if(!this.configured || !this.auth.currentUser) return [];
    try{ const snap = await this.col().get(); return snap.docs.map(d=>d.data()); }
    catch(e){ console.warn("sync pull failed", e.message); return []; }
  },
  async remove(id){
    if(!this.configured || !this.auth.currentUser) return false;
    try{ await this.col().doc(id).delete(); return true; } catch(e){ return false; }
  }
};

/* ===== GOOGLE DRIVE ===== */
const Drive = {
  tokenClient:null, accessToken:null, tokenExpiry:0, configured:false, vaultFolderId:null,
  _resolve:null, _reject:null,

  async ensureReady(){
    if(this.configured) return true;
    const cfg = window.VAULLET_GOOGLE_CONFIG;
    if(!cfg || !cfg.clientId) return false;
    for(let i=0;i<25;i++){
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
    if(!ready) throw new Error('Google Drive is not configured');
    return new Promise((resolve,reject)=>{
      this._resolve = resolve; this._reject = reject;
      this.tokenClient.requestAccessToken({prompt: interactive ? 'consent' : ''});
    });
  },
  async findOrCreateFolder(parentId, folderName){
    const token = await this.ensureToken();
    const q = `name='${folderName.replace(/'/g,"\\'")}' and mimeType='application/vnd.google-apps.folder' and '${parentId}' in parents and trashed=false`;
    const res = await fetch(`https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(q)}&fields=files(id)&pageSize=1`, {
      headers:{Authorization:'Bearer '+token}
    });
    if(!res.ok) throw new Error(`Drive query failed (HTTP ${res.status})`);
    const data = await res.json();
    if(data.files && data.files.length > 0) return data.files[0].id;
    
    // Create folder
    const createRes = await fetch('https://www.googleapis.com/drive/v3/files?fields=id', {
      method:'POST',
      headers:{Authorization:'Bearer '+token, 'Content-Type':'application/json'},
      body:JSON.stringify({name:folderName, mimeType:'application/vnd.google-apps.folder', parents:[parentId]})
    });
    if(!createRes.ok) throw new Error(`Drive folder creation failed (HTTP ${createRes.status})`);
    const newFolder = await createRes.json();
    return newFolder.id;
  },
  async ensureVaultFolder(){
    if(this.vaultFolderId) return this.vaultFolderId;
    try{
      const token = await this.ensureToken();
      // Find or create "documents" folder in root
      const documentsId = await this.findOrCreateFolder('root', 'documents');
      // Find or create "AI Vault" folder inside "documents"
      const vaultId = await this.findOrCreateFolder(documentsId, 'AI Vault');
      this.vaultFolderId = vaultId;
      return vaultId;
    }catch(e){
      console.error('Could not ensure vault folder:', e);
      throw new Error('Failed to set up Drive folder structure: ' + e.message);
    }
  },
  async upload(encryptedArrayBuffer, filename){
    const token = await this.ensureToken();
    const parentFolderId = await this.ensureVaultFolder();
    const metadata = {name: `vaullet_${filename}.enc`, mimeType: 'application/octet-stream', parents:[parentFolderId]};
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
    }catch(e){ console.warn('Drive delete failed:', e.message); }
  }
};

/* ===== AUTH SCREEN ===== */
function drawDial(){
  const ticks=document.getElementById('ticks');
  if(!ticks) return;
  ticks.innerHTML='';
  for(let i=0;i<24;i++){
    const a = (i/24)*2*Math.PI;
    const x1=60+44*Math.sin(a), y1=60-44*Math.cos(a), x2=60+50*Math.sin(a), y2=60-50*Math.cos(a);
    ticks.innerHTML += `<line class="dial-tick" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`;
  }
}
function spinNeedle(){
  const n=document.getElementById('needle');
  if(!n) return;
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

let pinTarget = 6;
let pinMode = null; // 'setup' | 'unlock'

async function initAuthScreen(){
  drawDial();
  const storedSalt = await LocalDB.getConfig('salt');
  pinMode = storedSalt ? 'unlock' : 'setup';
  
  document.getElementById('lockTitle').textContent = pinMode==='setup' ? 'Set your vault PIN' : 'Enter your PIN';
  document.getElementById('lockSub').textContent = pinMode==='setup'
    ? `Welcome, ${State.googleUser.displayName}! Choose a 6-digit PIN to encrypt your vault.`
    : 'Enter your PIN to unlock your vault.';
  
  renderPinDots(document.getElementById('pinDots'), pinTarget, 0);
  buildKeypad(document.getElementById('keypad'), onPinDigit, onPinBack);
  document.getElementById('lockError').textContent='';
}

async function onPinDigit(d){
  if(State.pinBuffer.length>=6) return;
  State.pinBuffer+=d;
  renderPinDots(document.getElementById('pinDots'), pinTarget, State.pinBuffer.length);
  if(State.pinBuffer.length===6){
    if(pinMode==='setup') await finishSetup();
    else await tryUnlock();
  }
}

function onPinBack(){
  State.pinBuffer = State.pinBuffer.slice(0,-1);
  renderPinDots(document.getElementById('pinDots'), pinTarget, State.pinBuffer.length);
}

async function finishSetup(){
  const pin = State.pinBuffer;
  spinNeedle();
  const {key, salt} = await Crypto.deriveKey(pin);
  const verifier = await Crypto.verifierFor(key);
  await LocalDB.setConfig('salt', salt);
  await LocalDB.setConfig('verifier', verifier);
  State.masterKey = key;
  State.pinBuffer='';
  toast('PIN set. Vault created.');
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
  }
}

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
  State.masterKey=null;
  State.documents=[];
  State.pinBuffer='';
  document.getElementById('app').classList.remove('active');
  document.getElementById('lock').style.display='flex';
  initAuthScreen();
}

/* ===== DATA LOAD/SAVE ===== */
async function loadVaultData(){
  const cats = await LocalDB.getConfig('categories');
  State.categories = cats && cats.length ? cats : [...DEFAULT_CATEGORIES];

  let localItems = await LocalDB.allItems();

  const fbCfg = window.VAULLET_FIREBASE_CONFIG;
  if(fbCfg && fbCfg.apiKey){
    try{
      const ok = await Cloud.init(fbCfg);
      if(ok && Cloud.auth.currentUser){
        toast('Syncing with Firestore…');
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
      console.error('Firestore sync failed:', e);
      toast('Firestore sync failed — showing local documents only.');
    }
  }

  State.documents = [];
  for(const enc of localItems){
    try{
      const json = await Crypto.decryptStr(State.masterKey, {iv:enc.iv, ct:enc.ct});
      const data = JSON.parse(json);
      State.documents.push({...data, id:enc.id, favorite:!!enc.favorite, updatedAt:enc.updatedAt, deviceName:enc.deviceName});
    }catch(e){ console.warn('Could not decrypt item', enc.id); }
  }
}

async function saveDocument(doc){
  const id = doc.id || ('doc_'+Date.now()+'_'+Math.random().toString(36).slice(2,8));
  const payload = {...doc}; delete payload.id; delete payload.favorite; delete payload.updatedAt; delete payload.deviceName;
  const {iv, ct} = await Crypto.encryptStr(State.masterKey, JSON.stringify(payload));
  const deviceName = await LocalDB.getConfig('deviceName') || 'My Device';
  const encItem = {id, iv, ct, category:doc.category, type:doc.type, favorite:doc.favorite||false, updatedAt:Date.now(), deviceName};
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
    toast('Could not update favorite');
  }
}

/* ===== FILE MANAGEMENT ===== */
let fileMenuTargetId = null;
let fileMoveMode = null; // 'move' or 'copy'

function openFileMenu(id){
  fileMenuTargetId = id;
  const modal = document.getElementById('fileMenuModal');
  modal.classList.add('active');
}

async function openRenameModal(){
  const d = State.documents.find(x=>x.id===fileMenuTargetId);
  if(!d) return;
  document.getElementById('f_newname').value = d.name;
  document.getElementById('renameModal').classList.add('active');
  closeModals();
}

async function renameFile(){
  const newName = document.getElementById('f_newname').value.trim();
  if(!newName) { toast('Name cannot be empty'); return; }
  
  try{
    const d = State.documents.find(x=>x.id===fileMenuTargetId);
    if(!d) return;
    
    d.name = newName;
    await saveDocument(d);
    closeModals();
    toast('File renamed');
  }catch(e){
    console.error('Rename failed:', e);
    toast('Could not rename file');
  }
}

async function openMoveModal(mode){
  fileMoveMode = mode; // 'move' or 'copy'
  const catSel = document.getElementById('f_targetCategory');
  catSel.innerHTML = State.categories.map(c=>`<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
  
  const d = State.documents.find(x=>x.id===fileMenuTargetId);
  if(d) catSel.value = d.category;
  
  document.getElementById('moveModalTitle').textContent = mode==='move' ? 'Move to category' : 'Copy to category';
  document.getElementById('confirmMoveBtn').textContent = mode==='move' ? 'Move' : 'Copy';
  document.getElementById('moveModal').classList.add('active');
  closeModals();
}

async function moveOrCopyFile(){
  const targetCategory = document.getElementById('f_targetCategory').value;
  const d = State.documents.find(x=>x.id===fileMenuTargetId);
  if(!d) return;
  
  try{
    if(fileMoveMode==='move'){
      d.category = targetCategory;
      await saveDocument(d);
      toast('File moved to ' + targetCategory);
    } else if(fileMoveMode==='copy'){
      const newDoc = {...d};
      delete newDoc.id;
      newDoc.category = targetCategory;
      newDoc.name = newDoc.name + ' (copy)';
      await saveDocument(newDoc);
      toast('File copied to ' + targetCategory);
    }
    closeModals();
  }catch(e){
    console.error('Move/Copy failed:', e);
    toast('Could not move/copy file');
  }
}

async function openDeleteModal(){
  const d = State.documents.find(x=>x.id===fileMenuTargetId);
  if(!d) return;
  
  document.getElementById('deleteFileName').textContent = escapeHtml(d.name);
  document.getElementById('deleteModal').classList.add('active');
  closeModals();
}

async function deleteFileConfirmed(){
  try{
    await deleteDocument(fileMenuTargetId);
    closeModals();
    toast('File deleted');
  }catch(e){
    console.error('Delete failed:', e);
    toast('Could not delete file');
  }
}

/* ===== FILE PREVIEW ===== */
async function previewAttachment(id){
  const d = State.documents.find(x=>x.id===id);
  if(!d || !d.attachment) return;
  
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
    } else if(d.attachment.data){
      const res = await fetch(d.attachment.data);
      blob = await res.blob();
    } else {
      throw new Error('No attachment data found');
    }
    
    if(/\.pdf$/i.test(fileName) && window.pdfjsLib){
      await renderPdfPreview(blob, body);
    } else if(/\.(jpg|jpeg|png|gif|webp)$/i.test(fileName)){
      renderImagePreview(blob, body);
    } else {
      content.innerHTML = `<div style="text-align:center; padding:40px;">
        <div style="color:var(--brass); font-size:40px; margin-bottom:12px;">📄</div>
        <div style="color:var(--bone);">Cannot preview this file type</div>
        <div style="color:var(--steel); font-size:12px; margin-top:8px;">${escapeHtml(fileName)}</div>
      </div>`;
    }
  }catch(err){
    console.error('Preview failed:', err);
    content.innerHTML = `<div style="text-align:center; padding:40px; color:var(--alert);">
      <div style="margin-bottom:10px;">Could not load preview</div>
      <div style="font-size:12px; color:var(--steel);">${escapeHtml(err.message)}</div>
    </div>`;
  }
}

async function renderPdfPreview(blob, container){
  container.innerHTML = '<div id="pdf-viewer" style="height:100%; display:flex; flex-direction:column;"></div>';
  const viewer = document.getElementById('pdf-viewer');
  
  try{
    const arrayBuf = await blob.arrayBuffer();
    const pdf = await window.pdfjsLib.getDocument({data: arrayBuf}).promise;
    
    viewer.innerHTML = `
      <div style="padding:12px; border-bottom:1px solid var(--hairline); display:flex; justify-content:space-between; align-items:center;">
        <div style="font-size:12px; color:var(--steel);">Page <span id="pdf-page">1</span> of ${pdf.numPages}</div>
        <div style="display:flex; gap:6px;">
          <button class="btn" id="pdf-prev" style="padding:6px 10px; font-size:11px;">← Prev</button>
          <button class="btn" id="pdf-next" style="padding:6px 10px; font-size:11px;">Next →</button>
        </div>
      </div>
      <div id="pdf-canvas-container" style="flex:1; overflow-y:auto; display:flex; align-items:center; justify-content:center; background:var(--bg-secondary);"></div>
    `;
    
    let currentPage = 1;
    const renderPage = async (pageNum)=>{
      try{
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
      }catch(e){
        console.error('Page render error:', e);
      }
    };
    
    renderPage(1);
    document.getElementById('pdf-prev').onclick = ()=>{ if(currentPage>1) renderPage(--currentPage); };
    document.getElementById('pdf-next').onclick = ()=>{ if(currentPage<pdf.numPages) renderPage(++currentPage); };
  }catch(e){
    viewer.innerHTML = `<div style="text-align:center; padding:40px; color:var(--alert);">PDF Library not loaded. Make sure pdf.js is available.</div>`;
  }
}

function renderImagePreview(blob, container){
  const url = URL.createObjectURL(blob);
  container.innerHTML = `<div style="padding:20px; text-align:center;"><img src="${url}" style="max-width:100%; max-height:100%; border-radius:12px; box-shadow:var(--shadow); display:block; margin:0 auto;"></div>`;
  setTimeout(()=>URL.revokeObjectURL(url), 300000);
}

/* ===== NAVIGATION ===== */
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

/* ===== RENDER HELPERS ===== */
function fmtDate(d){ if(!d) return '—'; const dt=new Date(d); return dt.toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}); }
function daysUntil(d){ if(!d) return Infinity; return Math.ceil((new Date(d) - new Date())/86400000); }
function maskNumber(num){
  if(!num) return '—';
  const clean = num.replace(/\s/g,'');
  if(clean.length<=4) return '••••';
  return 'XXXX '.repeat(Math.max(0,Math.floor((clean.length-4)/4))).trim()+' '+clean.slice(-4);
}
function escapeHtml(s){ return (s||'').replace(/[&<>"']/g, m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

function docRowHtml(d){
  const expiring = d.expiry && daysUntil(d.expiry) <= 30 && daysUntil(d.expiry) >= 0;
  const expired = d.expiry && daysUntil(d.expiry) < 0;
  return `<div class="doc-row" data-id="${d.id}" data-action="open">
    <div class="doc-icon">${ICONS[d.category]||'📁'}</div>
    <div class="doc-meta">
      <div class="doc-name">${escapeHtml(d.name)}</div>
      <div class="doc-cat">${escapeHtml(d.category)} ${d.number? '· <span class="mono">'+maskNumber(d.number)+'</span>':''} ${d.deviceName?'· 📱 '+escapeHtml(d.deviceName):''}</div>
    </div>
    ${expired? '<span class="doc-badge badge-warn">Expired</span>' : expiring? `<span class="doc-badge badge-warn">${daysUntil(d.expiry)}d left</span>`:''}
    <button class="btn-ghost" data-action="fav" data-id="${d.id}" style="font-size:15px;">${d.favorite?'<span class="badge-fav">★</span>':'☆'}</button>
    <button class="btn-ghost" data-action="file-menu" data-id="${d.id}" style="font-size:18px; padding:6px 10px;" title="More options">⋯</button>
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
  ${docs.length? `<div>${docs.map(d=>`<div>${docRowHtml(d)}</div>`).join('')}</div>` : '<div class="empty">No documents in this category yet.</div>'}
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
  const user = Cloud.getCurrentUser();
  return `
  <div class="settings-card">
    <div class="settings-row">
      <div><div class="settings-label">Signed in as</div><div class="settings-sub">${escapeHtml(user?.displayName||'Unknown')}</div></div>
      <button class="btn btn-ghost" id="signOutBtn" style="color:var(--alert);">Sign out</button>
    </div>
  </div>

  <div class="settings-card">
    <div class="settings-row">
      <div><div class="settings-label">Dark mode</div><div class="settings-sub">Switch between light and dark themes</div></div>
      <label class="switch"><input type="checkbox" id="themeSwitch" ${State.theme==='dark'?'checked':''}><span class="slider"></span></label>
    </div>
    <div class="settings-row">
      <div><div class="settings-label">Auto-lock</div><div class="settings-sub">Lock vault after 2 minutes of inactivity</div></div>
      <label class="switch"><input type="checkbox" id="autolockSwitch" checked><span class="slider"></span></label>
    </div>
  </div>

  <div class="section-title">Device management</div>
  <div class="settings-card" style="padding:18px 22px;">
    <div class="field"><label>This device's name</label><input id="deviceNameInput" type="text"></div>
    <button class="btn btn-brass" id="saveDeviceNameBtn" style="margin-top:8px;">Save device name</button>
    <div class="help-text" style="margin-top:12px;">Identifies which device uploaded files when syncing across devices</div>
  </div>

  <div class="section-title">Backup</div>
  <div class="settings-card" style="padding:18px 22px;">
    <div class="help-text" style="margin-bottom:12px;">Export an encrypted backup file. Import it on any device after signing in with your Google account.</div>
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
  document.querySelectorAll('[data-action="file-menu"]').forEach(b=>b.onclick=(e)=>{ e.stopPropagation(); openFileMenu(b.dataset.id); });
  document.querySelectorAll('.doc-row[data-action="open"]').forEach(r=>r.onclick=(e)=>{ if(e.target.closest('[data-action="fav"]') || e.target.closest('[data-action="file-menu"]')) return; viewDocument(r.dataset.id); });

  const search = document.getElementById('searchInput');
  if(search) search.oninput = ()=>runSearch(search.value);

  const themeSwitch = document.getElementById('themeSwitch');
  if(themeSwitch) themeSwitch.onchange = ()=>setTheme(themeSwitch.checked?'dark':'light');

  const deviceNameInput = document.getElementById('deviceNameInput');
  const saveDeviceNameBtn = document.getElementById('saveDeviceNameBtn');
  if(deviceNameInput && saveDeviceNameBtn){
    LocalDB.getConfig('deviceName').then(name=>{ deviceNameInput.value = name || ''; });
    saveDeviceNameBtn.onclick = async ()=>{
      const newName = deviceNameInput.value.trim();
      if(!newName){ toast('Device name cannot be empty'); return; }
      await LocalDB.setConfig('deviceName', newName);
      toast('Device name updated');
    };
  }

  const exportBtn = document.getElementById('exportBtn');
  if(exportBtn) exportBtn.onclick = exportBackup;
  const importBtn = document.getElementById('importBtn');
  if(importBtn) importBtn.onclick = ()=>document.getElementById('importFile').click();
  const importFile = document.getElementById('importFile');
  if(importFile) importFile.onchange = importBackup;

  const signOutBtn = document.getElementById('signOutBtn');
  if(signOutBtn) signOutBtn.onclick = async ()=>{
    if(confirm('Sign out of your Google account? You can sign in again on this device anytime.')){
      await Cloud.signOut();
      location.reload();
    }
  };

  const wipeBtn = document.getElementById('wipeBtn');
  if(wipeBtn) wipeBtn.onclick = async ()=>{
    if(confirm('This permanently deletes all locally stored vault data on this device. Continue?')){
      indexedDB.deleteDatabase('vaullet');
      toast('Vault erased. Reloading…');
      setTimeout(()=>location.reload(), 900);
    }
  };

  // Preview and download button handlers (use event delegation for dynamic content)
  document.addEventListener('click', async (e)=>{
    const previewBtn = e.target.closest('[data-action="preview-attachment"]');
    if(previewBtn){
      e.preventDefault();
      const id = previewBtn.dataset.id;
      await previewAttachment(id);
    }

    const downloadBtn = e.target.closest('[data-action="download-attachment"]');
    if(downloadBtn){
      e.preventDefault();
      const id = downloadBtn.dataset.id;
      const d = State.documents.find(x=>x.id===id);
      if(d && d.attachment){
        downloadBtn.disabled = true;
        downloadBtn.textContent = 'Decrypting…';
        try{
          let blob;
          if(d.attachment.storage === 'drive'){
            const cipherBuf = await Drive.download(d.attachment.driveFileId);
            const plainBuf = await Crypto.decryptBytes(State.masterKey, d.attachment.iv, cipherBuf);
            blob = new Blob([plainBuf], {type:d.attachment.type || 'application/octet-stream'});
          } else if(d.attachment.data){
            const res = await fetch(d.attachment.data);
            blob = await res.blob();
          }
          if(blob){
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = d.attachment.name || 'attachment';
            a.click();
            setTimeout(()=>URL.revokeObjectURL(a.href), 100);
            toast('Downloaded: ' + (d.attachment.name || 'attachment'));
          }
        }catch(err){
          console.error('Download failed:', err);
          toast('Download failed: ' + err.message);
        }finally{
          downloadBtn.disabled = false;
          downloadBtn.textContent = '⬇ Download';
        }
      }
    }
  });
}

function setTheme(t){
  State.theme=t;
  document.documentElement.setAttribute('data-theme', t);
}

/* ===== DOCUMENT MODAL ===== */
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
  const catSel = document.getElementById('f_category');
  catSel.innerHTML = State.categories.map(c=>`<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
  catSel.value = d.category;
  document.getElementById('docModal').classList.add('active');
}

document.getElementById('saveDocBtn').onclick = async ()=>{
  const btn = document.getElementById('saveDocBtn');
  const originalLabel = btn.textContent;
  btn.disabled = true; btn.textContent = 'Saving…';
  try{
    if(!State.masterKey) throw new Error('Vault key missing — please reload and unlock again.');
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
    toast('Could not save: ' + (e.message || 'unknown error'));
  }finally{
    btn.disabled = false; btn.textContent = originalLabel;
  }
};

function fileToBase64(file){
  return new Promise((res,rej)=>{
    const r = new FileReader();
    r.onload=()=>res({name:file.name, type:file.type, data:r.result});
    r.onerror=()=>rej(new Error(`Could not read "${file.name}"`));
    r.readAsDataURL(file);
  });
}

/* ===== CATEGORY MODAL ===== */
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

/* ===== REVEAL ===== */
let authPin='';
let authPinTarget = 6;
let authTargetId = null;
async function requestReveal(id){
  authPin='';
  authTargetId = id;
  authPinTarget = 6;
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

/* ===== BACKUP ===== */
async function exportBackup(){
  const items = await LocalDB.allItems();
  const salt = await LocalDB.getConfig('salt');
  const verifier = await LocalDB.getConfig('verifier');
  const categories = State.categories;
  const payload = {version:2, salt, verifier, categories, items, exportedAt:Date.now()};
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
      await LocalDB.setConfig('salt', payload.salt);
      await LocalDB.setConfig('verifier', payload.verifier);
    }
    for(const it of payload.items) await LocalDB.putItem(it);
    if(payload.categories) await LocalDB.setConfig('categories', payload.categories);
    toast('Backup imported. Your files should now appear in the vault.');
    await loadVaultData();
    render();
  }catch(err){ toast('Invalid backup file'); }
}

function closeModals(){ document.querySelectorAll('.overlay').forEach(o=>o.classList.remove('active')); }
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=closeModals);
document.querySelectorAll('.overlay').forEach(o=>o.addEventListener('click', e=>{ if(e.target===o) closeModals(); }));

/* ===== FILE MANAGEMENT MODAL HANDLERS ===== */
const fileMenuModal = document.getElementById('fileMenuModal');
if(fileMenuModal){
  fileMenuModal.querySelectorAll('[data-action="file-rename"]').forEach(b=>b.onclick=openRenameModal);
  fileMenuModal.querySelectorAll('[data-action="file-move"]').forEach(b=>b.onclick=()=>openMoveModal('move'));
  fileMenuModal.querySelectorAll('[data-action="file-copy"]').forEach(b=>b.onclick=()=>openMoveModal('copy'));
  fileMenuModal.querySelectorAll('[data-action="file-delete"]').forEach(b=>b.onclick=openDeleteModal);
}

const confirmRenameBtn = document.getElementById('confirmRenameBtn');
if(confirmRenameBtn) confirmRenameBtn.onclick = renameFile;

const confirmMoveBtn = document.getElementById('confirmMoveBtn');
if(confirmMoveBtn) confirmMoveBtn.onclick = moveOrCopyFile;

const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
if(confirmDeleteBtn) confirmDeleteBtn.onclick = deleteFileConfirmed;

/* ===== KEYBOARD ===== */
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
  }
});

/* ===== SHELL ===== */
document.getElementById('lockNow').onclick = lockVault;
document.getElementById('themeToggle').onclick = ()=>setTheme(State.theme==='dark'?'light':'dark');

/* ===== AUTO-LOCK ===== */
let inactivityTimer;
function resetInactivity(){
  clearTimeout(inactivityTimer);
  if(document.getElementById('app').classList.contains('active')){
    inactivityTimer = setTimeout(()=>{ lockVault(); toast('Locked after inactivity'); }, 120000);
  }
}
['click','keydown','mousemove','touchstart'].forEach(ev=>document.addEventListener(ev, resetInactivity));

/* ===== BOOT ===== */
(async function boot(){
  try{
    await LocalDB.open();
  }catch(e){
    console.error('LocalDB initialization failed:', e);
  }
  
  const fbCfg = window.VAULLET_FIREBASE_CONFIG;
  if(!fbCfg || !fbCfg.apiKey){
    console.error('Firebase config not found:', fbCfg);
    document.getElementById('lock').innerHTML = `<div style="text-align:center; padding:40px;">
      <div class="modal-title display" style="color:var(--alert); margin-bottom:20px;">⚠️ Configuration Error</div>
      <div class="help-text">Firebase credentials not found.<br><br>Make sure <strong>firebase_config.js</strong> is loaded.<br><br>Check browser console for details.</div>
    </div>`;
    return;
  }

  try{
    const cloudReady = await Cloud.init(fbCfg);
    if(!cloudReady){
      throw new Error('Cloud module initialization failed');
    }
  }catch(e){
    console.error('Firebase Auth initialization failed:', e);
    document.getElementById('lock').innerHTML = `<div style="text-align:center; padding:40px;">
      <div class="modal-title display" style="color:var(--alert); margin-bottom:20px;">⚠️ Setup Error</div>
      <div class="help-text">Firebase error:<br><strong>${escapeHtml(e.message)}</strong><br><br>Check console for details.</div>
    </div>`;
    return;
  }
  
  console.log('🔍 [BOOT] Firebase Auth initialized, setting up auth listener');
  
  // Set up auth state listener - this will trigger on initial load and whenever auth changes
  Cloud.onAuthStateChanged(async (user)=>{
    console.log('🔍 [AUTH STATE CHANGED]', user ? `User: ${user.email} (${user.uid})` : 'No user (signed out)');
    if(user){
      State.googleUser = user;
      console.log('✅ [LOGIN SUCCESS] User authenticated:', user.email);
      document.getElementById('lock').style.display='flex';
      document.getElementById('app').classList.remove('active');
      await initAuthScreen();
      resetInactivity();
    } else {
      console.log('⚠️ [NO USER] Showing sign-in screen');
      // Not signed in - show login screen
      document.getElementById('lock').innerHTML = `<div style="text-align:center;">
        <div class="modal-title display" style="margin-bottom:20px; font-size:24px;">Vaullet</div>
        <div class="help-text" style="margin-bottom:30px;">Secure personal vault<br>Google Account + Encrypted PIN</div>
        <button class="btn btn-brass" id="googleSignInBtn" style="font-size:15px; padding:12px 20px; display:flex; align-items:center; gap:10px; margin:0 auto;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
          </svg>
          Sign in
        </button>
      </div>`;
      const btn = document.getElementById('googleSignInBtn');
      if(btn){
        btn.disabled = false;
        btn.onclick = async ()=>{
          try{
            btn.disabled = true;
            btn.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
              <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
              <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
              <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
            </svg> Signing in…`;
            console.log('🔍 [BUTTON CLICK] Starting sign-in popup...');
            const result = await Cloud.signInWithGoogle();
            console.log('✅ [POPUP SUCCESS] User signed in from popup:', result.user.email);
            // Auth state listener will handle the UI update
          }catch(e){
            console.error('❌ [ERROR] Google sign-in failed:', e.message);
            console.error('Full error:', e);
            toast('Sign-in error: ' + e.message);
            btn.disabled = false;
            btn.innerHTML = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
              <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
              <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
              <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
            </svg> Sign in`;
          }
        };
      }
    }
  });
  
  console.log('🔍 [BOOT] Boot sequence complete, auth listener active');
})();
