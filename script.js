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
  loginWithEmail(email, password){
    const fullEmail = email.includes('@') ? email : email + '@vaullet.in';
    if(!fullEmail.endsWith('@vaullet.in')) throw new Error('Email must be @vaullet.in');
    return this.auth.signInWithEmailAndPassword(fullEmail, password);
  },
  registerWithEmail(email, password){
    const fullEmail = email.includes('@') ? email : email + '@vaullet.in';
    if(!fullEmail.endsWith('@vaullet.in')) throw new Error('Email must be @vaullet.in');
    if(password.length < 8) throw new Error('Password min 8 chars');
    return this.auth.createUserWithEmailAndPassword(fullEmail, password);
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
    return this.db.collection("users").doc(this.auth.currentUser.uid).collection("documents"); 
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
          scope: 'https://www.googleapis.com/auth/drive',  // Full Drive access (not just drive.file)
          callback: (resp)=>{
            if(resp && resp.access_token){
              this.accessToken = resp.access_token;
              localStorage.setItem('vaullet_google_access_token', resp.access_token);
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
    let token = localStorage.getItem('vaullet_google_access_token');
    console.log(`🔍 [DRIVE] Looking for folder "${folderName}" in parent ${parentId}`);
    
    const q = `name='${folderName.replace(/'/g,"\\'")}' and mimeType='application/vnd.google-apps.folder' and '${parentId}' in parents and trashed=false`;
    let res = await fetch(`https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(q)}&fields=files(id)&pageSize=1`, {
      headers:{Authorization:'Bearer '+token}
    });
    
    // If 401 or 403, try refreshing token
    if(res.status === 401 || res.status === 403){
      console.warn('⚠️ [DRIVE] Got HTTP ' + res.status + ', token invalid, refreshing...');
      try{
        const freshToken = await this.ensureToken(true);
        if(freshToken){
          localStorage.setItem('vaullet_google_access_token', freshToken);
          token = freshToken;
          console.log('✅ [DRIVE] Got fresh token, retrying...');
          res = await fetch(`https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(q)}&fields=files(id)&pageSize=1`, {
            headers:{Authorization:'Bearer '+token}
          });
        }
      }catch(e){
        console.warn('⚠️ [DRIVE] Token refresh failed:', e.message);
      }
    }
    
    if(!res.ok){
      console.error(`❌ [DRIVE] Query failed (HTTP ${res.status})`);
      throw new Error(`Drive query failed (HTTP ${res.status})`);
    }
    
    const data = await res.json();
    if(data.files && data.files.length > 0){
      console.log(`✅ [DRIVE] Found existing folder "${folderName}": ${data.files[0].id}`);
      return data.files[0].id;
    }
    
    console.log(`📝 [DRIVE] Creating new folder "${folderName}"...`);
    // Create folder
    const createRes = await fetch('https://www.googleapis.com/drive/v3/files?fields=id', {
      method:'POST',
      headers:{Authorization:'Bearer '+token, 'Content-Type':'application/json'},
      body:JSON.stringify({name:folderName, mimeType:'application/vnd.google-apps.folder', parents:[parentId]})
    });
    
    // If create also fails with 401/403, retry with fresh token
    if((createRes.status === 401 || createRes.status === 403) && token !== localStorage.getItem('vaullet_google_access_token')){
      console.warn('⚠️ [DRIVE] Create failed with HTTP ' + createRes.status + ', retrying with fresh token...');
      try{
        const freshToken = await this.ensureToken(true);
        if(freshToken){
          localStorage.setItem('vaullet_google_access_token', freshToken);
          const retryRes = await fetch('https://www.googleapis.com/drive/v3/files?fields=id', {
            method:'POST',
            headers:{Authorization:'Bearer '+freshToken, 'Content-Type':'application/json'},
            body:JSON.stringify({name:folderName, mimeType:'application/vnd.google-apps.folder', parents:[parentId]})
          });
          
          if(retryRes.ok){
            const newFolder = await retryRes.json();
            console.log(`✅ [DRIVE] Created folder "${folderName}": ${newFolder.id}`);
            return newFolder.id;
          }
        }
      }catch(e){
        console.warn('⚠️ [DRIVE] Retry failed:', e.message);
      }
    }
    
    if(!createRes.ok){
      console.error(`❌ [DRIVE] Folder creation failed (HTTP ${createRes.status})`);
      throw new Error(`Drive folder creation failed (HTTP ${createRes.status})`);
    }
    
    const newFolder = await createRes.json();
    console.log(`✅ [DRIVE] Created folder "${folderName}": ${newFolder.id}`);
    return newFolder.id;
  },
  async ensureVaultFolder(){
    if(this.vaultFolderId){
      console.log('✅ [DRIVE] Using cached vault folder ID:', this.vaultFolderId);
      return this.vaultFolderId;
    }
    try{
      console.log('🔍 [DRIVE] Looking up vault folder...');
      // Use cached token, or request one if missing
      let token = localStorage.getItem('vaullet_google_access_token');
      if(!token){
        console.warn('⚠️ [DRIVE] No access token, requesting...');
        token = await this.ensureToken(true);
        if(token){
          localStorage.setItem('vaullet_google_access_token', token);
        } else {
          throw new Error('Could not get access token');
        }
      }
      
      // Find or create "documents" folder in root
      console.log('🔍 [DRIVE] Creating/finding Documents folder...');
      const documentsId = await this.findOrCreateFolder('root', 'documents');
      console.log('✅ [DRIVE] Documents folder ID:', documentsId);
      
      // Find or create "AI Vault" folder inside "documents"
      console.log('🔍 [DRIVE] Creating/finding AI Vault folder...');
      const vaultId = await this.findOrCreateFolder(documentsId, 'AI Vault');
      console.log('✅ [DRIVE] AI Vault folder ID:', vaultId);
      
      this.vaultFolderId = vaultId;
      return vaultId;
    }catch(e){
      console.error('❌ [DRIVE] Could not ensure vault folder:', e);
      throw new Error('Failed to set up Drive folder structure: ' + e.message);
    }
  },
  async upload(encryptedArrayBuffer, filename){
    const token = localStorage.getItem('vaullet_google_access_token');
    console.log('✅ [DRIVE] Using stored Google access token for upload');
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
  async uploadRaw(fileArrayBuffer, filename){
    // Upload raw (unencrypted) file to Drive
    let token = localStorage.getItem('vaullet_google_access_token');
    
    if(!token){
      console.warn('⚠️ [DRIVE] No access token for upload, requesting...');
      token = await this.ensureToken(true);
      if(token){
        localStorage.setItem('vaullet_google_access_token', token);
      } else {
        throw new Error('Could not get access token for upload');
      }
    }
    
    console.log('✅ [DRIVE] Uploading raw file (unencrypted):', filename);
    
    const parentFolderId = await this.ensureVaultFolder();
    const metadata = {name: filename, mimeType: 'application/octet-stream', parents:[parentFolderId]};
    const form = new FormData();
    form.append('metadata', new Blob([JSON.stringify(metadata)], {type:'application/json'}));
    form.append('file', new Blob([fileArrayBuffer]));
    
    let res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', {
      method:'POST', headers:{Authorization:'Bearer '+token}, body:form
    });
    
    // If 403, try refreshing token
    if(res.status === 403 || res.status === 401){
      console.warn('⚠️ [DRIVE] Got ' + res.status + ' on upload, refreshing token...');
      try{
        const freshToken = await this.ensureToken(true);
        if(freshToken){
          localStorage.setItem('vaullet_google_access_token', freshToken);
          console.log('✅ [DRIVE] Got fresh token, retrying upload...');
          token = freshToken;
          
          const form2 = new FormData();
          form2.append('metadata', new Blob([JSON.stringify(metadata)], {type:'application/json'}));
          form2.append('file', new Blob([fileArrayBuffer]));
          res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', {
            method:'POST', headers:{Authorization:'Bearer '+token}, body:form2
          });
        }
      }catch(e){
        console.warn('⚠️ [DRIVE] Token refresh failed:', e.message);
      }
    }
    
    if(!res.ok) throw new Error(`Drive upload failed (HTTP ${res.status})`);
    const data = await res.json();
    console.log('✅ [DRIVE] Raw file uploaded:', filename, '- ID:', data.id);
    return data.id;
  },
  async getAccessToken(){
    // Try to use cached token first
    let token = localStorage.getItem('vaullet_google_access_token');
    if(token){
      console.log('✅ [DRIVE] Using cached access token');
      return token;
    }
    
    // No cached token - request fresh one
    try{
      console.log('🔄 [DRIVE] Requesting fresh access token...');
      const user = this.auth.currentUser;
      if(!user){
        console.warn('⚠️ [DRIVE] No user logged in');
        return null;
      }
      
      // Force refresh - this will ask user for permission if needed
      const result = await this.signInWithGoogle();
      if(result.credential && result.credential.accessToken){
        token = result.credential.accessToken;
        localStorage.setItem('vaullet_google_access_token', token);
        console.log('✅ [DRIVE] Got fresh access token');
        return token;
      }
    }catch(e){
      console.error('❌ [DRIVE] Could not get access token:', e);
    }
    return null;
  },
  async download(fileId){
    try{
      // Use stored Google access token for Drive API
      let token = localStorage.getItem('vaullet_google_access_token');
      
      if(!token){
        console.warn('⚠️ [DRIVE] No access token found, requesting...');
        token = await this.getAccessToken();
        if(!token) token = await this.ensureToken(true);
      } else {
        console.log('✅ [DRIVE] Using stored Google access token');
      }
      
      let res = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, 
        {headers:{Authorization:'Bearer '+token}}
      );
      
      // If token issue (401 expired or 403 forbidden), refresh and retry
      if(res.status === 401 || res.status === 403){
        console.log('🔄 [DRIVE] Token issue (HTTP ' + res.status + '), refreshing...');
        token = await this.ensureToken(true);
        if(token){
          localStorage.setItem('vaullet_google_access_token', token);
          res = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`, 
            {headers:{Authorization:'Bearer '+token}}
          );
        }
      }
      
      if(!res.ok) throw new Error(`Drive download failed (HTTP ${res.status})`);
      return await res.arrayBuffer();
    }catch(e){
      console.error('❌ [DRIVE] Download failed:', e.message);
      throw e;
    }
  },
  async listVaultFiles(){
    try{
      console.log('🔍 [DRIVE SYNC] Starting listVaultFiles...');
      const vaultFolderId = await this.ensureVaultFolder();
      console.log('✅ [DRIVE SYNC] Vault folder ID:', vaultFolderId);
      
      let token = localStorage.getItem('vaullet_google_access_token');
      console.log('🔐 [DRIVE SYNC] Access token available:', !!token);
      
      if(!token){
        console.warn('⚠️ [DRIVE] No access token, cannot sync');
        return [];
      }
      
      const q = `'${vaultFolderId}' in parents and trashed=false`;
      console.log('🔍 [DRIVE SYNC] Query:', q);
      
      let res = await fetch(`https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(q)}&fields=files(id,name,mimeType,createdTime,modifiedTime,size)&pageSize=1000`, {
        headers:{Authorization:'Bearer '+token}
      });
      
      console.log('📡 [DRIVE SYNC] Response status:', res.status);
      
      // If 403, try refreshing token
      if(res.status === 403){
        console.warn('⚠️ [DRIVE SYNC] Got 403, token might be limited, trying to refresh...');
        try{
          const freshToken = await this.ensureToken(true);
          if(freshToken){
            localStorage.setItem('vaullet_google_access_token', freshToken);
            console.log('✅ [DRIVE SYNC] Got fresh token, retrying...');
            token = freshToken;
            res = await fetch(`https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(q)}&fields=files(id,name,mimeType,createdTime,modifiedTime,size)&pageSize=1000`, {
              headers:{Authorization:'Bearer '+token}
            });
          }
        }catch(e){
          console.warn('⚠️ [DRIVE SYNC] Token refresh failed:', e.message);
        }
      }
      
      if(!res.ok){
        const errText = await res.text();
        console.error('❌ [DRIVE SYNC] Response error:', errText);
        throw new Error(`Drive list failed (HTTP ${res.status})`);
      }
      
      const data = await res.json();
      console.log('📋 [DRIVE SYNC] Files found:', data.files ? data.files.length : 0);
      console.log('📋 [DRIVE SYNC] All files:', data.files);
      
      // Accept all files (encrypted .enc, PDFs, images, etc.) - exclude folders
      const files = (data.files||[]).filter(f => f.mimeType !== 'application/vnd.google-apps.folder');
      console.log(`✅ [DRIVE SYNC] Filtered ${files.length} files (excluding folders)`);
      files.forEach(f => console.log(`   - ${f.name} (${f.mimeType})`));
      
      return files;
    }catch(e){
      console.error('❌ [DRIVE SYNC] Failed to list files:', e.message);
      console.error('❌ [DRIVE SYNC] Full error:', e);
      return [];
    }
  },
  async syncFromDrive(){
    try{
      console.log('🔄 [DRIVE SYNC] Starting sync from Google Drive...');
      const driveFiles = await this.listVaultFiles();
      
      if(driveFiles.length === 0){
        console.log('ℹ️ [DRIVE SYNC] No files to sync');
        return 0;
      }
      
      let synced = 0;
      for(const driveFile of driveFiles){
        // Check if file already exists in app
        const exists = State.documents.some(d => 
          d.attachment && d.attachment.driveFileId === driveFile.id
        );
        
        if(!exists){
          // Extract file name
          let fileName = driveFile.name;
          
          // For encrypted files, remove vaullet_ prefix and .enc extension
          if(fileName.startsWith('vaullet_') && fileName.endsWith('.enc')){
            fileName = fileName.replace(/^vaullet_/, '').replace(/\.enc$/, '');
          }
          
          // Determine file type from mime type
          let category = 'Personal';
          if(driveFile.mimeType.startsWith('image/')) category = 'Personal';
          else if(driveFile.mimeType === 'application/pdf') category = 'Personal';
          else if(driveFile.mimeType.includes('word') || driveFile.mimeType.includes('document')) category = 'Personal';
          
          // Add new document from Drive file
          const doc = {
            id: Math.random().toString(36).substr(2,9),
            name: fileName,
            type: 'document',
            category: category,
            attachment: {
              name: driveFile.name,
              driveFileId: driveFile.id,
              storage: 'drive',
              size: driveFile.size||0
            },
            createdAt: new Date(driveFile.createdTime).getTime(),
            updatedAt: new Date(driveFile.modifiedTime).getTime(),
            favorite: false,
            tags: ['synced-from-drive'],
            notes: 'Synced from Google Drive'
          };
          
          State.documents.push(doc);
          
          // Save to LocalDB (metadata only, file is on Drive)
          try{
            const payload = {...doc}; 
            delete payload.id; 
            delete payload.favorite; 
            delete payload.updatedAt;
            const {iv, ct} = await Crypto.encryptStr(State.masterKey, JSON.stringify(payload));
            const deviceName = await LocalDB.getConfig('deviceName') || 'My Device';
            const encItem = {id: doc.id, iv, ct, category: doc.category, type: doc.type, favorite: false, updatedAt: Date.now(), deviceName};
            await LocalDB.putItem(encItem);
            await Cloud.push(encItem);
            console.log(`✅ [DRIVE SYNC] Saved to LocalDB & Firestore: ${fileName}`);
          }catch(e){
            console.warn('⚠️ [DRIVE SYNC] Could not save metadata:', e.message);
          }
          
          synced++;
          console.log(`✅ [DRIVE SYNC] Added: ${fileName} (from Drive)`);
        }
      }
      
      console.log(`✅ [DRIVE SYNC] Sync complete: ${synced} new files`);
      return synced;
    }catch(e){
      console.error('❌ [DRIVE SYNC] Sync failed:', e.message);
      return 0;
    }
  },
  async remove(fileId){
    try{
      const token = localStorage.getItem('vaullet_google_access_token');
      if(!token){
        console.warn('⚠️ [DRIVE] No access token for delete');
        return false;
      }
      console.log('🗑️ [DRIVE] Deleting file from Drive:', fileId);
      const res = await fetch(`https://www.googleapis.com/drive/v3/files/${fileId}`, {
        method:'DELETE',
        headers:{Authorization:'Bearer '+token}
      });
      if(!res.ok){
        console.error(`❌ [DRIVE] Delete failed (HTTP ${res.status})`);
        return false;
      }
      console.log('✅ [DRIVE] File deleted from Drive:', fileId);
      return true;
    }catch(e){
      console.error('❌ [DRIVE] Delete error:', e.message);
      return false;
    }
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
  try{
    if(!el){
      console.error('❌ [KEYPAD] Keypad element not found');
      return;
    }
    
    console.log('🔨 [KEYPAD] Building keypad');
    el.innerHTML='';
    const keys=['1','2','3','4','5','6','7','8','9','','0','⌫'];
    
    keys.forEach(k=>{
      const b=document.createElement('button');
      b.className='keypad-btn';
      
      if(k===''){
        b.style.visibility='hidden';
      } else if(k==='⌫'){
        b.className='btn-ghost';
        b.textContent=k;
        b.onclick=(e)=>{
          e.preventDefault();
          console.log('🔙 [KEYPAD] Backspace pressed');
          onBack();
        };
      } else {
        b.textContent=k;
        b.onclick=(e)=>{
          e.preventDefault();
          console.log('🔢 [KEYPAD] Digit pressed:', k);
          onDigit(k);
        };
      }
      el.appendChild(b);
    });
    
    console.log('✅ [KEYPAD] Keypad built successfully');
  }catch(err){
    console.error('❌ [KEYPAD] Error building keypad:', err);
  }
}

let pinTarget = 6;
let pinMode = null; // 'setup' | 'unlock'

async function initAuthScreen(){
  // Create new circular PIN entry screen with SVG logo
  document.getElementById('lock').innerHTML = `
    <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:100vh; padding:20px; width:100%;">
      
      <!-- Circular Logo with SVG -->
      <div style="position:relative; width:180px; height:180px; margin-bottom:40px; flex-shrink:0;">
        <svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" style="width:100%; height:100%;">
          <!-- Outer circles -->
          <circle cx="100" cy="100" r="95" fill="none" stroke="var(--brass)" stroke-width="2" opacity="0.3"/>
          <circle cx="100" cy="100" r="90" fill="none" stroke="var(--brass)" stroke-width="1.5" opacity="0.2"/>
          
          <!-- Inner circle -->
          <circle cx="100" cy="100" r="70" fill="var(--charcoal)" stroke="var(--brass)" stroke-width="2"/>
          
          <!-- Upload icon (folder with arrow) -->
          <g transform="translate(100, 100)">
            <!-- Folder shape -->
            <path d="M -30 -15 L -10 -15 L -5 -25 L 30 -25 L 30 25 L -30 25 Z" fill="none" stroke="var(--brass)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            <!-- Upload arrow -->
            <path d="M -5 10 L -5 -5 M -10 0 L -5 -5 L 0 0" fill="none" stroke="var(--brass)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
          </g>
        </svg>
      </div>
      
      <!-- Title and Subtitle -->
      <div style="text-align:center; margin-bottom:45px;">
        <div class="modal-title display" id="lockTitle" style="font-size:24px; margin-bottom:8px; font-weight:600;">Enter your PIN</div>
        <div class="help-text" id="lockSub" style="font-size:13px; color:var(--steel); max-width:280px;">6-digit code to unlock your secure vault</div>
      </div>
      
      <!-- PIN Dots -->
      <div id="pinDots" style="display:flex; justify-content:center; gap:12px; margin-bottom:40px; flex-shrink:0;"></div>
      
      <!-- Error Message -->
      <div id="lockError" class="help-text" style="color:var(--alert); text-align:center; min-height:16px; font-size:12px; margin-bottom:30px;"></div>
      
      <!-- Keypad -->
      <div id="keypad" style="display:grid; grid-template-columns:repeat(3,1fr); gap:12px; width:100%; max-width:280px; margin-bottom:20px; flex-shrink:0;"></div>
      
    </div>
  `;
  
  // SVG logo is already rendered, no canvas dial needed
  let storedSalt = await LocalDB.getConfig('salt');
  
  // If no local salt, check Firestore (for multi-device sync)
  if(!storedSalt){
    try{
      const userId = Cloud.auth.currentUser.uid;
      console.log('🔍 [MULTIDEVICE] Checking Firestore for PIN salt, user:', userId);
      
      const userDoc = await Cloud.db.collection('users').doc(userId).get();
      console.log('📋 [MULTIDEVICE] Firestore document exists:', vaultDoc.exists);
      
      if(userDoc.exists){
        const data = userDoc.data();
        console.log('📋 [MULTIDEVICE] Document data keys:', Object.keys(data || {}));
        
        if(data && data.salt){
          storedSalt = data.salt;
          const verifier = data.verifier;
          await LocalDB.setConfig('salt', storedSalt);
          await LocalDB.setConfig('verifier', verifier);
          console.log('✅ [MULTIDEVICE] PIN salt loaded from Firestore successfully');
        } else {
          console.warn('⚠️ [MULTIDEVICE] Document exists but no salt found');
        }
      } else {
        console.log('ℹ️ [MULTIDEVICE] No Firestore document found - this is first device');
      }
    }catch(e){
      console.warn('⚠️ [MULTIDEVICE] Could not load PIN from Firestore:', e.message);
      console.warn('⚠️ [MULTIDEVICE] Error code:', e.code);
      // Don't fail - just use setup mode
    }
  }
  
  pinMode = storedSalt ? 'unlock' : 'setup';
  
  document.getElementById('lockTitle').textContent = pinMode==='setup' ? 'Set your vault PIN' : 'Enter your PIN';
  document.getElementById('lockSub').textContent = pinMode==='setup'
    ? `Welcome, ${State.googleUser.displayName || State.googleUser.email}! Choose a 6-digit PIN to encrypt your vault.`
    : 'Enter your PIN to unlock your vault.';
  
  renderPinDots(document.getElementById('pinDots'), pinTarget, 0);
  buildKeypad(document.getElementById('keypad'), onPinDigit, onPinBack);
  document.getElementById('lockError').textContent='';
}

async function onPinDigit(d){
  if(!d){
    console.warn('⚠️ [PIN] No digit provided');
    return;
  }
  
  if(State.pinBuffer.length>=6){
    console.log('ℹ️ [PIN] PIN already 6 digits, ignoring:', d);
    return;
  }
  
  State.pinBuffer+=d;
  console.log('📝 [PIN] PIN digit added. Buffer length:', State.pinBuffer.length);
  renderPinDots(document.getElementById('pinDots'), pinTarget, State.pinBuffer.length);
  
  if(State.pinBuffer.length===6){
    console.log('✅ [PIN] PIN entry complete. Mode:', pinMode);
    if(pinMode==='setup') await finishSetup();
    else await tryUnlock();
  }
}

function onPinBack(){
  if(State.pinBuffer.length===0){
    console.log('ℹ️ [PIN] Nothing to backspace');
    return;
  }
  
  State.pinBuffer=State.pinBuffer.slice(0,-1);
  console.log('⌫ [PIN] Backspace. Buffer length:', State.pinBuffer.length);
  renderPinDots(document.getElementById('pinDots'), pinTarget, State.pinBuffer.length);
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
  
  // Store PIN salt in Firestore for multi-device sync
  try{
    const userId = Cloud.auth.currentUser.uid;
    console.log('💾 [MULTIDEVICE] Saving PIN salt to Firestore for user:', userId);
    
    const vaultData = {
      salt: salt,
      verifier: verifier,
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
      lastUpdated: firebase.firestore.FieldValue.serverTimestamp(),
      email: Cloud.auth.currentUser.email
    };
    
    await Cloud.db.collection('users').doc(userId).set({email: Cloud.auth.currentUser.email, salt, verifier, createdAt: firebase.firestore.FieldValue.serverTimestamp(), lastUpdated: firebase.firestore.FieldValue.serverTimestamp()}, {merge: true});
    console.log('✅ [MULTIDEVICE] PIN salt successfully saved to Firestore');
  }catch(e){
    console.error('❌ [MULTIDEVICE] Failed to sync PIN to Firestore:', e);
    console.error('❌ [MULTIDEVICE] Error code:', e.code);
    console.error('❌ [MULTIDEVICE] Error message:', e.message);
    // Don't fail - local copy is enough
    toast('⚠️ Cloud sync failed, but vault is created locally');
  }
  
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
  console.log('📂 [VAULT] Loading vault data...');
  const cats = await LocalDB.getConfig('categories');
  State.categories = cats && cats.length ? cats : [...DEFAULT_CATEGORIES];

  let localItems = await LocalDB.allItems();
  console.log('💾 [VAULT] Found', localItems.length, 'local items');

  const fbCfg = window.VAULLET_FIREBASE_CONFIG;
  if(fbCfg && fbCfg.apiKey){
    try{
      const ok = await Cloud.init(fbCfg);
      if(ok && Cloud.auth.currentUser){
        console.log('☁️ [VAULT] Syncing with Firestore...');
        toast('Syncing with Firestore…');
        const cloudItems = await Cloud.pull();
        console.log('☁️ [VAULT] Found', cloudItems.length, 'cloud items');
        const localIds = new Set(localItems.map(i=>i.id));
        let newCount = 0;
        for(const ci of cloudItems){
          if(!localIds.has(ci.id)){
            try{ 
              await LocalDB.putItem(ci); 
              newCount++;
            } catch(e){ 
              console.warn('⚠️ [VAULT] Skipping malformed cloud item', ci.id, e); 
            }
          }
        }
        if(newCount > 0) console.log('✅ [VAULT] Added', newCount, 'new items from cloud');
        localItems = await LocalDB.allItems();
      }
    }catch(e){
      console.error('❌ [VAULT] Firestore sync failed:', e);
      toast('Firestore sync failed — showing local documents only.');
    }
  }

  State.documents = [];
  for(const enc of localItems){
    try{
      const json = await Crypto.decryptStr(State.masterKey, {iv:enc.iv, ct:enc.ct});
      const data = JSON.parse(json);
      State.documents.push({...data, id:enc.id, favorite:!!enc.favorite, updatedAt:enc.updatedAt, deviceName:enc.deviceName});
    }catch(e){ 
      console.warn('⚠️ [VAULT] Could not decrypt item', enc.id); 
    }
  }
  
  console.log('✅ [VAULT] Loaded', State.documents.length, 'decrypted documents');
  
  // Auto-sync files from Google Drive vault folder
  if(State.googleUser && localStorage.getItem('vaullet_google_access_token')){
    try{
      console.log('📁 [VAULT] Auto-syncing from Google Drive...');
      const synced = await Drive.syncFromDrive();
      if(synced > 0) {
        console.log('✅ [VAULT] Synced', synced, 'files from Drive');
        toast(`✅ Synced ${synced} file${synced!==1?'s':''} from Drive`);
      }
    }catch(e){
      console.warn('⚠️ [VAULT] Auto-sync failed:', e.message);
    }
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
  console.log('📋 [MENU] Opening file menu for:', id);
  fileMenuTargetId = id;
  const modal = document.getElementById('fileMenuModal');
  if(!modal){
    console.warn('⚠️ [MENU] File menu modal not found!');
    return;
  }
  modal.classList.add('active');
  console.log('✅ [MENU] File menu opened');
}

async function openRenameModal(){
  console.log('🔧 [MENU] Opening rename modal for:', fileMenuTargetId);
  const d = State.documents.find(x=>x.id===fileMenuTargetId);
  if(!d){
    console.warn('⚠️ [MENU] Document not found:', fileMenuTargetId);
    return;
  }
  document.getElementById('f_newname').value = d.name;
  closeModals();
  document.getElementById('renameModal').classList.add('active');
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
  console.log('📁 [MENU] Opening move/copy modal, mode:', mode);
  fileMoveMode = mode; // 'move' or 'copy'
  const catSel = document.getElementById('f_targetCategory');
  catSel.innerHTML = State.categories.map(c=>`<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
  
  const d = State.documents.find(x=>x.id===fileMenuTargetId);
  if(!d){
    console.warn('⚠️ [MENU] Document not found:', fileMenuTargetId);
    return;
  }
  catSel.value = d.category;
  
  document.getElementById('moveModalTitle').textContent = mode==='move' ? 'Move to category' : 'Copy to category';
  document.getElementById('confirmMoveBtn').textContent = mode==='move' ? 'Move' : 'Copy';
  closeModals();
  document.getElementById('moveModal').classList.add('active');
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
    render();
  }catch(e){
    console.error('Move/Copy failed:', e);
    toast('Could not move/copy file');
  }
}

async function downloadFileFromMenu(){
  console.log('📥 [DOWNLOAD] Downloading from menu for:', fileMenuTargetId);
  const d = State.documents.find(x=>x.id===fileMenuTargetId);
  if(!d || !d.attachment){
    console.warn('⚠️ [DOWNLOAD] No attachment found');
    toast('No file to download');
    return;
  }
  
  closeModals();
  
  try{
    let blob;
    const fileName = d.attachment.name || 'attachment';
    
    if(d.attachment.storage === 'drive'){
      console.log('📥 [DOWNLOAD] Downloading from Drive:', fileName);
      const fileData = await Drive.download(d.attachment.driveFileId);
      
      let plainBuf;
      if(d.attachment.iv){
        // File is encrypted - decrypt it
        console.log('🔓 [DOWNLOAD] Decrypting file:', fileName);
        plainBuf = await Crypto.decryptBytes(State.masterKey, d.attachment.iv, fileData);
      } else {
        // File is unencrypted - use as-is
        console.log('📄 [DOWNLOAD] File is unencrypted:', fileName);
        plainBuf = fileData;
      }
      blob = new Blob([plainBuf], {type: d.attachment.type || 'application/octet-stream'});
    } else if(d.attachment.data){
      const res = await fetch(d.attachment.data);
      blob = await res.blob();
    } else {
      throw new Error('No attachment data found');
    }
    
    if(blob){
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = fileName;
      a.click();
      setTimeout(()=>URL.revokeObjectURL(a.href), 100);
      toast('Downloaded: ' + fileName);
      console.log('✅ [DOWNLOAD] File downloaded:', fileName);
    }
  }catch(err){
    console.error('❌ [DOWNLOAD] Download failed:', err);
    toast('Download failed: ' + err.message);
  }
}

async function openDeleteModal(){
  console.log('🗑️ [MENU] Opening delete modal for:', fileMenuTargetId);
  const d = State.documents.find(x=>x.id===fileMenuTargetId);
  if(!d){
    console.warn('⚠️ [MENU] Document not found:', fileMenuTargetId);
    return;
  }
  
  document.getElementById('deleteFileName').textContent = escapeHtml(d.name);
  closeModals();
  document.getElementById('deleteModal').classList.add('active');
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
  console.log('🖼️ [PREVIEW] Opening preview for file ID:', id);
  const d = State.documents.find(x=>x.id===id);
  if(!d || !d.attachment){
    console.warn('⚠️ [PREVIEW] No attachment found for:', id);
    return;
  }
  
  const modal = document.getElementById('previewModal');
  const previewBody = document.getElementById('previewBody');
  const previewTitle = document.getElementById('previewTitle');
  
  if(!modal || !previewBody){
    console.error('❌ [PREVIEW] Modal elements not found');
    return;
  }
  
  try{
    // 1. Complete HTML reset - remove everything
    console.log('🧹 [PREVIEW] Clearing modal content');
    previewBody.innerHTML = '';
    previewTitle.textContent = escapeHtml(d.attachment.name || 'Attachment');
    
    // 2. Show loading message
    previewBody.innerHTML = '<div style="text-align:center; padding:40px; color:var(--steel);">Loading…</div>';
    modal.classList.add('active');
    
    let blob;
    const fileName = d.attachment.name || 'attachment';
    
    // 3. Download file
    if(d.attachment.storage === 'drive'){
      previewBody.innerHTML = '<div style="text-align:center; padding:40px; color:var(--steel);">Downloading from Google Drive…</div>';
      const fileData = await Drive.download(d.attachment.driveFileId);
      
      // Check if encrypted or raw
      let plainBuf;
      if(d.attachment.iv){
        console.log('🔓 [PREVIEW] Decrypting file:', fileName);
        plainBuf = await Crypto.decryptBytes(State.masterKey, d.attachment.iv, fileData);
      } else {
        console.log('📄 [PREVIEW] Using raw unencrypted file:', fileName);
        plainBuf = fileData;
      }
      
      blob = new Blob([plainBuf], {type: d.attachment.type || 'application/octet-stream'});
    } else if(d.attachment.data){
      const res = await fetch(d.attachment.data);
      blob = await res.blob();
    } else {
      throw new Error('No attachment data found');
    }
    
    // 4. Clear loading and render new content
    console.log('🎨 [PREVIEW] Rendering file:', fileName);
    previewBody.innerHTML = '';
    
    if(/\.pdf$/i.test(fileName) && window.pdfjsLib){
      await renderPdfPreview(blob, previewBody);
      console.log('✅ [PREVIEW] PDF rendered successfully');
    } else if(/\.(jpg|jpeg|png|gif|webp)$/i.test(fileName)){
      renderImagePreview(blob, previewBody);
      console.log('✅ [PREVIEW] Image rendered successfully');
    } else if(/\.(txt|md|markdown|js|json|html|css|xml|yaml|yml|py|java|cpp|c|sh|bash)$/i.test(fileName)){
      // Text-based files
      await renderTextPreview(blob, previewBody, fileName);
      console.log('✅ [PREVIEW] Text file rendered successfully');
    } else if(/\.(doc|docx)$/i.test(fileName)){
      // Word documents - show download button with preview message
      renderDocumentPreview(blob, previewBody, fileName, d.attachment.name);
      console.log('ℹ️ [PREVIEW] Word document - showing download option');
    } else if(/\.(xls|xlsx)$/i.test(fileName)){
      // Excel files - show download button with preview message
      renderSpreadsheetPreview(blob, previewBody, fileName, d.attachment.name);
      console.log('ℹ️ [PREVIEW] Excel file - showing download option');
    } else {
      previewBody.innerHTML = `<div style="text-align:center; padding:40px;">
        <div style="color:var(--brass); font-size:40px; margin-bottom:12px;">📄</div>
        <div style="color:var(--bone);">Cannot preview this file type</div>
        <div style="color:var(--steel); font-size:12px; margin-top:8px;">${escapeHtml(fileName)}</div>
        <button class="btn" id="fallback-download" style="margin-top:16px;">⬇️ Download file</button>
      </div>`;
      // Add download handler
      const dlBtn = document.getElementById('fallback-download');
      if(dlBtn){
        dlBtn.onclick = ()=>{
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = d.attachment.name || 'file';
          a.click();
          setTimeout(()=>URL.revokeObjectURL(a.href), 100);
        };
      }
      console.log('ℹ️ [PREVIEW] File type not previewed - download option provided');
    }
  }catch(err){
    console.error('❌ [PREVIEW] Preview error:', err.message);
    previewBody.innerHTML = `<div style="text-align:center; padding:40px; color:var(--alert);">
      <div style="margin-bottom:10px;">Could not load preview</div>
      <div style="font-size:12px; color:var(--steel);">${escapeHtml(err.message)}</div>
    </div>`;
  }
}

async function renderPdfPreview(blob, container){
  console.log('📕 [PDF] Starting PDF render');
  // Complete cleanup first
  container.innerHTML = '';
  
  const viewerHtml = `
    <div id="pdf-viewer" style="height:100%; width:100%; display:flex; flex-direction:column; background:var(--bg-secondary);">
      <div id="pdf-toolbar" style="padding:12px; border-bottom:1px solid var(--hairline); display:flex; justify-content:space-between; align-items:center; flex-shrink:0;">
        <div style="font-size:12px; color:var(--steel);">Page <span id="pdf-page">1</span> of <span id="pdf-total">1</span></div>
        <div style="display:flex; gap:6px;">
          <button class="btn" id="pdf-prev" style="padding:6px 10px; font-size:11px;">← Prev</button>
          <button class="btn" id="pdf-next" style="padding:6px 10px; font-size:11px;">Next →</button>
        </div>
      </div>
      <div id="pdf-canvas-container" style="flex:1; overflow:auto; display:flex; align-items:center; justify-content:center;"></div>
    </div>
  `;
  container.innerHTML = viewerHtml;
  
  try{
    const arrayBuf = await blob.arrayBuffer();
    const pdf = await window.pdfjsLib.getDocument({data: arrayBuf}).promise;
    console.log('📕 [PDF] Loaded PDF with', pdf.numPages, 'pages');
    
    document.getElementById('pdf-total').textContent = pdf.numPages;
    
    let currentPage = 1;
    const canvasContainer = document.getElementById('pdf-canvas-container');
    const prevBtn = document.getElementById('pdf-prev');
    const nextBtn = document.getElementById('pdf-next');
    
    const renderPage = async (pageNum)=>{
      try{
        console.log('📄 [PDF] Rendering page', pageNum);
        const page = await pdf.getPage(pageNum);
        const scale = window.innerHeight > 1000 ? 2 : 1.5;
        const viewport = page.getViewport({scale});
        
        const canvas = document.createElement('canvas');
        canvas.width = viewport.width;
        canvas.height = viewport.height;
        
        const ctx = canvas.getContext('2d');
        if(!ctx) throw new Error('Could not get canvas context');
        
        await page.render({canvasContext: ctx, viewport}).promise;
        
        // Clear and add new canvas
        if(canvasContainer){
          canvasContainer.innerHTML = '';
          canvas.style.maxWidth = '95vw';
          canvas.style.maxHeight = '85vh';
          canvas.style.boxShadow = 'var(--shadow)';
          canvasContainer.appendChild(canvas);
        }
        
        const pageSpan = document.getElementById('pdf-page');
        if(pageSpan) pageSpan.textContent = pageNum;
      }catch(e){
        console.error('❌ [PDF] Page render error:', e);
      }
    };
    
    // Render first page
    await renderPage(1);
    
    // Setup buttons
    if(prevBtn) prevBtn.onclick = async ()=>{ 
      if(currentPage > 1) await renderPage(--currentPage); 
    };
    if(nextBtn) nextBtn.onclick = async ()=>{ 
      if(currentPage < pdf.numPages) await renderPage(++currentPage); 
    };
    
    console.log('✅ [PDF] PDF viewer ready');
  }catch(e){
    console.error('❌ [PDF] PDF render failed:', e);
    container.innerHTML = `<div style="text-align:center; padding:40px; color:var(--alert);">
      <div style="margin-bottom:10px;">PDF viewer error</div>
      <div style="font-size:12px; color:var(--steel);">${escapeHtml(e.message)}</div>
    </div>`;
  }
}

function renderImagePreview(blob, container){
  const url = URL.createObjectURL(blob);
  container.innerHTML = `<div style="padding:20px; text-align:center; display:flex; align-items:center; justify-content:center; height:100%;"><img src="${url}" style="max-width:95vw; max-height:95vh; object-fit:contain; border-radius:8px; box-shadow:var(--shadow); display:block; margin:0 auto;"></div>`;
  setTimeout(()=>URL.revokeObjectURL(url), 300000);
}

async function renderTextPreview(blob, container, fileName){
  try{
    const text = await blob.text();
    const language = getLanguageFromExt(fileName);
    
    container.innerHTML = `
      <div style="padding:20px; height:100%; display:flex; flex-direction:column;">
        <div style="flex:1; overflow:auto; background:var(--bg-secondary); border-radius:8px; padding:16px;">
          <pre style="margin:0; color:var(--bone); font-family:monospace; font-size:13px; line-height:1.5; white-space:pre-wrap; word-wrap:break-word;">${escapeHtml(text)}</pre>
        </div>
      </div>
    `;
    console.log('✅ [TEXT] Text file rendered:', fileName);
  }catch(err){
    console.error('❌ [TEXT] Failed to read text file:', err);
    container.innerHTML = `<div style="text-align:center; padding:40px; color:var(--alert);">
      <div>Could not read file</div>
      <div style="font-size:12px; color:var(--steel);">${escapeHtml(err.message)}</div>
    </div>`;
  }
}

function getLanguageFromExt(fileName){
  const ext = fileName.split('.').pop().toLowerCase();
  const langs = {
    'js': 'javascript',
    'py': 'python',
    'java': 'java',
    'cpp': 'cpp',
    'c': 'c',
    'html': 'html',
    'css': 'css',
    'json': 'json',
    'xml': 'xml',
    'sh': 'bash',
    'bash': 'bash',
    'md': 'markdown',
    'yaml': 'yaml',
    'yml': 'yaml'
  };
  return langs[ext] || 'text';
}

function renderDocumentPreview(blob, container, fileName, originalName){
  container.innerHTML = `
    <div style="text-align:center; padding:40px; display:flex; flex-direction:column; align-items:center; height:100%; justify-content:center;">
      <div style="color:var(--brass); font-size:50px; margin-bottom:16px;">📄</div>
      <div style="color:var(--bone); font-size:16px; margin-bottom:8px;">Word Document</div>
      <div style="color:var(--steel); font-size:12px; margin-bottom:24px;">${escapeHtml(originalName || fileName)}</div>
      <button class="btn" id="doc-download" style="padding:10px 24px;">⬇️ Download and Open in Word</button>
      <div style="color:var(--steel); font-size:11px; margin-top:16px; max-width:400px;">Word documents are best viewed in Microsoft Word or compatible applications. Click the download button to open this file.</div>
    </div>
  `;
  
  const dlBtn = document.getElementById('doc-download');
  if(dlBtn){
    dlBtn.onclick = ()=>{
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = originalName || fileName;
      a.click();
      setTimeout(()=>URL.revokeObjectURL(a.href), 100);
    };
  }
}

function renderSpreadsheetPreview(blob, container, fileName, originalName){
  container.innerHTML = `
    <div style="text-align:center; padding:40px; display:flex; flex-direction:column; align-items:center; height:100%; justify-content:center;">
      <div style="color:var(--brass); font-size:50px; margin-bottom:16px;">📊</div>
      <div style="color:var(--bone); font-size:16px; margin-bottom:8px;">Excel Spreadsheet</div>
      <div style="color:var(--steel); font-size:12px; margin-bottom:24px;">${escapeHtml(originalName || fileName)}</div>
      <button class="btn" id="xlsx-download" style="padding:10px 24px;">⬇️ Download and Open in Excel</button>
      <div style="color:var(--steel); font-size:11px; margin-top:16px; max-width:400px;">Excel spreadsheets are best viewed in Microsoft Excel or compatible applications. Click the download button to open this file.</div>
    </div>
  `;
  
  const dlBtn = document.getElementById('xlsx-download');
  if(dlBtn){
    dlBtn.onclick = ()=>{
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = originalName || fileName;
      a.click();
      setTimeout(()=>URL.revokeObjectURL(a.href), 100);
    };
  }
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

function renderMobileSidebar(){
  const sidebarNav = document.getElementById('mobileSidebarNav');
  sidebarNav.innerHTML = '';
  
  NAV.forEach(n=>{
    const b=document.createElement('button');
    b.className='rail-btn'+(State.activeTab===n.id?' active':'');
    b.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="${n.icon}"/></svg><span>${n.label}</span>`;
    b.onclick=()=>{
      navigate(n.id);
      closeMobileSidebar();
    };
    sidebarNav.appendChild(b);
  });
}

function openMobileSidebar(){
  const sidebar = document.getElementById('mobileSidebar');
  const overlay = document.getElementById('sidebarOverlay');
  sidebar.classList.add('active');
  overlay.classList.add('active');
  console.log('📂 [SIDEBAR] Mobile sidebar opened');
}

function closeMobileSidebar(){
  const sidebar = document.getElementById('mobileSidebar');
  const overlay = document.getElementById('sidebarOverlay');
  sidebar.classList.remove('active');
  overlay.classList.remove('active');
  console.log('📂 [SIDEBAR] Mobile sidebar closed');
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
    <button class="btn" data-action="sync-drive">🔄 Sync Drive</button>
    <button class="btn" data-action="goto-search">🔍 Search</button>
    <button class="btn" data-action="add-card">💳 Add card</button>
  </div>

  <div class="section-title">Expiring soon ${expiring.length?`<span class="link" data-action="goto-alerts">View all</span>`:''}</div>
  ${expiring.length? expiring.map(docRowHtml).join('') : '<div class="empty">Nothing expiring in the next 30 days.</div>'}

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
    
    <!-- Card number (masked/revealed) -->
    <div class="wc-number mono" data-masked="true" data-id="${d.id}" data-real="${escapeHtml(d.number)}">${maskNumber(d.number)}</div>
    
    <!-- Card details (expiry and CVV visible on reveal) -->
    <div class="wc-details" data-id="${d.id}" style="display:none; font-size:11px; color:var(--steel); margin-top:8px;">
      <div style="display:flex; gap:20px;">
        <div>
          <div class="wc-label">Expiry</div>
          <div class="wc-value mono">${escapeHtml(d.expiry || 'N/A')}</div>
        </div>
        <div>
          <div class="wc-label">CVV</div>
          <div class="wc-value mono">${escapeHtml(d.cvv || 'N/A')}</div>
        </div>
      </div>
    </div>
    
    <div class="wc-bottom">
      <div>
        <div class="wc-label">Name</div>
        <div class="wc-value">${escapeHtml(d.name)}</div>
      </div>
      <div style="display:flex; gap:8px;">
        <button class="wc-reveal" data-action="reveal" data-id="${d.id}">Reveal</button>
        <button class="wc-reveal" data-action="edit-card" data-id="${d.id}" style="background:var(--graphite); color:var(--brass);">Edit</button>
      </div>
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
  renderMobileSidebar();
  wireContentEvents();
}

function wireContentEvents(){
  document.querySelectorAll('[data-action="add-doc"]').forEach(b=>b.onclick=()=>openDocModal('document'));
  document.querySelectorAll('[data-action="add-card"]').forEach(b=>b.onclick=()=>openDocModal('card'));
  document.querySelectorAll('[data-action="scan"]').forEach(b=>b.onclick=()=>{ openDocModal('document'); setTimeout(()=>document.getElementById('f_file').click(),200); });
  document.querySelectorAll('[data-action="sync-drive"]').forEach(b=>b.onclick=async ()=>{ 
    b.disabled=true; 
    b.textContent='🔄 Syncing...'; 
    const count = await Drive.syncFromDrive();
    render();
    b.disabled=false; 
    b.textContent='🔄 Sync Drive';
    toast(`Synced ${count} file${count!==1?'s':''} from Drive`);
  });
  document.querySelectorAll('[data-action="goto-search"]').forEach(b=>b.onclick=()=>navigate('search'));
  document.querySelectorAll('[data-action="goto-alerts"]').forEach(b=>b.onclick=()=>navigate('notifications'));
  document.querySelectorAll('[data-action="filter-cat"]').forEach(b=>b.onclick=()=>{ State.activeCategory=b.dataset.cat; render(); });
  document.querySelectorAll('[data-action="new-cat"]').forEach(b=>b.onclick=()=>document.getElementById('catModal').classList.add('active'));
  document.querySelectorAll('[data-action="fav"]').forEach(b=>b.onclick=(e)=>{ e.stopPropagation(); toggleFavorite(b.dataset.id); });
  document.querySelectorAll('[data-action="reveal"]').forEach(b=>b.onclick=(e)=>{ 
    e.stopPropagation();
    requestReveal(b.dataset.id);
  });
  document.querySelectorAll('[data-action="edit-card"]').forEach(b=>b.onclick=(e)=>{ 
    e.stopPropagation();
    editCard(b.dataset.id);
  });
  document.querySelectorAll('[data-action="file-menu"]').forEach(b=>b.onclick=(e)=>{ e.stopPropagation(); openFileMenu(b.dataset.id); });
  document.querySelectorAll('.doc-row[data-action="open"]').forEach(r=>r.onclick=(e)=>{ 
    if(e.target.closest('[data-action="fav"]') || e.target.closest('[data-action="file-menu"]')) return;
    const id = r.dataset.id;
    const doc = State.documents.find(d=>d.id===id);
    console.log('📄 [CLICK] File clicked:', doc?.name, 'Has attachment:', !!doc?.attachment);
    if(doc && doc.attachment){
      // Has attachment - preview it
      console.log('👁 [PREVIEW] Opening preview for:', doc.attachment.name);
      previewAttachment(id, 0);
    } else {
      // No attachment - open edit modal
      console.log('✏️ [EDIT] Opening edit modal for:', doc?.name);
      viewDocument(id);
    }
  });

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
        downloadBtn.textContent = d.attachment.iv ? 'Decrypting…' : 'Downloading…';
        try{
          let blob;
          if(d.attachment.storage === 'drive'){
            const fileData = await Drive.download(d.attachment.driveFileId);
            let plainBuf;
            if(d.attachment.iv){
              // File is encrypted - decrypt it
              console.log('🔓 [DOWNLOAD] Decrypting:', d.attachment.name);
              plainBuf = await Crypto.decryptBytes(State.masterKey, d.attachment.iv, fileData);
            } else {
              // File is unencrypted - use as-is
              console.log('📥 [DOWNLOAD] File is unencrypted:', d.attachment.name);
              plainBuf = fileData;
            }
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
        // Upload raw file to Drive (NO encryption)
        btn.textContent = 'Uploading to Drive…';
        const rawBytes = await file.arrayBuffer();
        const driveFileId = await Drive.uploadRaw(rawBytes, file.name);
        attachment = {storage:'drive', driveFileId, name:file.name, type:file.type, size:file.size};
        console.log('✅ [UPLOAD] File uploaded to Drive unencrypted');
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
      toast('Saved to Google Drive (unencrypted).');
    }
  }catch(e){
    console.error('Save to vault failed:', e);
    let errorMsg = e.message || 'unknown error';
    if(errorMsg.includes('HTTP 401') || errorMsg.includes('HTTP 403') || errorMsg.includes('token')){
      errorMsg = 'Google Drive access expired. Please sign out and sign in again.';
    }
    toast('Could not save: ' + errorMsg);
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
    
    // Reveal card number
    const numberEl = document.querySelector(`.wc-number[data-id="${id}"]`);
    if(numberEl && d){ 
      numberEl.textContent = d.number || '—'; 
      numberEl.dataset.masked='false';
      // Auto-hide after 10 seconds
      setTimeout(()=>{ 
        numberEl.textContent = maskNumber(d.number); 
        numberEl.dataset.masked='true';
      }, 10000);
    }
    
    // Show expiry and CVV
    const detailsEl = document.querySelector(`.wc-details[data-id="${id}"]`);
    if(detailsEl){ 
      detailsEl.style.display = 'block';
      // Auto-hide after 10 seconds
      setTimeout(()=>{ 
        detailsEl.style.display = 'none';
      }, 10000);
    }
    
    console.log('🔓 [CARD] Card details revealed for 10 seconds');
  } else {
    document.getElementById('authError').textContent='Incorrect PIN.';
    authPin='';
    renderPinDots(document.getElementById('authPinDots'), authPinTarget, 0);
  }
}

async function editCard(id){
  console.log('✏️ [CARD] Editing card:', id);
  const card = State.documents.find(d=>d.id===id);
  if(!card) return;
  
  // Populate form with card data
  document.getElementById('f_name').value = card.name || '';
  document.getElementById('f_number').value = card.number || '';
  document.getElementById('f_cvv').value = card.cvv || '';
  document.getElementById('f_expiry').value = card.expiry || '';
  document.getElementById('f_category').value = card.category || 'Cards';
  
  // Set edit mode
  editingDocId = id;
  editingDocType = 'card';
  
  const btn = document.getElementById('docSaveBtn');
  btn.textContent = '💾 Update card';
  
  openDocModal('card');
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

function closeModals(){ 
  document.querySelectorAll('.overlay').forEach(o=>{
    o.classList.remove('active');
    // Clear any remaining content in modals
    const modal = o.querySelector('.modal');
    if(modal){
      const body = modal.querySelector('.modal-body');
      if(body && body.id === 'previewBody'){
        body.innerHTML = '';
      }
    }
  });
}
document.querySelectorAll('[data-close]').forEach(b=>b.onclick=closeModals);
document.querySelectorAll('.overlay').forEach(o=>o.addEventListener('click', e=>{ if(e.target===o) closeModals(); }));

/* ===== FILE MANAGEMENT MODAL HANDLERS ===== */
const fileMenuModal = document.getElementById('fileMenuModal');
if(fileMenuModal){
  fileMenuModal.querySelectorAll('[data-action="file-rename"]').forEach(b=>{
    b.onclick = async (e)=>{
      e.preventDefault();
      e.stopPropagation();
      await openRenameModal();
    };
  });
  fileMenuModal.querySelectorAll('[data-action="file-move"]').forEach(b=>{
    b.onclick = async (e)=>{
      e.preventDefault();
      e.stopPropagation();
      await openMoveModal('move');
    };
  });
  fileMenuModal.querySelectorAll('[data-action="file-copy"]').forEach(b=>{
    b.onclick = async (e)=>{
      e.preventDefault();
      e.stopPropagation();
      await openMoveModal('copy');
    };
  });
  fileMenuModal.querySelectorAll('[data-action="file-download"]').forEach(b=>{
    b.onclick = async (e)=>{
      e.preventDefault();
      e.stopPropagation();
      await downloadFileFromMenu();
    };
  });
  fileMenuModal.querySelectorAll('[data-action="file-delete"]').forEach(b=>{
    b.onclick = async (e)=>{
      e.preventDefault();
      e.stopPropagation();
      await openDeleteModal();
    };
  });
}

const confirmRenameBtn = document.getElementById('confirmRenameBtn');
if(confirmRenameBtn) confirmRenameBtn.onclick = renameFile;

const confirmMoveBtn = document.getElementById('confirmMoveBtn');
if(confirmMoveBtn) confirmMoveBtn.onclick = moveOrCopyFile;

const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
if(confirmDeleteBtn) confirmDeleteBtn.onclick = deleteFileConfirmed;

/* ===== FILE UPLOAD OPTIONS ===== */
const cameraBtn = document.getElementById('cameraBtn');
const filesBtn = document.getElementById('filesBtn');
const fileInput = document.getElementById('f_file');
const cameraInput = document.getElementById('f_camera');
const fileSelected = document.getElementById('fileSelected');

if(cameraBtn){
  cameraBtn.onclick = (e)=>{
    e.preventDefault();
    console.log('📷 [UPLOAD] Camera button clicked');
    cameraInput.click();
  };
}

if(filesBtn){
  filesBtn.onclick = (e)=>{
    e.preventDefault();
    console.log('📁 [UPLOAD] Files button clicked');
    fileInput.click();
  };
}

// Handle file selection from both inputs
function handleFileSelect(file){
  if(!file) return;
  console.log('✅ [UPLOAD] File selected:', file.name);
  fileSelected.textContent = '✓ ' + file.name;
  fileSelected.style.display = 'block';
}

if(fileInput){
  fileInput.onchange = (e)=>{
    const file = e.target.files?.[0];
    if(file) handleFileSelect(file);
  };
}

if(cameraInput){
  cameraInput.onchange = (e)=>{
    const file = e.target.files?.[0];
    if(file){
      handleFileSelect(file);
      // Copy camera file to main file input for processing
      const dataTransfer = new DataTransfer();
      dataTransfer.items.add(file);
      fileInput.files = dataTransfer.files;
    }
  };
}

/* ===== MOBILE SIDEBAR ===== */
const hamburgerBtn = document.getElementById('hamburgerBtn');
const sidebarClose = document.getElementById('sidebarClose');
const sidebarOverlay = document.getElementById('sidebarOverlay');

if(hamburgerBtn){
  hamburgerBtn.onclick = (e)=>{
    e.preventDefault();
    openMobileSidebar();
  };
}

if(sidebarClose){
  sidebarClose.onclick = (e)=>{
    e.preventDefault();
    closeMobileSidebar();
  };
}

if(sidebarOverlay){
  sidebarOverlay.onclick = closeMobileSidebar;
}

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
      
      // Cache Google Drive token for file preview (so we don't need auth every time)
      try{
        const token = await user.getIdToken();
        localStorage.setItem('vaullet_drive_token', token);
        console.log('✅ [DRIVE] Access token cached for file previews');
      }catch(e){
        console.warn('⚠️ [DRIVE] Could not cache Drive token:', e.message);
      }
      
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
            
            // Extract Google access token from credential
            if(result.credential && result.credential.accessToken){
              localStorage.setItem('vaullet_google_access_token', result.credential.accessToken);
              console.log('✅ [DRIVE] Google access token stored for Drive API');
            }
            
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


// Wire authentication buttons - ONLY after DOM is fully loaded
document.addEventListener('DOMContentLoaded', function(){
  console.log('🔌 [INIT] DOM loaded, wiring auth buttons');
  
  const loginBtn = document.getElementById('loginBtn');
  const registerBtn = document.getElementById('registerBtn');
  const switchToRegister = document.getElementById('switchToRegister');
  const switchToLogin = document.getElementById('switchToLogin');
  
  if(loginBtn){
    loginBtn.onclick = async (e)=>{
      e.preventDefault();
      try{
        loginBtn.disabled = true;
        loginBtn.textContent = 'Signing in...';
        const email = (document.getElementById('loginEmail')?.value || '').trim();
        const password = document.getElementById('loginPassword')?.value || '';
        
        if(!email || !password) throw new Error('Please enter email and password');
        
        await Cloud.loginWithEmail(email, password);
        document.getElementById('loginEmail').value = '';
        document.getElementById('loginPassword').value = '';
        document.getElementById('loginError').textContent = '';
      }catch(err){
        document.getElementById('loginError').textContent = err.message;
        loginBtn.disabled = false;
        loginBtn.textContent = 'Login';
      }
    };
  }
  
  if(registerBtn){
    registerBtn.onclick = async (e)=>{
      e.preventDefault();
      try{
        registerBtn.disabled = true;
        registerBtn.textContent = 'Creating account...';
        const email = (document.getElementById('registerEmail')?.value || '').trim();
        const password = document.getElementById('registerPassword')?.value || '';
        const confirm = document.getElementById('registerConfirm')?.value || '';
        
        if(!email || !password || !confirm) throw new Error('Please fill all fields');
        if(password !== confirm) throw new Error('Passwords do not match');
        
        await Cloud.registerWithEmail(email, password);
        document.getElementById('registerEmail').value = '';
        document.getElementById('registerPassword').value = '';
        document.getElementById('registerConfirm').value = '';
        document.getElementById('registerError').textContent = '';
        
        document.getElementById('registerForm').style.display = 'none';
        document.getElementById('loginForm').style.display = 'block';
        toast('Account created! Please log in.');
      }catch(err){
        document.getElementById('registerError').textContent = err.message;
        registerBtn.disabled = false;
        registerBtn.textContent = 'Create Account';
      }
    };
  }
  
  if(switchToRegister){
    switchToRegister.onclick = ()=>{
      document.getElementById('loginForm').style.display = 'none';
      document.getElementById('registerForm').style.display = 'block';
    };
  }
  
  if(switchToLogin){
    switchToLogin.onclick = ()=>{
      document.getElementById('registerForm').style.display = 'none';
      document.getElementById('loginForm').style.display = 'block';
    };
  }
  
  console.log('✅ [INIT] Auth buttons wired successfully');
});
