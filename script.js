/* VAULLET — Complete Firebase Email/Password + PIN Authentication
   Built from scratch - Firebase Auth, Firestore, Encryption, All Features
*/

const DEFAULT_CATEGORIES = ["Identity","Banking","Cards","Insurance","Vehicle","Education","Employment","Medical","Tax","Personal"];
const ICONS = {Identity:"🪪",Banking:"🏦",Cards:"💳",Insurance:"🛡️",Vehicle:"🚗",Education:"🎓",Employment:"💼",Medical:"⚕️",Tax:"📄",Personal:"🗂️"};

const State = {
  unlocked:false,
  pinBuffer:"",
  masterKey:null,
  currentUser:null,
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

/* ===== CRYPTO ===== */
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

/* ===== CLOUD (Firebase) ===== */
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
  
  signOut(){ return this.auth.signOut(); },
  getCurrentUser(){ return this.auth.currentUser; },
  onAuthStateChanged(callback){ return this.auth.onAuthStateChanged(callback); },
  
  col(){ 
    if(!this.auth.currentUser) throw new Error('Not signed in');
    return this.db.collection("users").doc(this.auth.currentUser.uid).collection("documents"); 
  },
  
  async push(encryptedItem){
    if(!this.configured || !this.auth.currentUser) return {ok:false};
    const approxBytes = new Blob([JSON.stringify(encryptedItem)]).size;
    if(approxBytes > 900 * 1024) return {ok:false, reason:'too-large'};
    try{ 
      await this.col().doc(encryptedItem.id).set(encryptedItem); 
      return {ok:true}; 
    }
    catch(e){ 
      console.warn("sync push failed", e.message); 
      return {ok:false}; 
    }
  },
  
  async pull(){
    if(!this.configured || !this.auth.currentUser) return [];
    try{ 
      const snap = await this.col().get(); 
      return snap.docs.map(d=>d.data()); 
    }
    catch(e){ 
      console.warn("sync pull failed", e.message); 
      return []; 
    }
  },
  
  async remove(id){
    if(!this.configured || !this.auth.currentUser) return false;
    try{ 
      await this.col().doc(id).delete(); 
      return true; 
    } 
    catch(e){ return false; }
  }
};

/* ===== THEME ===== */
function setTheme(theme){
  State.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('vaullet_theme', theme);
}

function loadTheme(){
  const saved = localStorage.getItem('vaullet_theme') || 'dark';
  setTheme(saved);
}

/* ===== AUTH SCREEN ===== */
async function initAuthScreen(){
  const storedSalt = await LocalDB.getConfig('salt');
  const storedVerifier = await LocalDB.getConfig('verifier');
  
  if(!storedSalt || !storedVerifier){
    // New PIN - setup
    document.getElementById('lock').innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:100vh; padding:20px;">
        <div style="text-align:center; margin-bottom:50px;">
          <div class="display" style="font-size:24px; margin-bottom:8px;">Set Your PIN</div>
          <div style="color:var(--steel); font-size:13px;">Create a 6-digit PIN (stored locally)</div>
          <div style="color:var(--brass); font-size:12px; margin-top:8px;">${Cloud.getCurrentUser().email}</div>
        </div>
        <div id="pinDots" style="display:flex; justify-content:center; gap:12px; margin-bottom:40px;"></div>
        <div id="lockError" style="color:var(--alert); font-size:12px; margin-bottom:30px; min-height:16px;"></div>
        <div id="keypad" style="display:grid; grid-template-columns:repeat(3,1fr); gap:12px; width:100%; max-width:280px;"></div>
      </div>
    `;
    window.pinMode = 'setup';
  } else {
    // Existing PIN - unlock
    document.getElementById('lock').innerHTML = `
      <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:100vh; padding:20px;">
        <div style="text-align:center; margin-bottom:50px;">
          <div class="display" style="font-size:24px; margin-bottom:8px;">Enter Your PIN</div>
          <div style="color:var(--steel); font-size:13px;">Unlock your vault</div>
          <div style="color:var(--brass); font-size:12px; margin-top:8px;">${Cloud.getCurrentUser().email}</div>
        </div>
        <div id="pinDots" style="display:flex; justify-content:center; gap:12px; margin-bottom:40px;"></div>
        <div id="lockError" style="color:var(--alert); font-size:12px; margin-bottom:30px; min-height:16px;"></div>
        <div id="keypad" style="display:grid; grid-template-columns:repeat(3,1fr); gap:12px; width:100%; max-width:280px;"></div>
      </div>
    `;
    window.pinMode = 'unlock';
  }
  
  renderPinDots(document.getElementById('pinDots'), 6, 0);
  buildKeypad(document.getElementById('keypad'), onPinDigit, onPinBack);
  
  document.getElementById('app').style.display = 'none';
  document.getElementById('lock').style.display = 'flex';
}

function renderPinDots(container, count, filled){
  container.innerHTML = Array(count).fill(0).map((_, i) => 
    `<div style="width:12px; height:12px; border-radius:50%; background:${i < filled ? 'var(--brass)' : 'var(--graphite)'}; transition:all 200ms;"></div>`
  ).join('');
}

function buildKeypad(container, onDigit, onBack){
  const buttons = [1,2,3,4,5,6,7,8,9,'','0','⌫'];
  container.innerHTML = buttons.map(b => 
    b === '' ? '<div></div>' : 
    `<button style="padding:16px; font-size:18px; border:1px solid var(--hairline); border-radius:8px; background:var(--graphite); color:var(--bone); cursor:pointer; font-weight:600;">${b}</button>`
  ).join('');
  
  const btns = container.querySelectorAll('button');
  btns.forEach((btn, i) => {
    const val = buttons[i];
    if(val === '⌫') btn.onclick = onBack;
    else if(val !== '') btn.onclick = () => onDigit(val);
  });
}

function onPinDigit(digit){
  State.pinBuffer += digit;
  renderPinDots(document.getElementById('pinDots'), 6, State.pinBuffer.length);
  
  if(State.pinBuffer.length === 6){
    setTimeout(() => tryPin(), 200);
  }
}

function onPinBack(){
  State.pinBuffer = State.pinBuffer.slice(0, -1);
  renderPinDots(document.getElementById('pinDots'), 6, State.pinBuffer.length);
  document.getElementById('lockError').textContent = '';
}

async function tryPin(){
  try{
    const storedVerifier = await LocalDB.getConfig('verifier');
    const salt = await LocalDB.getConfig('salt');
    
    if(window.pinMode === 'setup'){
      // Save new PIN
      const {key, salt: newSalt} = await Crypto.deriveKey(State.pinBuffer);
      const verifier = await Crypto.verifierFor(key);
      
      await LocalDB.setConfig('salt', newSalt);
      await LocalDB.setConfig('verifier', verifier);
      State.masterKey = key;
      
      // Save to Firestore
      const userId = Cloud.getCurrentUser().uid;
      await Cloud.db.collection('users').doc(userId).set({
        email: Cloud.getCurrentUser().email,
        salt: newSalt,
        verifier: verifier,
        createdAt: firebase.firestore.FieldValue.serverTimestamp(),
        lastUpdated: firebase.firestore.FieldValue.serverTimestamp()
      }, {merge: true});
      
      State.pinBuffer = '';
      enterVault();
    } else {
      // Verify PIN
      const {key} = await Crypto.deriveKey(State.pinBuffer, salt);
      const verifier = await Crypto.verifierFor(key);
      
      if(verifier === storedVerifier){
        State.masterKey = key;
        State.pinBuffer = '';
        enterVault();
      } else {
        document.getElementById('lockError').textContent = 'Wrong PIN';
        State.pinBuffer = '';
        renderPinDots(document.getElementById('pinDots'), 6, 0);
      }
    }
  }catch(e){
    console.error('PIN error:', e);
    document.getElementById('lockError').textContent = e.message;
    State.pinBuffer = '';
    renderPinDots(document.getElementById('pinDots'), 6, 0);
  }
}

async function enterVault(){
  document.getElementById('lock').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  
  // Load documents
  const cloudItems = await Cloud.pull();
  for(const item of cloudItems){
    try{
      const json = await Crypto.decryptStr(State.masterKey, {iv: item.iv, ct: item.ct});
      const data = JSON.parse(json);
      State.documents.push({...data, id: item.id});
      await LocalDB.putItem(item);
    }catch(e){
      console.warn('Could not decrypt item', item.id);
    }
  }
  
  renderApp();
}

async function lockVault(){
  State.masterKey = null;
  State.documents = [];
  State.pinBuffer = '';
  document.getElementById('app').style.display = 'none';
  await initAuthScreen();
}

/* ===== APP RENDERING ===== */
function renderApp(){
  const content = document.getElementById('content');
  const rail = document.getElementById('rail');
  
  // Rail (sidebar)
  rail.innerHTML = `
    <div style="padding:16px; border-bottom:1px solid var(--hairline);">
      <div class="display" style="font-size:16px; margin-bottom:8px;">Vaullet</div>
      <div style="font-size:11px; color:var(--steel);">Vault</div>
    </div>
    <button data-tab="home" class="rail-item active">🏠 Home</button>
    <button data-tab="documents" class="rail-item">📄 Documents</button>
    <button data-tab="cards" class="rail-item">💳 Cards</button>
    <button data-tab="all" class="rail-item">📂 All Items</button>
  `;
  
  rail.querySelectorAll('[data-tab]').forEach(btn => {
    btn.onclick = () => switchTab(btn.dataset.tab);
  });
  
  // Content
  if(State.activeTab === 'home'){
    content.innerHTML = `
      <div style="padding:24px;">
        <h2 class="display">Welcome</h2>
        <p style="color:var(--steel); margin:16px 0;">You have ${State.documents.length} item${State.documents.length !== 1 ? 's' : ''}</p>
        <button class="btn btn-brass" id="newDocBtn">+ New Document</button>
      </div>
    `;
    document.getElementById('newDocBtn').onclick = () => openDocModal();
  }
  
  document.getElementById('pageTitle').textContent = State.activeTab.charAt(0).toUpperCase() + State.activeTab.slice(1);
}

function switchTab(tab){
  State.activeTab = tab;
  renderApp();
}

function openDocModal(){
  document.getElementById('docModal').classList.add('active');
}

function escapeHtml(text){
  const map = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'};
  return text.replace(/[&<>"']/g, m => map[m]);
}

/* ===== BOOT ===== */
(async function boot(){
  loadTheme();
  
  try{
    await LocalDB.open();
  }catch(e){
    console.error('LocalDB init failed:', e);
    toast('Database init failed');
    return;
  }
  
  const fbCfg = window.VAULLET_FIREBASE_CONFIG;
  if(!fbCfg || !fbCfg.apiKey){
    console.error('Firebase config missing');
    document.getElementById('lock').innerHTML = '<div style="text-align:center; padding:40px; color:var(--alert);">Firebase config not found</div>';
    return;
  }
  
  try{
    const ready = await Cloud.init(fbCfg);
    if(!ready) throw new Error('Cloud init failed');
  }catch(e){
    console.error('Cloud init failed:', e);
    document.getElementById('lock').innerHTML = '<div style="text-align:center; padding:40px; color:var(--alert);">Firebase init failed</div>';
    return;
  }
  
  console.log('✅ [BOOT] Firebase initialized');
  
  Cloud.onAuthStateChanged(async (user)=>{
    console.log('🔍 [AUTH]', user ? user.email : 'No user');
    
    if(user){
      State.currentUser = user.uid;
      document.getElementById('authScreen').style.display = 'none';
      document.getElementById('lock').style.display = 'flex';
      await initAuthScreen();
    } else {
      document.getElementById('authScreen').style.display = 'flex';
      document.getElementById('lock').style.display = 'none';
      document.getElementById('app').style.display = 'none';
    }
  });
  
  console.log('✅ [BOOT] Boot complete');
})();

/* ===== AUTH BUTTON WIRING ===== */
document.addEventListener('DOMContentLoaded', ()=>{
  console.log('🔌 [DOM] Wiring buttons');
  
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
        registerBtn.textContent = 'Creating...';
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
  
  console.log('✅ [DOM] Buttons wired');
});
