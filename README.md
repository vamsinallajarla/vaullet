# Vaultkeep — Digital Document & Card Vault

A privacy-first personal vault for IDs, cards, insurance, vehicle, education,
employment, medical, and tax documents. Single-file web app (`index.html`) —
open it directly in a browser, no build step required.

## Quick start
1. Open `index.html`.
2. First run: set a 4–6 digit PIN. This derives your master encryption key —
   the PIN itself is never stored anywhere.
3. Optionally enable biometric unlock (Face ID / fingerprint) if your device/
   browser supports WebAuthn platform authenticators.
4. Start adding documents and cards. Everything is encrypted in your browser
   before it touches disk or the network.

## Connecting Firebase Firestore (optional cloud sync)
Go to **Settings → Cloud sync** and paste your Firebase web config:
```json
{ "apiKey": "...", "authDomain": "...", "projectId": "...", "appId": "..." }
```
The app signs in anonymously and syncs to `vaults/{uid}/items/{itemId}`.
**Only ciphertext and non-sensitive metadata (category, type, timestamps)
are written to Firestore.** Document names, numbers, notes, and attachments
are encrypted client-side with AES-256-GCM before upload; Firestore/Google
never sees plaintext.

### Required Firestore security rules
Set these in the Firebase console so a user's vault is only readable by that
same anonymous session/uid:
```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /vaults/{uid}/items/{itemId} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
  }
}
```
Note: anonymous Firebase auth ties data to a browser/device session. For
real multi-device use, upgrade to Firebase email/phone auth so the same uid
persists across devices and the master key can be re-derived from the same
PIN on each one.

## Security model (what's implemented and why)
- **Key derivation:** PBKDF2-SHA256, 210,000 iterations, random 16-byte salt
  per vault. The PIN is never persisted — only the salt and a one-way
  verifier hash (used to check unlock attempts) are stored locally.
- **Encryption:** AES-256-GCM, random 12-byte IV per record. Every document
  field set and attachment is encrypted as one JSON blob per item.
- **At rest:** Local cache is IndexedDB, storing ciphertext only.
- **In transit:** Firestore traffic is TLS; payloads are already ciphertext
  before they leave the browser (defense in depth).
- **Masking:** Card/ID numbers are masked by default everywhere in the UI
  (`XXXX XXXX XXXX 4582`). Revealing requires PIN re-entry (re-authentication
  modal), and the reveal auto-re-masks after 8 seconds.
- **Auto-lock:** Vault re-locks after 2 minutes of inactivity, clearing the
  in-memory master key and decrypted document cache.
- **Biometrics:** WebAuthn platform authenticator can be registered as a
  faster unlock gesture. Underlying decryption still depends on the PIN-
  derived key — biometrics do not replace or weaken the encryption key.
- **No plaintext logs:** the app never `console.log`s PIN, decrypted
  content, or key material.

## Known limitations of this web prototype
- **Push notifications:** expiry reminders are computed and shown in-app
  (Alerts tab) but a browser can't reliably deliver OS-level push
  notifications when closed. A native Android/iOS build (React Native,
  sharing the same `Crypto`/`LocalDB` logic) is needed for real background
  reminders — the architecture is already modular to support that.
  Screenshot/screen-recording prevention is likewise an OS-level capability
  only available in native apps (`FLAG_SECURE` on Android, screen capture
  protection on iOS), not in a browser tab.
- **Biometric unlock UX:** WebAuthn confirms *device presence*, not key
  release — a full native build can wrap the derived key in the platform
  Keystore/Secure Enclave for biometric-gated decryption without a PIN
  fallback prompt each time.
- **Anonymous Firebase auth** ties a vault to one browser/device by default;
  see the note above for multi-device sync.
- This is a self-contained demo you fully control — review the encryption
  and auth code in `index.html` (`Crypto`, `LocalDB`, `Cloud`, `Bio`
  modules) before trusting it with real sensitive documents in production use.

## Suggested next steps toward the full spec
- Port `Crypto`/`LocalDB`/`Cloud` modules into a React Native app for
  Android/iOS with OS keystore-backed key wrapping and real push
  notifications.
- Add per-field encryption (rather than whole-record) if you need to query
  on non-sensitive fields server-side.
- Add rate-limiting/lockout after repeated failed PIN attempts.
- Add scheduled Cloud Functions to email/push expiry reminders using only
  encrypted metadata timestamps (never plaintext document content).
