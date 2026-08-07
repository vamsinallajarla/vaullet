/**
 * Vaullet — Google Drive credentials
 * -----------------------------------------------------------------
 * Keep this file OUT of source control (add "google_config.js" to
 * your .gitignore). It is loaded by index.html before script.js.
 *
 * Setup (Google Cloud Console — console.cloud.google.com):
 *   1. Create or select a project.
 *   2. APIs & Services → Library → enable "Google Drive API".
 *   3. APIs & Services → OAuth consent screen → configure it
 *      (External is fine for personal use; add yourself as a test
 *      user if it stays in "Testing" status).
 *   4. APIs & Services → Credentials → Create Credentials →
 *      OAuth client ID → Application type: "Web application".
 *   5. Under "Authorized JavaScript origins", add the exact URL
 *      you'll open Vaullet from, e.g. http://localhost:3000
 *      (must be http://localhost or https:// — not file://).
 *   6. Copy the Client ID it generates and paste it below.
 *
 * Leave clientId as an empty string to disable Drive integration —
 * attachments then fall back to inline storage (subject to
 * Firestore's 1MB document cap for cloud sync).
 */
window.VAULLET_GOOGLE_CONFIG = {
  clientId: "840290523953-u9jdtr6m7hqqebogn50iit029qpuc868.apps.googleusercontent.com"
};