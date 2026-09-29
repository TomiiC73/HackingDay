/*
 * HackerBank - login "passwordless / biometrico" (lado del cliente).
 *
 * Cada passkey se genera en el navegador con WebCrypto. La clave PRIVADA se
 * guarda en localStorage (para el laboratorio) bajo `hb_privkey_<usuario>` y la
 * PUBLICA se registra en el servidor. Al servidor solo viajan la clave publica
 * (al registrar) y firmas del challenge (al entrar).
 *
 * >>> NOTA (CTF Hacking Day) <<<
 * Guardar la clave privada en localStorage es el pecado: es accesible por
 * JavaScript, asi que un XSS que corra en el contexto de la victima puede
 * robarla. En FIDO2 real la privada vive en el TPM y JS nunca la toca.
 *
 * Funciones utiles desde la consola (F12):
 *   signChallenge(privB64, challenge)   -> firma un challenge (raw r||s hex)
 *   hbForge(username, credentialId, privB64) -> pide challenge, firma y entra
 */

// ---------- helpers ----------
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function bufToB64(buffer) { return btoa(String.fromCharCode(...new Uint8Array(buffer))); }
function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randomHex(n) {
  const a = new Uint8Array(n); crypto.getRandomValues(a);
  return Array.from(a).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function spkiToPem(spki) {
  const lines = bufToB64(spki).match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

// ---------- passkey local ----------
function privStorageKey(username) { return "hb_privkey_" + username; }

async function generatePasskey() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  return { credentialId: randomHex(16), privB64: bufToB64(pkcs8), publicPem: spkiToPem(spki) };
}

// Firma un challenge con una clave privada PKCS8 base64. Global: usable en consola.
window.signChallenge = async function (privB64, challenge) {
  const key = await crypto.subtle.importKey(
    "pkcs8", b64ToBytes(privB64), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(challenge));
  return bufToHex(sig); // raw r||s (64 bytes)
};

// Pide un challenge para `username`, lo firma con `privB64` y verifica con
// `credentialId`. Si entra, redirige. Pensada para usar desde la consola (F12).
window.hbForge = async function (username, credentialId, privB64) {
  const ch = (await (await fetch("/auth/challenge", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  })).json());
  if (!ch.ok) throw new Error(ch.error || "challenge falló");
  const signature = await window.signChallenge(privB64, ch.challenge);
  const v = await (await fetch("/auth/verify", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, credential_id: credentialId, challenge: ch.challenge, signature }),
  })).json();
  if (v.ok) { window.location.href = v.next; }
  return v;
};

// ---------- flujo de login legitimo (botón de huella) ----------
async function passwordlessLogin(username, onStatus) {
  if (onStatus) onStatus("Verificando tu passkey…", "info");

  // 1) challenge (trae el user_id)
  const ch = await (await fetch("/auth/challenge", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  })).json();
  if (!ch.ok) throw new Error(ch.error || "No se pudo iniciar el login.");

  // 2) mi credential_id (el servidor lo tiene si ya registré)
  const keys = await (await fetch(`/auth/keys/${ch.user_id}`)).json();
  let privB64 = null;
  try { privB64 = localStorage.getItem(privStorageKey(username)); } catch (e) {}
  let credentialId = keys.ok ? keys.credential_id : null;

  // 3) si no tengo passkey local o el server no tiene mi credencial: registrar
  if (!privB64 || !credentialId) {
    if (onStatus) onStatus("Creando tu passkey en este dispositivo…", "info");
    const pk = await generatePasskey();
    const reg = await (await fetch("/auth/register", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, credential_id: pk.credentialId, public_key: pk.publicPem }),
    })).json();
    if (!reg.ok) throw new Error(reg.error || "No se pudo registrar la passkey.");
    privB64 = pk.privB64;
    credentialId = pk.credentialId;
    try {
      localStorage.setItem(privStorageKey(username), privB64);
      localStorage.setItem("hb_current_user", username);
    } catch (e) {}
  } else {
    try { localStorage.setItem("hb_current_user", username); } catch (e) {}
  }

  // 4) firmar y verificar
  const signature = await window.signChallenge(privB64, ch.challenge);
  const v = await (await fetch("/auth/verify", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, credential_id: credentialId, challenge: ch.challenge, signature }),
  })).json();
  if (!v.ok) throw new Error(v.error || "No se pudo verificar la firma.");
  return v.next;
}

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("passwordless-form");
  if (!form) return;
  const usernameInput = document.getElementById("username");
  const statusBox = document.getElementById("login-status");
  const scanBtn = document.getElementById("scan-btn");

  function setStatus(message, kind) { statusBox.textContent = message; statusBox.dataset.kind = kind || "info"; }

  async function run() {
    const username = (usernameInput.value || "").trim().toLowerCase();
    if (!username) { setStatus("Ingresá tu usuario para escanear tu biometría.", "error"); return; }
    scanBtn.disabled = true;
    setStatus("Escaneando biometría…", "info");
    try {
      const next = await passwordlessLogin(username, setStatus);
      setStatus("Identidad verificada. Redirigiendo…", "ok");
      window.location.href = next;
    } catch (err) {
      setStatus(err.message, "error");
      scanBtn.disabled = false;
    }
  }
  form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
});
