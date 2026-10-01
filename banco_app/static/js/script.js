/*
 * HackerBank - login "passwordless / Windows Hello" (lado del cliente).
 *
 * Ceremonia estilo WebAuthn/Windows Hello en dos pasos:
 *   1) /auth/hello/options  -> challenge (+ user_id)
 *   2) /auth/hello/assert   -> assertion {clientDataJSON, authenticatorData, signature}
 *
 * Cada passkey se genera en el navegador con WebCrypto. La clave PRIVADA se
 * guarda en localStorage (para el laboratorio) bajo `hb_privkey_<usuario>` y la
 * PUBLICA se registra en el servidor. Al servidor solo viajan la clave publica
 * (al registrar) y firmas (al entrar).
 *
 * >>> TEATRO DE WINDOWS HELLO <<<
 * Al loguearse se invoca el PIN REAL de Windows Hello con
 * navigator.credentials.create(), pero su resultado se DESCARTA. La auth real
 * corre con la clave de software de localStorage. El factor fuerte no protege
 * nada: ese es el "mal implementado".
 *
 * >>> NOTA (CTF Hacking Day) <<<
 * Guardar la clave privada en localStorage es el pecado: es accesible por
 * JavaScript, asi que un XSS que corra en el contexto de la victima puede
 * robarla. En Windows Hello real la privada vive en el TPM y JS nunca la toca.
 *
 * Funciones utiles desde la consola (F12):
 *   signChallenge(privB64, mensaje)          -> firma los bytes UTF-8 de `mensaje` (raw r||s hex)
 *   hbSign(privB64, challenge)               -> arma el clientDataJSON y devuelve {clientDataJSON, signature} listos para el /assert
 *   helloForge(username, credentialId, privB64) -> pide options, firma el clientDataJSON y entra
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
// base64url (sin padding) de un string UTF-8. Es como viaja el clientDataJSON.
function strToB64url(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// Arma el clientDataJSON de la assertion (como WebAuthn: type/challenge/origin).
function buildClientDataJSON(challenge) {
  return JSON.stringify({ type: "webauthn.get", challenge: challenge, origin: window.location.origin });
}

// ---------- passkey local ----------
function privStorageKey(username) { return "hb_privkey_" + username; }
// Guardamos TAMBIEN el credential_id propio, para firmar siempre con la pareja
// (privada local <-> su credential_id) y no con la "mas reciente" que devuelva
// el server (que puede ser de otra passkey: otro navegador, solve.py, etc.).
function credStorageKey(username) { return "hb_credid_" + username; }

async function generatePasskey() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  return { credentialId: randomHex(16), privB64: bufToB64(pkcs8), publicPem: spkiToPem(spki) };
}

// Firma los bytes UTF-8 de `message` con una clave privada PKCS8 base64.
// En la ceremonia, `message` es el string del clientDataJSON. Global para consola.
window.signChallenge = async function (privB64, message) {
  const key = await crypto.subtle.importKey(
    "pkcs8", b64ToBytes(privB64), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(message));
  return bufToHex(sig); // raw r||s (64 bytes)
};

// Conveniencia para la consola: pasás SOLO la clave privada y el challenge, y te
// arma el clientDataJSON por dentro. Devuelve (y loguea) los dos valores LISTOS
// para pegar en el body del POST /auth/hello/assert:
//   response.clientDataJSON  y  response.signature
// Uso:  await hbSign("<clave privada>", "<challenge>")
window.hbSign = async function (privB64, challenge) {
  const clientDataJSON = buildClientDataJSON(challenge);
  const out = {
    clientDataJSON: strToB64url(clientDataJSON),
    signature: await window.signChallenge(privB64, clientDataJSON),
  };
  console.log("clientDataJSON:", out.clientDataJSON);
  console.log("signature:", out.signature);
  return out;
};

// TEATRO: invoca el PIN real de Windows Hello (authenticator de plataforma) y
// DESCARTA el resultado. Solo busca el prompt del SO. Si no hay Windows Hello
// (otra plataforma, cancelado, sin soporte) sigue sin romper nada.
async function windowsHelloTheater(username) {
  try {
    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) return;
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "HackerBank", id: window.location.hostname },
        user: {
          id: new TextEncoder().encode(username),
          name: username,
          displayName: username,
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
        timeout: 60000,
        attestation: "none",
      },
    });
    void cred; // <- se descarta a proposito; la auth real va por abajo.
  } catch (e) {
    // NotAllowedError / NotSupportedError / cancelado: el teatro no aparece, seguimos.
  }
}

// Construye y postea la assertion (/auth/hello/assert) firmando el clientDataJSON.
async function assertLogin(username, credentialId, privB64, challenge) {
  const clientDataJSON = buildClientDataJSON(challenge);
  const signature = await window.signChallenge(privB64, clientDataJSON);
  const body = {
    username: username,
    id: credentialId,
    type: "public-key",
    response: {
      clientDataJSON: strToB64url(clientDataJSON),
      authenticatorData: strToB64url("hackerbank-authenticator-data"), // decorativo
      signature: signature,
    },
  };
  return await (await fetch("/auth/hello/assert", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  })).json();
}

// Pide options para `username`, arma el clientDataJSON, lo firma con `privB64` y
// hace el assert con `credentialId`. Si entra, redirige. Para la consola (F12).
window.helloForge = async function (username, credentialId, privB64) {
  const opt = await (await fetch("/auth/hello/options", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  })).json();
  if (!opt.ok) throw new Error(opt.error || "options falló");
  const v = await assertLogin(username, credentialId, privB64, opt.challenge);
  if (v.ok) { window.location.href = v.next; }
  return v;
};

// Registra una passkey NUEVA para `username` (genera el par, manda la pública) y
// la guarda en localStorage (privada + su credential_id). Devuelve {privB64, credentialId}.
async function registerPasskey(username, onStatus) {
  if (onStatus) onStatus("Creando tu passkey en este dispositivo…", "info");
  const pk = await generatePasskey();
  const reg = await (await fetch("/auth/register", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, credential_id: pk.credentialId, public_key: pk.publicPem }),
  })).json();
  if (!reg.ok) throw new Error(reg.error || "No se pudo registrar la passkey.");
  try {
    localStorage.setItem(privStorageKey(username), pk.privB64);
    localStorage.setItem(credStorageKey(username), pk.credentialId);
    localStorage.setItem("hb_current_user", username);
  } catch (e) {}
  return { privB64: pk.privB64, credentialId: pk.credentialId };
}

// ---------- flujo de login legitimo (botón de Windows Hello) ----------
async function helloLogin(username, onStatus) {
  // 1) Teatro: PIN real de Windows Hello (se descarta).
  if (onStatus) onStatus("Confirmá con Windows Hello…", "info");
  await windowsHelloTheater(username);

  // 2) options (trae el challenge y el user_id)
  if (onStatus) onStatus("Verificando tu passkey…", "info");
  const opt = await (await fetch("/auth/hello/options", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  })).json();
  if (!opt.ok) throw new Error(opt.error || "No se pudo iniciar el login.");

  // 3) RECONOCIMIENTO: el cliente consulta su credencial registrada por
  //    /auth/keys/<username>. Es parte legítima del flujo (así el alumno ve ESTE
  //    endpoint en Burp: es la superficie del IDOR de la Capa 2 — basta cambiar
  //    el nombre a 'ceo'). OJO: su resultado NO decide con qué clave firmamos;
  //    eso lo define la passkey LOCAL, para que privada y credential_id sean
  //    siempre la misma pareja.
  try { await fetch(`/auth/keys/${encodeURIComponent(username)}`); } catch (e) {}

  // 4) Mi passkey LOCAL (privada + su propio credential_id).
  let privB64 = null, credentialId = null;
  try {
    privB64 = localStorage.getItem(privStorageKey(username));
    credentialId = localStorage.getItem(credStorageKey(username));
  } catch (e) {}

  // 5) Si tengo passkey local, intento entrar con ella.
  if (privB64 && credentialId) {
    try { localStorage.setItem("hb_current_user", username); } catch (e) {}
    const v = await assertLogin(username, credentialId, privB64, opt.challenge);
    if (v.ok) return v.next;
    // La passkey local quedó obsoleta (base reseteada, otra credencial, etc.):
    // re-registro una nueva en vez de fallar.
  }

  // 6) Registrar una passkey nueva y entrar con ella (reusa el challenge de
  //    options: el server no lo vincula — VULN-3 — así que sigue siendo válido).
  const pk = await registerPasskey(username, onStatus);
  const v2 = await assertLogin(username, pk.credentialId, pk.privB64, opt.challenge);
  if (!v2.ok) throw new Error(v2.error || "No se pudo verificar la firma.");
  return v2.next;
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
    if (!username) { setStatus("Ingresá tu usuario para continuar con Windows Hello.", "error"); return; }
    scanBtn.disabled = true;
    setStatus("Abriendo Windows Hello…", "info");
    try {
      const next = await helloLogin(username, setStatus);
      setStatus("Identidad verificada. Redirigiendo…", "ok");
      window.location.href = next;
    } catch (err) {
      setStatus(err.message, "error");
      scanBtn.disabled = false;
    }
  }
  form.addEventListener("submit", (e) => { e.preventDefault(); run(); });
});
