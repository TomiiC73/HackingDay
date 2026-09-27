/*
 * HackerBank - login "passwordless / biometrico" (lado del cliente).
 *
 * A diferencia de una versión anterior, acá NO se baja ninguna clave privada
 * del servidor. Cada passkey se genera en el navegador con WebCrypto y su
 * clave privada se queda del lado del cliente (la simulamos guardándola en
 * localStorage). Al servidor solo viaja la clave PÚBLICA (al registrar) y una
 * firma del challenge (al entrar) — igual que en FIDO2/WebAuthn real.
 *
 * >>> NOTA PARA QUIEN AUDITA ESTE CODIGO (CTF Hacking Day) <<<
 * El agujero no está acá: está en el servidor. En /auth/verify el backend NO
 * comprueba que la credencial que firma pertenezca al usuario que se reclama
 * (falta de binding credencial->usuario). Con una passkey propia, registrada
 * en tu cuenta, se puede firmar el challenge del CEO y entrar como el CEO.
 */

// ---------------------------------------------------------------------------
// Helpers base64 / bytes
// ---------------------------------------------------------------------------
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bufToB64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(nBytes) {
  const a = new Uint8Array(nBytes);
  crypto.getRandomValues(a);
  return Array.from(a).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function spkiToPem(spki) {
  const b64 = bufToB64(spki);
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}


// ---------------------------------------------------------------------------
// Passkey local (simulación de un autenticador de plataforma)
// La privada se guarda en localStorage. En FIDO2 real viviría en el TPM y
// jamás sería exportable; acá es una simulación para el laboratorio.
// ---------------------------------------------------------------------------
function passkeyStorageKey(username) {
  return "hb_passkey_" + username;
}

function loadPasskey(username) {
  try {
    const raw = localStorage.getItem(passkeyStorageKey(username));
    return raw ? JSON.parse(raw) : null;
  } catch (e) {
    return null;
  }
}

function savePasskey(username, data) {
  try {
    localStorage.setItem(passkeyStorageKey(username), JSON.stringify(data));
  } catch (e) {
    /* modo privado: seguimos con la passkey en memoria de esta carga */
  }
}

async function generatePasskey() {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  return {
    credentialId: randomHex(16),
    privB64: bufToB64(pkcs8),      // clave privada (se queda del lado del cliente)
    publicPem: spkiToPem(spki),    // clave pública (lo único que se registra)
  };
}

async function signChallenge(privB64, challenge) {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    b64ToBytes(privB64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  // WebCrypto devuelve la firma en formato raw r||s (64 bytes), no DER.
  const sigBuf = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    new TextEncoder().encode(challenge)
  );
  return bufToHex(sigBuf);
}


// ---------------------------------------------------------------------------
// Flujo: (registrar passkey si no hay) -> challenge -> firmar -> verify
// ---------------------------------------------------------------------------
async function passwordlessLogin(username, onStatus) {
  let pk = loadPasskey(username);

  // 1) Si esta cuenta todavía no tiene passkey en este dispositivo, registrarla.
  if (!pk) {
    if (onStatus) onStatus("Creando tu passkey en este dispositivo…", "info");
    pk = await generatePasskey();
    const regRes = await fetch("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        credential_id: pk.credentialId,
        public_key: pk.publicPem,
      }),
    });
    const regData = await regRes.json();
    if (!regData.ok) throw new Error(regData.error || "No se pudo registrar la passkey.");
    savePasskey(username, pk);
  }

  // 2) Pedir un challenge fresco.
  if (onStatus) onStatus("Verificando tu biometría…", "info");
  const chRes = await fetch("/auth/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  });
  const chData = await chRes.json();
  if (!chData.ok) throw new Error(chData.error || "No se pudo iniciar el login.");

  // 3) Firmar el challenge con la clave privada local.
  const signature = await signChallenge(pk.privB64, chData.challenge);

  // 4) Enviar la firma (con el credential_id) para que el servidor la verifique.
  const vRes = await fetch("/auth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      credential_id: pk.credentialId,
      challenge: chData.challenge,
      signature,
    }),
  });
  const vData = await vRes.json();
  if (!vData.ok) throw new Error(vData.error || "No se pudo verificar la firma.");
  return vData.next;
}


// ---------------------------------------------------------------------------
// Cableado de la UI del login (botón cosmético de huella/rostro)
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("passwordless-form");
  if (!form) return;

  const usernameInput = document.getElementById("username");
  const statusBox = document.getElementById("login-status");
  const scanBtn = document.getElementById("scan-btn");

  function setStatus(message, kind) {
    statusBox.textContent = message;
    statusBox.dataset.kind = kind || "info";
  }

  async function run() {
    const username = (usernameInput.value || "").trim().toLowerCase();
    if (!username) {
      setStatus("Ingresá tu usuario para escanear tu biometría.", "error");
      return;
    }
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

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    run();
  });
});
