const BACKUP_KEY = "hb_backup_key_2026";


// ---------------------------------------------------------------------------
// Helpers base64 / bytes
// ---------------------------------------------------------------------------
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToStr(bytes) {
  return new TextDecoder().decode(bytes);
}

function xorBytes(bytes, keyStr) {
  const key = new TextEncoder().encode(keyStr);
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % key.length];
  return out;
}

function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


// ---------------------------------------------------------------------------
// Decodificacion de la clave privada
// Revierte lo que hace el servidor: base64( XOR( base64(PEM), BACKUP_KEY ) )
// ---------------------------------------------------------------------------
function decodePrivateKey(encoded) {
  const xored = b64ToBytes(encoded);          // deshago el base64 exterior
  const innerB64Bytes = xorBytes(xored, BACKUP_KEY);  // deshago el XOR
  const innerB64 = bytesToStr(innerB64Bytes);    // esto es base64(PEM)
  const pemBytes = b64ToBytes(innerB64);         // deshago el base64 interior
  return bytesToStr(pemBytes);                   // PEM de la clave privada
}


// ---------------------------------------------------------------------------
// Firma ECDSA P-256 del challenge con WebCrypto
// ---------------------------------------------------------------------------
function pemToPkcs8Der(pem) {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  return b64ToBytes(body);
}

async function signChallenge(privatePem, challenge) {
  const der = pemToPkcs8Der(privatePem);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    der,
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
// Flujo completo: challenge -> (bajar y decodificar clave) -> firmar -> verify
// ---------------------------------------------------------------------------
async function passwordlessLogin(username) {
  // 1) Pedir un challenge fresco. La respuesta trae tambien nuestro user_id.
  const chRes = await fetch("/auth/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username }),
  });
  const chData = await chRes.json();
  if (!chData.ok) throw new Error(chData.error || "No se pudo iniciar el login.");

  // 2) Bajar la clave privada "de backup" del usuario y decodificarla.
  const keyRes = await fetch(`/auth/keys/${chData.user_id}`);
  const keyData = await keyRes.json();
  if (!keyData.ok) throw new Error(keyData.error || "No se pudo recuperar la clave.");
  const privatePem = decodePrivateKey(keyData.private_key);

  // 3) Firmar el challenge con la clave privada.
  const signature = await signChallenge(privatePem, chData.challenge);

  // 4) Enviar la firma para que el servidor la verifique con la clave publica.
  const vRes = await fetch("/auth/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, challenge: chData.challenge, signature }),
  });
  const vData = await vRes.json();
  if (!vData.ok) throw new Error(vData.error || "No se pudo verificar la firma.");
  return vData.next;
}


// ---------------------------------------------------------------------------
// Cableado de la UI del login (botones cosmeticos de huella/rostro)
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
    setStatus("Escaneando biometría y firmando el acceso…", "info");
    try {
      const next = await passwordlessLogin(username);
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
