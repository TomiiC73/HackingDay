"""
Utilidades criptograficas del CTF passwordless.

Implementa, del lado del servidor:
  - Generacion de un par de claves ECDSA P-256 (secp256r1) por usuario.
  - "Ofuscacion" (NO cifrado) de la clave privada para guardarla en la base.
  - Verificacion de la firma de un challenge con la clave publica.

NOTA PEDAGOGICA: en FIDO2/WebAuthn real el servidor SOLO guarda claves
publicas y la privada vive en hardware inextraible (TPM/Secure Enclave). Aca,
a proposito, el servidor genera y guarda la clave PRIVADA (ofuscada) y ademas
la expone por un endpoint (ver app.py -> /auth/keys/<user_id>). Ese es el
pecado capital que el desafio ensena a explotar.

Formato de firma en el "cable": raw r||s de 64 bytes (32 + 32), en hex. Es el
formato que produce WebCrypto (crypto.subtle.sign) en el navegador. El
servidor lo convierte a DER para verificar con la libreria `cryptography`.
"""
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

import config


# --------------------------------------------------------------------
# Generacion de claves (usado por seed.py)
# --------------------------------------------------------------------
def generate_keypair_pem():
    """Genera un par ECDSA P-256 y lo devuelve como (priv_pem, pub_pem) str.

    - priv: PKCS8 PEM sin cifrar (asi el navegador puede importarla con
      WebCrypto en formato 'pkcs8' sin pedir passphrase).
    - pub: SubjectPublicKeyInfo PEM.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


# --------------------------------------------------------------------
# "Ofuscacion" de la clave privada (VULNERABILIDAD INTENCIONAL, Capa 2)
# --------------------------------------------------------------------
def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR de `data` contra `key` repetida ciclicamente."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def obfuscate_private_key(priv_pem: str) -> str:
    """Aplica base64( XOR( base64(PEM), OBFUSCATION_KEY ) ).

    Este es el "esquema" que el desarrollador junior creyo seguro. La misma
    OBFUSCATION_KEY esta visible en el JS del frontend, asi que es reversible
    por cualquiera. Ofuscar no es cifrar.
    """
    key = config.OBFUSCATION_KEY.encode("ascii")
    inner_b64 = base64.b64encode(priv_pem.encode("ascii"))   # base64(PEM)
    xored = _xor_bytes(inner_b64, key)                        # XOR con la key
    return base64.b64encode(xored).decode("ascii")           # base64 exterior


def deobfuscate_private_key(obfuscated: str) -> str:
    """Revierte obfuscate_private_key(). Se incluye para tests/demo del server;
    el alumno reimplementa esta misma logica leyendo el JS del frontend."""
    key = config.OBFUSCATION_KEY.encode("ascii")
    xored = base64.b64decode(obfuscated)
    inner_b64 = _xor_bytes(xored, key)
    return base64.b64decode(inner_b64).decode("ascii")


# --------------------------------------------------------------------
# Verificacion de la firma del challenge (usado por /auth/verify)
# --------------------------------------------------------------------
def _raw_sig_to_der(signature_raw: bytes) -> bytes:
    """Convierte una firma raw r||s (64 bytes, formato WebCrypto) a DER, que es
    lo que espera `cryptography` para verificar."""
    if len(signature_raw) != 64:
        raise ValueError("La firma raw debe tener exactamente 64 bytes (r||s).")
    r = int.from_bytes(signature_raw[:32], "big")
    s = int.from_bytes(signature_raw[32:], "big")
    return encode_dss_signature(r, s)


def verify_signature(pub_pem: str, challenge: str, signature_hex: str) -> bool:
    """Verifica que `signature_hex` sea una firma ECDSA-SHA256 valida del
    `challenge` (sus bytes UTF-8) hecha con la clave privada correspondiente a
    `pub_pem`. La firma llega como hex de raw r||s (64 bytes)."""
    try:
        public_key = serialization.load_pem_public_key(pub_pem.encode("ascii"))
        signature_der = _raw_sig_to_der(bytes.fromhex(signature_hex))
        public_key.verify(
            signature_der,
            challenge.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
