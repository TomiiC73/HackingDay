"""
Utilidades criptograficas del CTF passwordless.

El servidor SOLO necesita:
  - Generar un par ECDSA P-256 (para aprovisionar la passkey del CEO en el
    seed; la privada se le pasa al bot headless y nunca se expone por la web).
  - Verificar la firma de un challenge contra una clave PUBLICA.

La clave privada, del lado del cliente, se maneja en formato PKCS8 base64 (lo
que produce WebCrypto: exportKey('pkcs8') -> base64). Se guarda asi en
localStorage y es lo que el XSS termina robando.

Formato de firma en el "cable": raw r||s de 64 bytes (32 + 32) en hex (formato
WebCrypto). El servidor lo convierte a DER para verificar con `cryptography`.
"""
import base64
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature


def generate_credential():
    """Genera un par ECDSA P-256. Devuelve (priv_pkcs8_b64, pub_pem):
    - priv_pkcs8_b64: la privada en PKCS8 DER base64 (idéntico a lo que
      exporta WebCrypto en el navegador).
    - pub_pem: la publica en PEM (lo unico que guarda el servidor).
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_der = priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return base64.b64encode(priv_der).decode("ascii"), pub_pem


def generate_credential_id() -> str:
    """Un id de credencial opaco (hex), analogo al credential_id de WebAuthn."""
    return secrets.token_hex(16)


def _raw_sig_to_der(signature_raw: bytes) -> bytes:
    if len(signature_raw) != 64:
        raise ValueError("La firma raw debe tener exactamente 64 bytes (r||s).")
    r = int.from_bytes(signature_raw[:32], "big")
    s = int.from_bytes(signature_raw[32:], "big")
    return encode_dss_signature(r, s)


def verify_signature(pub_pem: str, challenge: str, signature_hex: str) -> bool:
    """True si `signature_hex` (hex de raw r||s, 64 bytes) es una firma
    ECDSA-SHA256 valida del `challenge` para la clave publica `pub_pem`."""
    try:
        public_key = serialization.load_pem_public_key(pub_pem.encode("ascii"))
        signature_der = _raw_sig_to_der(bytes.fromhex(signature_hex))
        public_key.verify(signature_der, challenge.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
