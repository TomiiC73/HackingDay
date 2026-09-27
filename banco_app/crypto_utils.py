"""
Utilidades criptograficas del CTF passwordless.

Del lado del servidor solo se necesita:
  - Generacion de un par de claves ECDSA P-256 (usado por seed.py para
    aprovisionar la credencial pre-cargada del CEO; la privada se descarta).
  - Verificacion de la firma de un challenge con una clave PUBLICA.

NOTA PEDAGOGICA: como en FIDO2/WebAuthn real, el servidor SOLO guarda claves
publicas. La clave privada de cada credencial vive del lado del cliente y nunca
viaja al servidor. La vulnerabilidad del desafio no es una clave robable: es
que /auth/verify no comprueba que la credencial que firma pertenezca al usuario
que se reclama (falta de binding credencial->usuario).

Formato de firma en el "cable": raw r||s de 64 bytes (32 + 32), en hex. Es el
formato que produce WebCrypto (crypto.subtle.sign) en el navegador. El servidor
lo convierte a DER para verificar con la libreria `cryptography`.
"""
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature


# --------------------------------------------------------------------
# Generacion de claves / credenciales (usado por seed.py)
# --------------------------------------------------------------------
def generate_keypair_pem():
    """Genera un par ECDSA P-256 y lo devuelve como (priv_pem, pub_pem) str.

    seed.py lo usa para aprovisionar la credencial del CEO: guarda solo la
    publica y descarta la privada (igual que un servidor FIDO2 real, que nunca
    llega a ver la privada).
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


def generate_credential_id() -> str:
    """Un id de credencial opaco (hex), analogo al credential_id de WebAuthn."""
    return secrets.token_hex(16)


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
