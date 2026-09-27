"""
Configuracion centralizada del CTF "Passwordless de Carton" (HackerBank).

IMPORTANTE - ENTORNO EDUCATIVO: este es un desafio de ciberseguridad (CTF)
para el Hacking Day de Cordoba. La app imita un login passwordless/FIDO2 pero
esta ROTA A PROPOSITO para ensenar, por contraste, como funciona FIDO2 real.
Todos los datos (CEO, cuentas, codigo ganador) son ficticios. No procesa dinero
real ni esta conectada a ningun sistema bancario.
"""
import os

# --- Flask ---
# En un banco real esto seria un secreto fuerte y fuera del codigo; aca es
# hardcodeado a proposito (entorno de laboratorio efimero que se resetea).
FLASK_SECRET_KEY = os.environ.get("HACKERBANK_SECRET") or "lab-only-insecure-secret-hackertech-cba"

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hackerbank.db")

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("HACKERBANK_COOKIE_SECURE", "0") == "1"

# --- Clave de sesion ---
SESSION_KEY_USER_ID = "authenticated_user_id"

# --- Cripto del flujo passwordless ---
# Curva P-256 (secp256r1): la MISMA que usa WebAuthn real. El servidor SOLO
# guarda claves publicas (como FIDO2 real): la privada de cada credencial se
# genera y vive del lado del cliente y nunca viaja. La vulnerabilidad del
# desafio NO es una clave robable, sino que el servidor no valida el BINDING
# entre la credencial firmante y el usuario que dice ser (ver app.py).
CHALLENGE_BYTES = 24              # largo del challenge aleatorio (en bytes)
CHALLENGE_TTL_SECONDS = 300       # ventana de validez del challenge emitido

# --- Datos de presentacion del banco (landing) ---
PUBLIC_USD_BUY = 1180.50
PUBLIC_USD_SELL = 1220.50
PUBLIC_EUR_BUY = 1275.00
PUBLIC_EUR_SELL = 1325.00
PUBLIC_LOAN_MAX_ARS = 5000000.00
PUBLIC_LOAN_TNA_PERCENT = 45
PUBLIC_FIXED_DEPOSIT_TNA_PERCENT = 38
PUBLIC_FIXED_DEPOSIT_MIN_DAYS = 30
PUBLIC_CREDIT_CARD_TNA_PERCENT = 62

BANK_BRANCH_LABEL = "Sucursal Centro — Córdoba (031)"
ACCOUNT_TYPE_LABEL = "Caja de ahorro en pesos"
BANK_BIC = "HKBKARBA"

PUBLIC_SUPPORT_PHONE = "0800-555-4225"
PUBLIC_SUPPORT_HOURS = "Lunes a viernes de 8 a 20 hs · Sábados de 9 a 13 hs"

PUBLIC_BRANCHES = [
    {"name": "Sucursal Centro", "address": "Av. Colón 145, Córdoba"},
    {"name": "Sucursal Nueva Córdoba", "address": "Bv. Illia 355, Córdoba"},
    {"name": "Sucursal Güemes", "address": "Belgrano 620, Córdoba"},
]
