"""
Configuracion centralizada de HackerBank.
"""
import os

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Flask ---
# En un banco real esto seria un secreto fuerte y fuera del codigo; aca es
# hardcodeado a proposito (entorno de laboratorio efimero que se resetea).
FLASK_SECRET_KEY = os.environ.get("HACKERBANK_SECRET") or "lab-only-insecure-secret-hackertech-cba"

DATABASE_PATH = os.path.join(_BASE_DIR, "hackerbank.db")

# Token compartido SOLO con el contenedor del agente (agente/agent.py). Protege
# los endpoints internos del banco: el de aprovisionamiento de la passkey del
# CEO y el de la cola de visitas del agente. En un lab efimero es un valor fijo;
# en produccion seria un secreto fuerte e inyectado por entorno.
# IMPORTANTE (seguridad del CTF): si este token se filtra ANTES de que el agente
# aprovisione al CEO, alguien podria registrarle una passkey propia y entrar sin
# robar nada. Por eso el endpoint de provision es ademas one-shot (rechaza si el
# CEO ya tiene credencial).
AGENT_TOKEN = os.environ.get("AGENT_TOKEN") or "lab-only-agent-token-hackertech-cba"

# Cada cuanto el agente CEO revisa su bandeja aunque nadie lo "invite" (seg).
AGENT_PERIODIC_SECONDS = int(os.environ.get("AGENT_PERIODIC_SECONDS") or "45")

# URL publica del portal de soporte (otro puerto/sitio) donde esta el boton para
# "pedir que el administrador revise su bandeja". Se muestra como pista en
# /mensajes. Es la URL vista desde el navegador del alumno.
SOPORTE_PUBLIC_URL = os.environ.get("SOPORTE_PUBLIC_URL") or "http://localhost:5001"

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("HACKERBANK_COOKIE_SECURE", "0") == "1"

# --- Clave de sesion ---
SESSION_KEY_USER_ID = "authenticated_user_id"

# --- Cripto del flujo passwordless ---
# Curva P-256 (secp256r1): la MISMA que usa WebAuthn real. El servidor SOLO
# guarda claves publicas; la privada de cada passkey vive del lado del cliente
# (en localStorage, para el laboratorio). Ese es justamente el pecado: en FIDO2
# real la privada vive en hardware inextraible y JavaScript nunca la toca.
CHALLENGE_BYTES = 24              # largo del challenge aleatorio (en bytes)
CHALLENGE_TTL_SECONDS = 300       # ventana de validez del challenge emitido

# --- Ingenieria social (disparo del bot CEO) ---
SOCIAL_NOTIFY_COOLDOWN_SECONDS = 60   # 1 disparo por minuto, como en el Blog de Pepe

# --- Usuario de practica (la cuenta del "atacante") ---
PRACTICE_USERNAME = "t3ny"

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
