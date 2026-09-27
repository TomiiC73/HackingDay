"""
HackerBank - CTF "Passwordless de Carton" (Hacking Day Cordoba).

Banco ficticio que promociona un login "passwordless / biometrico, seguro como
una passkey", pero cuya implementacion imita a FIDO2/WebAuthn SIN entenderlo.
El objetivo pedagogico es que el alumno rompa esta version trucha y, por
contraste, entienda que garantiza FIDO2 real.

Como en FIDO2 real, el servidor SOLO guarda claves publicas: la clave privada
de cada passkey vive del lado del cliente y nunca viaja. No hay ninguna clave
que robar. La (unica) VULNERABILIDAD INTENCIONAL es de AUTORIZACION:

  VULN (binding credencial->usuario): en /auth/verify el servidor comprueba que
       la firma sea valida para la clave publica de la credencial presentada,
       pero NO comprueba que esa credencial pertenezca al usuario que se
       reclama. Resultado: un atacante registra su propia passkey (en una
       cuenta cualquiera) y la usa para firmar el challenge del CEO -> el
       servidor lo deja entrar como el CEO. En FIDO2 real el servidor SIEMPRE
       verifica la firma contra las credenciales registradas de ESE usuario
       (allowCredentials), no contra cualquier credencial valida.

Todo es ficticio y con fines educativos. No maneja dinero real.
"""
import secrets
import time

from flask import (Flask, jsonify, redirect, render_template, request,
                   session, url_for)

import config
import crypto_utils
import db

SERVER_PORT = 5000

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.FLASK_SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=config.SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
)

db.init_db()


def _format_currency(amount):
    """Formatea con separador de miles '.' y decimales ',' (es-AR)."""
    formatted = f"{abs(amount):,.2f}".replace(",", "_").replace(".", ",").replace("_", ".")
    return f"-{formatted}" if amount < 0 else formatted


app.jinja_env.filters["currency"] = _format_currency


# --------------------------------------------------------------------
# Almacen efimero de challenges emitidos, en memoria: {username: (challenge, expiry_ts)}.
# Un banco real usaria algo distribuido; para una instancia de CTF alcanza.
# --------------------------------------------------------------------
_ISSUED_CHALLENGES = {}


def _issue_challenge(username):
    challenge = secrets.token_urlsafe(config.CHALLENGE_BYTES)
    _ISSUED_CHALLENGES[username] = (challenge, time.time() + config.CHALLENGE_TTL_SECONDS)
    return challenge


def _consume_challenge(username, challenge):
    """Devuelve True si `challenge` es el vigente (no expirado) para `username`
    y lo invalida (un solo uso)."""
    stored = _ISSUED_CHALLENGES.get(username)
    if not stored:
        return False
    value, expiry = stored
    if time.time() > expiry:
        _ISSUED_CHALLENGES.pop(username, None)
        return False
    if not secrets.compare_digest(value, challenge):
        return False
    _ISSUED_CHALLENGES.pop(username, None)   # un solo uso
    return True


def _current_user():
    user_id = session.get(config.SESSION_KEY_USER_ID)
    return db.get_user_by_id(user_id) if user_id else None


def _account_view(user):
    cbu = user["cbu"]
    account_number = f"{cbu[3:7]} / {cbu[8:]}" if len(cbu) >= 12 else cbu
    return {
        "account_number": account_number,
        "account_type": config.ACCOUNT_TYPE_LABEL,
        "branch": config.BANK_BRANCH_LABEL,
        "bic": config.BANK_BIC,
        "status": "Activa",
    }


# --------------------------------------------------------------------
# Paginas
# --------------------------------------------------------------------
@app.route("/")
def landing():
    return render_template(
        "landing.html",
        usd_buy=config.PUBLIC_USD_BUY,
        usd_sell=config.PUBLIC_USD_SELL,
        eur_buy=config.PUBLIC_EUR_BUY,
        eur_sell=config.PUBLIC_EUR_SELL,
        loan_max_ars=config.PUBLIC_LOAN_MAX_ARS,
        loan_tna=config.PUBLIC_LOAN_TNA_PERCENT,
        fixed_deposit_tna=config.PUBLIC_FIXED_DEPOSIT_TNA_PERCENT,
        fixed_deposit_min_days=config.PUBLIC_FIXED_DEPOSIT_MIN_DAYS,
        credit_card_tna=config.PUBLIC_CREDIT_CARD_TNA_PERCENT,
        support_phone=config.PUBLIC_SUPPORT_PHONE,
        support_hours=config.PUBLIC_SUPPORT_HOURS,
        branches=config.PUBLIC_BRANCHES,
    )


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    user = _current_user()
    if not user:
        return redirect(url_for("login_page"))
    return render_template(
        "dashboard.html",
        user=user,
        account=_account_view(user),
        is_ceo=(user["role"] == "ceo"),
        winning_code=user["winning_code"],
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# --------------------------------------------------------------------
# API del flujo passwordless
# --------------------------------------------------------------------
@app.route("/auth/register", methods=["POST"])
def auth_register():
    """Registra una passkey nueva para un usuario: guarda SOLO su clave publica
    (la privada nunca llega al servidor, la genera y conserva el cliente).

    El auto-registro esta habilitado por cuenta (passkey_registration_open). El
    CEO lo tiene deshabilitado (su passkey la aprovisiona IT), asi nadie puede
    simplemente registrarle una passkey nueva y entrar: el atacante tiene que
    registrar la suya en otra cuenta y explotar la falta de binding en verify.
    """
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()
    credential_id = (payload.get("credential_id") or "").strip()
    public_key = payload.get("public_key") or ""

    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="Usuario inexistente."), 404
    if not user["passkey_registration_open"]:
        return jsonify(ok=False, error="El registro de passkeys está deshabilitado para esta cuenta."), 403
    if not credential_id or not public_key:
        return jsonify(ok=False, error="Faltan datos de la credencial."), 400

    # Validar que la clave publica tenga formato PEM valido (entrada de red).
    from cryptography.hazmat.primitives import serialization
    try:
        serialization.load_pem_public_key(public_key.encode("ascii"))
    except (ValueError, TypeError):
        return jsonify(ok=False, error="Clave pública inválida."), 400

    try:
        db.add_credential(credential_id, user["id"], public_key)
    except Exception:
        return jsonify(ok=False, error="No se pudo registrar la credencial (¿id repetido?)."), 409

    return jsonify(ok=True, credential_id=credential_id)


@app.route("/auth/challenge", methods=["POST"])
def auth_challenge():
    """Emite un challenge aleatorio para un usuario y le dice al cliente que
    credenciales (allowCredentials) tiene registradas ese usuario.

    Un cliente honesto usaria allowCredentials para firmar solo con una
    credencial de ese usuario. El atacante lo ignora: esa es la gracia.
    """
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()

    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="Usuario inexistente."), 404

    challenge = _issue_challenge(username)
    return jsonify(
        ok=True,
        username=username,
        challenge=challenge,
        allow_credentials=db.get_credential_ids_for_user(user["id"]),
    )


@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    """Verifica la firma del challenge e inicia sesion.

    VULN (binding credencial->usuario): se verifica que la firma sea valida
    para la clave publica de la credencial presentada, pero NO se comprueba que
    esa credencial pertenezca al `username` que se reclama. Falta, a proposito,
    el chequeo:

        if credential["user_id"] != user["id"]: rechazar

    Sin ese chequeo, cualquiera con una passkey valida (registrada en su propia
    cuenta) puede firmar el challenge del CEO y entrar como el CEO.
    """
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()
    credential_id = (payload.get("credential_id") or "").strip()
    challenge = payload.get("challenge") or ""
    signature_hex = payload.get("signature") or ""

    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="Usuario inexistente."), 404

    if not _consume_challenge(username, challenge):
        return jsonify(ok=False, error="Challenge inválido, vencido o ya usado. Pedí uno nuevo."), 400

    credential = db.get_credential(credential_id)
    if credential is None:
        return jsonify(ok=False, error="Credencial desconocida."), 401

    if not crypto_utils.verify_signature(credential["public_key_pem"], challenge, signature_hex):
        return jsonify(ok=False, error="Firma inválida."), 401

    # <-- VULN: aca faltaria comprobar que `credential` pertenezca a `user`
    #     (credential["user_id"] == user["id"]) y/o que credential_id este en
    #     allowCredentials del usuario. Al no hacerlo, se acepta la passkey de
    #     cualquiera como si fuera la del usuario reclamado.

    session.clear()
    session[config.SESSION_KEY_USER_ID] = user["id"]
    return jsonify(ok=True, next=url_for("dashboard"))


if __name__ == "__main__":
    print(f"HackerBank (CTF passwordless) disponible en: http://localhost:{SERVER_PORT}")
    app.run(debug=True, host="0.0.0.0", port=SERVER_PORT)
