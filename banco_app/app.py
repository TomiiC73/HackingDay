"""
HackerBank - CTF "Passwordless de Carton" (Hacking Day Cordoba).

Banco ficticio passwordless. Como en FIDO2 real, el servidor SOLO guarda claves
publicas; la privada de cada passkey vive del lado del cliente (en localStorage).
El desafio encadena un IDOR (filtra el credential_id del CEO) y un Stored XSS
(el inbox del CEO renderiza mensajes sin sanitizar; un bot CEO los ve y un
payload roba su clave privada de localStorage).

VULN-1 (IDOR): GET /auth/keys/<user_id> devuelve la credencial de cualquiera.
VULN-2 (Stored XSS): GET /inbox no sanitiza los mensajes.

El pecado de fondo que ensena FIDO2: guardar la clave privada donde JavaScript
la alcanza (localStorage) la hace robable por XSS. En FIDO2 real vive en el TPM
y JS nunca la toca. Todo es ficticio y educativo.
"""
import secrets
import time
from functools import wraps

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
    formatted = f"{abs(amount):,.2f}".replace(",", "_").replace(".", ",").replace("_", ".")
    return f"-{formatted}" if amount < 0 else formatted


app.jinja_env.filters["currency"] = _format_currency

_ISSUED_CHALLENGES = {}


def _issue_challenge(username):
    challenge = secrets.token_urlsafe(config.CHALLENGE_BYTES)
    _ISSUED_CHALLENGES[username] = (challenge, time.time() + config.CHALLENGE_TTL_SECONDS)
    return challenge


def _consume_challenge(username, challenge):
    stored = _ISSUED_CHALLENGES.get(username)
    if not stored:
        return False
    value, expiry = stored
    if time.time() > expiry:
        _ISSUED_CHALLENGES.pop(username, None)
        return False
    if not secrets.compare_digest(value, challenge):
        return False
    _ISSUED_CHALLENGES.pop(username, None)
    return True


def _current_user():
    user_id = session.get(config.SESSION_KEY_USER_ID)
    return db.get_user_by_id(user_id) if user_id else None


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if _current_user() is None:
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


def _account_view(user):
    cbu = user["cbu"]
    account_number = f"{cbu[3:7]} / {cbu[8:]}" if len(cbu) >= 12 else cbu
    return {"account_number": account_number, "account_type": config.ACCOUNT_TYPE_LABEL,
            "branch": config.BANK_BRANCH_LABEL, "bic": config.BANK_BIC, "status": "Activa"}


@app.route("/")
def landing():
    return render_template(
        "landing.html",
        usd_buy=config.PUBLIC_USD_BUY, usd_sell=config.PUBLIC_USD_SELL,
        eur_buy=config.PUBLIC_EUR_BUY, eur_sell=config.PUBLIC_EUR_SELL,
        loan_max_ars=config.PUBLIC_LOAN_MAX_ARS, loan_tna=config.PUBLIC_LOAN_TNA_PERCENT,
        fixed_deposit_tna=config.PUBLIC_FIXED_DEPOSIT_TNA_PERCENT,
        fixed_deposit_min_days=config.PUBLIC_FIXED_DEPOSIT_MIN_DAYS,
        credit_card_tna=config.PUBLIC_CREDIT_CARD_TNA_PERCENT,
        support_phone=config.PUBLIC_SUPPORT_PHONE, support_hours=config.PUBLIC_SUPPORT_HOURS,
        branches=config.PUBLIC_BRANCHES,
    )


@app.route("/login")
def login_page():
    return render_template("login.html", practice_user=config.PRACTICE_USERNAME)


@app.route("/dashboard")
@require_login
def dashboard():
    user = _current_user()
    return render_template("dashboard.html", user=user, account=_account_view(user),
                           is_ceo=(user["role"] == "ceo"), winning_code=user["winning_code"])


@app.route("/mensajes")
@require_login
def mensajes_page():
    return render_template("mensajes.html", user=_current_user(),
                           cooldown=config.SOCIAL_NOTIFY_COOLDOWN_SECONDS)


@app.route("/inbox")
def inbox():
    """Bandeja de 'mensajes al administrador' que revisa el CEO. VULN-2 (Stored
    XSS): los mensajes se renderizan SIN sanitizar. La visita el bot CEO, que
    tiene la clave privada del CEO en localStorage pero NO una sesion bancaria,
    asi que un payload solo roba la clave, no la flag."""
    return render_template("inbox.html", messages=db.get_all_messages(),
                           practice_user=config.PRACTICE_USERNAME)


@app.route("/collected")
@require_login
def collected_page():
    return render_template("collected.html", items=db.get_all_collected())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.route("/auth/register", methods=["POST"])
def auth_register():
    """Registra una passkey (solo la clave publica). Bloqueado para cuentas con
    registro cerrado (el CEO)."""
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
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()
    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="Usuario inexistente."), 404
    challenge = _issue_challenge(username)
    return jsonify(ok=True, username=username, user_id=user["id"], challenge=challenge)


@app.route("/auth/keys/<int:user_id>", methods=["GET"])
def auth_keys(user_id):
    """VULN-1 (IDOR): devuelve la credencial (credential_id + clave publica, NO
    la privada) de cualquier user_id sin autorizacion. Filtra el credential_id
    del CEO, necesario para /auth/verify."""
    user = db.get_user_by_id(user_id)
    if user is None:
        return jsonify(ok=False, error="No existe ese usuario."), 404
    cred = db.get_primary_credential_for_user(user_id)
    if cred is None:
        return jsonify(ok=True, user_id=user["id"], username=user["username"],
                       display_name=user["display_name"], credential_id=None, public_key=None)
    return jsonify(ok=True, user_id=user["id"], username=user["username"],
                   display_name=user["display_name"], credential_id=cred["credential_id"],
                   public_key=cred["public_key_pem"])


@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    """Verifica firma + binding (la credencial debe pertenecer al usuario). Para
    entrar como el CEO hace falta SU credential_id (IDOR) y firmar con SU clave
    privada (robada por XSS). El server es honesto: el pecado fue dejar la clave
    privada al alcance de un XSS."""
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
    if credential is None or credential["user_id"] != user["id"]:
        return jsonify(ok=False, error="Esa credencial no pertenece a este usuario."), 401
    if not crypto_utils.verify_signature(credential["public_key_pem"], challenge, signature_hex):
        return jsonify(ok=False, error="Firma inválida."), 401

    session.clear()
    session[config.SESSION_KEY_USER_ID] = user["id"]
    return jsonify(ok=True, next=url_for("dashboard"))


@app.route("/messages", methods=["POST"])
@require_login
def post_message():
    user = _current_user()
    body = (request.get_json(silent=True) or {}).get("body") or ""
    if not body.strip():
        return jsonify(ok=False, error="El mensaje está vacío."), 400
    db.add_message(user["username"], body)
    return jsonify(ok=True)


@app.route("/social/notify", methods=["POST"])
@require_login
def social_notify():
    """Ingenieria social: fuerza al bot CEO a revisar su bandeja. 1 vez/min."""
    last = db.last_bot_request_epoch()
    now = int(time.time())
    if last is not None and (now - last) < config.SOCIAL_NOTIFY_COOLDOWN_SECONDS:
        wait = config.SOCIAL_NOTIFY_COOLDOWN_SECONDS - (now - last)
        return jsonify(ok=False, error=f"Esperá {wait}s antes de volver a avisarle al administrador."), 429
    db.enqueue_bot_visit()
    return jsonify(ok=True)


@app.route("/collect")
def collect():
    """Recibe lo que exfiltra el payload XSS (?data=...). Sin auth: buzon abierto."""
    data = request.args.get("data", "")
    if data:
        db.add_collected(data)
    return ("", 204)


if __name__ == "__main__":
    print(f"HackerBank (CTF passwordless) disponible en: http://localhost:{SERVER_PORT}")
    app.run(debug=True, host="0.0.0.0", port=SERVER_PORT)
