"""
HackerBank - CTF "Passwordless de Carton" (Hacking Day Cordoba).

Banco ficticio que promociona un login "passwordless / biometrico, seguro como
una passkey", pero cuya implementacion imita a FIDO2/WebAuthn SIN entenderlo.
El objetivo pedagogico es que el alumno rompa esta version trucha y, por
contraste, entienda que garantiza FIDO2 real.

MAPA DE VULNERABILIDADES INTENCIONALES (buscar "VULN" en el codigo):
  VULN-1 (Capa 2, IDOR):  GET /auth/keys/<user_id> devuelve la clave PRIVADA
          de cualquier usuario, sin validar autorizacion.
  VULN-2 (Capa 2, cripto): la clave privada existe del lado del server, apenas
          "ofuscada" (reversible leyendo el JS del frontend). Ofuscar != cifrar.
  VULN-3 (diseno): el unico factor de autenticacion es una firma cuya clave
          privada es alcanzable por la red -> cualquiera que la obtenga se
          hace pasar por el duenio. En FIDO2 real la privada vive en hardware
          inextraible y solo viajan la publica y la firma.

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


@app.route("/profile")
def profile():
    """Perfil del usuario logueado. Muestra su propio user_id: es la pista de
    donde sale el <user_id> que consume el endpoint /auth/keys/<user_id>."""
    user = _current_user()
    if not user:
        return jsonify(ok=False, error="No hay sesión iniciada."), 401
    return jsonify(
        ok=True,
        user_id=user["id"],
        username=user["username"],
        display_name=user["display_name"],
        alias=user["alias"],
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# --------------------------------------------------------------------
# API del flujo passwordless trucho
# --------------------------------------------------------------------
@app.route("/auth/challenge", methods=["POST"])
def auth_challenge():
    """Emite un challenge aleatorio para un usuario.

    Devuelve tambien el user_id del usuario: el frontend lo necesita para ir a
    buscar la clave privada a /auth/keys/<user_id> y poder firmar. Esa
    filtracion del user_id es la primera pista del IDOR de la Capa 2.
    """
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()

    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="Usuario inexistente."), 404

    challenge = _issue_challenge(username)
    return jsonify(ok=True, username=username, user_id=user["id"], challenge=challenge)


@app.route("/auth/keys/<int:user_id>", methods=["GET"])
def auth_keys(user_id):
    """'Backup' de la clave privada del usuario.

    VULN-1 (IDOR) + VULN-2 (ofuscacion): devuelve la clave PRIVADA ofuscada de
    CUALQUIER user_id, sin validar que el que pide sea el duenio (ni siquiera
    exige sesion). En un banco real esto no deberia existir; en FIDO2 real no
    hay ninguna clave privada del lado del server que se pueda exponer.

    Incluye username/display_name "para que el usuario confirme que es su
    backup" -> en la practica permite identificar de quien es cada clave al
    enumerar los user_id (asi el alumno reconoce cual es el del CEO).
    """
    user = db.get_user_by_id(user_id)
    if user is None:
        return jsonify(ok=False, error="No existe backup para ese id."), 404
    return jsonify(
        ok=True,
        user_id=user["id"],
        username=user["username"],
        display_name=user["display_name"],
        # "Tu clave sigue protegida: viaja ofuscada." (spoiler: ofuscar no es cifrar)
        private_key_obfuscated=user["private_key_obfuscated"],
    )


@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    """Verifica la firma del challenge con la clave PUBLICA del usuario.

    Si la firma es valida para el challenge vigente, inicia sesion. No pide
    contrasena ni ningun otro factor: quien tenga la clave privada (obtenible
    por la red via /auth/keys) puede autenticarse como el usuario.
    """
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()
    challenge = payload.get("challenge") or ""
    signature_hex = payload.get("signature") or ""

    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="Usuario inexistente."), 404

    if not _consume_challenge(username, challenge):
        return jsonify(ok=False, error="Challenge inválido, vencido o ya usado. Pedí uno nuevo."), 400

    if not crypto_utils.verify_signature(user["public_key_pem"], challenge, signature_hex):
        return jsonify(ok=False, error="Firma inválida."), 401

    session.clear()
    session[config.SESSION_KEY_USER_ID] = user["id"]
    return jsonify(ok=True, next=url_for("dashboard"))


if __name__ == "__main__":
    print(f"HackerBank (CTF passwordless) disponible en: http://localhost:{SERVER_PORT}")
    app.run(debug=True, host="0.0.0.0", port=SERVER_PORT)
