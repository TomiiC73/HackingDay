"""
HackerBank - CTF "Passwordless de Carton" (Hacking Day Cordoba).

Banco ficticio passwordless con una ceremonia estilo WebAuthn / Windows Hello
(options + assert). Como en FIDO2 real, el servidor SOLO guarda claves publicas;
la privada de cada passkey vive del lado del cliente (en localStorage). El
desafio encadena un IDOR (filtra el credential_id del CEO) y un Stored XSS (el
inbox del CEO renderiza mensajes sin sanitizar; el agente CEO los ve y un payload
roba su clave privada de localStorage), y termina forjando el assert del CEO.

VULN-1 (IDOR): GET /auth/keys/<user_id> devuelve la credencial de cualquiera.
VULN-2 (Stored XSS): /inbox (y la vista previa de /mensajes) no sanitizan.
VULN-3 (challenge no vinculado): /auth/hello/assert toma el challenge de adentro
  del clientDataJSON que manda el cliente, en vez de validar el que emitio en
  /auth/hello/options (sin anti-replay ni chequeo de origin).

Teatro de Windows Hello: el login del navegador invoca el PIN real del SO
(navigator.credentials.create) pero DESCARTA esa credencial; la auth real corre
con una clave de software guardada en localStorage. El factor fuerte no protege
nada: ese es el "mal implementado".

El pecado de fondo que ensena FIDO2: guardar la clave privada donde JavaScript
la alcanza (localStorage) la hace robable por XSS. En FIDO2/Windows Hello real
vive en el TPM y JS nunca la toca. Todo es ficticio y educativo.
"""
import base64
import json
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
    # El banco SI emite y guarda un challenge aca... pero /auth/hello/assert
    # nunca lo valida (VULN-3). Se emite para que la ceremonia se vea como
    # WebAuthn real en la red; el bug es que el server no lo exige de vuelta.
    challenge = secrets.token_urlsafe(config.CHALLENGE_BYTES)
    _ISSUED_CHALLENGES[username] = (challenge, time.time() + config.CHALLENGE_TTL_SECONDS)
    return challenge


def _b64url_decode(data):
    """base64url -> bytes (tolera falta de padding, como WebAuthn)."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _check_agent_token():
    """True si la request trae el token del agente (endpoints internos)."""
    return secrets.compare_digest(request.headers.get("X-Agent-Token", ""), config.AGENT_TOKEN)


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
    return render_template("mensajes.html", user=_current_user())


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


@app.route("/auth/hello/options", methods=["POST"])
def auth_hello_options():
    """Paso 1 de la ceremonia (como PublicKeyCredentialRequestOptions de
    WebAuthn/Windows Hello): emite el challenge para `username`. Devuelve tambien
    el user_id para que el cliente pida su credential_id a /auth/keys (ahi vive
    el IDOR de la Capa 2). rpId/userVerification son decorativos del flujo."""
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()
    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="Usuario inexistente."), 404
    challenge = _issue_challenge(username)
    rp_id = request.host.split(":")[0]
    return jsonify(ok=True, username=username, user_id=user["id"], challenge=challenge,
                   rpId=rp_id, userVerification="required")


@app.route("/auth/keys/<username>", methods=["GET"])
def auth_keys(username):
    """VULN-1 (IDOR): devuelve la credencial (credential_id + clave publica, NO
    la privada) de CUALQUIER usuario, por su NOMBRE, sin control de acceso. En el
    login tu navegador pide /auth/keys/<tu_usuario>; cambiando el nombre a otro
    (p.ej. 'ceo') se filtra el credential_id ajeno, necesario para el assert."""
    username = (username or "").strip().lower()
    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="No existe ese usuario."), 404
    cred = db.get_primary_credential_for_user(user["id"])
    if cred is None:
        return jsonify(ok=True, user_id=user["id"], username=user["username"],
                       display_name=user["display_name"], credential_id=None, public_key=None)
    return jsonify(ok=True, user_id=user["id"], username=user["username"],
                   display_name=user["display_name"], credential_id=cred["credential_id"],
                   public_key=cred["public_key_pem"])


@app.route("/auth/hello/assert", methods=["POST"])
def auth_hello_assert():
    """Paso 2 de la ceremonia (como la assertion de WebAuthn/Windows Hello).
    Recibe {username, id, type, response:{clientDataJSON, authenticatorData,
    signature}}.

    Para entrar como el CEO hace falta SU credential_id (IDOR, Capa 2) y firmar
    con SU clave privada (robada por XSS, Capa 3). El server mantiene HONESTO lo
    importante: el binding credencial<->usuario y la verificacion de la firma
    contra la clave PUBLICA guardada. El pecado no esta en verify: esta en que la
    privada era robable (y en VULN-3, abajo)."""
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()
    credential_id = (payload.get("id") or payload.get("credential_id") or "").strip()
    response = payload.get("response") or {}
    client_data_b64 = response.get("clientDataJSON") or ""
    signature_hex = response.get("signature") or ""

    user = db.get_user_by_username(username)
    if user is None:
        return jsonify(ok=False, error="Usuario inexistente."), 404

    # Decodificar el clientDataJSON que armo el cliente (base64url -> JSON).
    try:
        client_data_bytes = _b64url_decode(client_data_b64)
        client_data = json.loads(client_data_bytes.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError):
        return jsonify(ok=False, error="clientDataJSON inválido."), 400

    # VULN-3 (challenge no vinculado): el challenge se LEE de clientDataJSON y NO
    # se valida contra el que emitio /auth/hello/options, ni se chequea el origin.
    # Un RP WebAuthn correcto exigiria: challenge == el emitido (anti-replay) y
    # origin == el propio. Aca alcanza con que la firma sea valida -> replay y
    # challenge elegido por el atacante. (Igual sigue necesitando la privada.)
    _challenge_no_validado = client_data.get("challenge")  # se ignora a proposito

    # Binding HONESTO: la credencial debe pertenecer a este usuario.
    credential = db.get_credential(credential_id)
    if credential is None or credential["user_id"] != user["id"]:
        return jsonify(ok=False, error="Esa credencial no pertenece a este usuario."), 401

    # Firma HONESTA: ECDSA-SHA256 sobre los bytes de clientDataJSON, contra la
    # clave PUBLICA guardada de la credencial.
    if not crypto_utils.verify_signature_bytes(credential["public_key_pem"], client_data_bytes, signature_hex):
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
def social_notify():
    """Ingenieria social: encola un pedido para que el agente CEO revise su
    bandeja. Lo dispara el portal de soporte (otro sitio/puerto), por eso NO pide
    sesion bancaria. Rate-limit 1/min (como el Blog de Pepe)."""
    last = db.last_bot_request_epoch()
    now = int(time.time())
    if last is not None and (now - last) < config.SOCIAL_NOTIFY_COOLDOWN_SECONDS:
        wait = config.SOCIAL_NOTIFY_COOLDOWN_SECONDS - (now - last)
        return jsonify(ok=False, error=f"Esperá {wait}s antes de volver a avisarle al administrador."), 429
    # La URL que el administrador abrirá (la elige quien lo "invita" desde el
    # portal de soporte). Si no mandan una, el agente usa su /inbox por defecto.
    url = (request.get_json(silent=True) or {}).get("url") or None
    db.enqueue_bot_visit(url)
    return jsonify(ok=True)


@app.route("/internal/provision-ceo", methods=["POST"])
def internal_provision_ceo():
    """INTERNO (solo el agente, con X-Agent-Token). Aprovisiona la passkey del
    CEO guardando SOLO su clave publica (la privada vive en el navegador del
    agente). Saltea el gate passkey_registration_open=0, POR ESO exige token.
    One-shot: si el CEO ya tiene credencial, rechaza -> un token filtrado tras el
    arranque no sirve para registrarle una passkey nueva al CEO."""
    if not _check_agent_token():
        return jsonify(ok=False, error="No autorizado."), 401
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip().lower()
    credential_id = (payload.get("credential_id") or "").strip()
    public_key = payload.get("public_key") or ""
    if username != "ceo":
        return jsonify(ok=False, error="Este endpoint solo aprovisiona al CEO."), 403
    user = db.get_user_by_username("ceo")
    if user is None:
        return jsonify(ok=False, error="CEO inexistente."), 404
    if db.get_primary_credential_for_user(user["id"]) is not None:
        return jsonify(ok=False, error="El CEO ya tiene una credencial (one-shot)."), 409
    if not credential_id or not public_key:
        return jsonify(ok=False, error="Faltan datos de la credencial."), 400
    from cryptography.hazmat.primitives import serialization
    try:
        serialization.load_pem_public_key(public_key.encode("ascii"))
    except (ValueError, TypeError):
        return jsonify(ok=False, error="Clave pública inválida."), 400
    db.add_credential(credential_id, user["id"], public_key)
    return jsonify(ok=True)


@app.route("/internal/agent/pending", methods=["GET"])
def internal_agent_pending():
    """INTERNO (solo el agente, con X-Agent-Token). Devuelve si hay un pedido de
    visita pendiente (lo encola /social/notify) y lo marca como tomado."""
    if not _check_agent_token():
        return jsonify(ok=False, error="No autorizado."), 401
    req = db.take_pending_bot_visit()
    if req is None:
        return jsonify(ok=True, pending=False, url=None)
    return jsonify(ok=True, pending=True, url=req.get("url"))


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
