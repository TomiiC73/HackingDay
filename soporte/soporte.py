"""
Portal interno de soporte de HackerBank — sitio aparte, en otro puerto (:5001).

A proposito NO forma parte del banco: es "otro sistema" donde los clientes piden
que el administrador (el CEO) revise su bandeja de mensajes. Tiene un solo boton.
Al tocarlo, este servidor reenvia el pedido al banco (POST /social/notify), que lo
encola para el agente CEO. Hacerlo del lado del servidor evita problemas de CORS
entre :5001 y :5000.

Config por entorno:
  BANK_URL      (default http://banco_app:5000)   -> el banco, red interna de compose
  SUPPORT_PORT  (default 5001)
"""
import os

import requests
from flask import Flask, jsonify, render_template, request

BANK_URL = (os.environ.get("BANK_URL") or "http://banco_app:5000").rstrip("/")
SUPPORT_PORT = int(os.environ.get("SUPPORT_PORT") or "5001")

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("soporte.html")


@app.route("/notify", methods=["POST"])
def notify():
    """Reenvia el pedido al banco (con la URL que debe abrir el admin) para que
    el agente CEO la visite."""
    url = (request.get_json(silent=True) or {}).get("url") or None
    try:
        r = requests.post(f"{BANK_URL}/social/notify", json={"url": url}, timeout=5)
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if r.ok and data.get("ok"):
            return jsonify(ok=True, message="Listo: el administrador va a revisar su bandeja en unos segundos.")
        return jsonify(ok=False, error=data.get("error") or "No se pudo avisar al administrador."), r.status_code
    except requests.RequestException:
        return jsonify(ok=False, error="No se pudo contactar al banco."), 502


if __name__ == "__main__":
    print(f"Portal de soporte HackerBank en: http://localhost:{SUPPORT_PORT}")
    app.run(host="0.0.0.0", port=SUPPORT_PORT)
