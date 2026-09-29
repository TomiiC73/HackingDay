"""
Bot "CEO" del CTF (la victima del Stored XSS).

Simula al CEO revisando su bandeja de mensajes. Es un navegador headless
(Playwright/Chromium) que:
  1. Carga en su localStorage la clave privada del CEO (desde ceo_passkey.json,
     que dejo el seed) bajo `hb_privkey_ceo`, y `hb_current_user = "ceo"`.
  2. NO inicia sesion bancaria: solo tiene la passkey guardada. Asi, un payload
     XSS que corra en su contexto puede robar la clave privada, pero no puede
     leer la flag (no hay sesion al dashboard).
  3. Cuando alguien lo "invita" con la ingenieria social (se encola un pedido en
     bot_requests), visita /inbox, donde el Stored XSS se ejecuta.

Corre en el mismo contenedor que la app (comparte la base sqlite).
"""
import json
import time

import config
import db

BASE = "http://localhost:5000"
POLL_SECONDS = 2
RENDER_WAIT_MS = 2000


def _load_ceo_passkey():
    with open(config.CEO_PASSKEY_FILE, "r", encoding="ascii") as f:
        return json.load(f)


def run():
    from playwright.sync_api import sync_playwright

    passkey = _load_ceo_passkey()
    priv_b64 = passkey["private_key_b64"]

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        context = browser.new_context()
        page = context.new_page()

        # 1) Sembrar el localStorage del "dispositivo del CEO" (una vez).
        #    Reintenta hasta que la app responda.
        for _ in range(60):
            try:
                page.goto(f"{BASE}/inbox", wait_until="load")
                page.evaluate(
                    """([priv]) => {
                        localStorage.setItem('hb_privkey_ceo', priv);
                        localStorage.setItem('hb_current_user', 'ceo');
                    }""",
                    [priv_b64],
                )
                break
            except Exception:
                time.sleep(1)
        print("[bot] CEO listo (passkey cargada en localStorage, sin sesión bancaria).")

        # 2) Loop: cuando hay un pedido, el CEO 'entra' a revisar su bandeja.
        while True:
            try:
                if db.take_pending_bot_visit() is not None:
                    print("[bot] El CEO revisa su bandeja (/inbox)...")
                    page.goto(f"{BASE}/inbox", wait_until="load")
                    page.wait_for_timeout(RENDER_WAIT_MS)  # deja correr cualquier XSS guardado
            except Exception as e:  # nunca morir por un error puntual
                print(f"[bot] aviso: {e}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    # Espera a que la app y el seed esten listos.
    for _ in range(30):
        try:
            _load_ceo_passkey()
            break
        except FileNotFoundError:
            time.sleep(1)
    run()
