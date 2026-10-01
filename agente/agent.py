"""
Agente "CEO" del CTF (la victima del Stored XSS) — contenedor separado.

Simula la notebook del CEO revisando su bandeja. Es un navegador real headless
(Playwright/Chromium) que:
  1. GENERA la passkey del CEO en el navegador (WebCrypto): deja la PRIVADA en su
     propio localStorage (`hb_privkey_ceo`) y aprovisiona SOLO la PUBLICA al banco
     por un endpoint interno (con token). El banco nunca ve la privada.
  2. NO inicia sesion bancaria: solo tiene la passkey guardada. Asi, un payload
     XSS que corra en su contexto puede robar la clave privada, pero NO puede
     leer la flag (no hay sesion al dashboard).
  3. Revisa su bandeja (/inbox) periodicamente y cuando alguien lo "invita" desde
     el portal de soporte (se encola un pedido via /social/notify). Ahi se
     ejecuta el Stored XSS.

Corre en su propio contenedor (ver agente/Dockerfile). Se comunica con el banco
solo por HTTP. Config por entorno:
  BANK_URL       (default http://banco_app:5000)
  AGENT_TOKEN    (debe coincidir con el del banco)
  AGENT_PERIODIC_SECONDS (default 45)
"""
import os
import time

BANK_URL = (os.environ.get("BANK_URL") or "http://banco_app:5000").rstrip("/")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN") or "lab-only-agent-token-hackertech-cba"
PERIODIC_SECONDS = int(os.environ.get("AGENT_PERIODIC_SECONDS") or "45")

POLL_SECONDS = 2
RENDER_WAIT_MS = 2000

# WebCrypto en el navegador del CEO: genera el par ECDSA P-256, guarda la privada
# en localStorage (robable por XSS) y devuelve credential_id + PEM de la publica.
_GEN_PASSKEY_JS = """
async () => {
  function bufToB64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function spkiToPem(spki){
    const lines = bufToB64(spki).match(/.{1,64}/g).join("\\n");
    return `-----BEGIN PUBLIC KEY-----\\n${lines}\\n-----END PUBLIC KEY-----`;
  }
  function randomHex(n){
    const a = new Uint8Array(n); crypto.getRandomValues(a);
    return Array.from(a).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  const privB64 = bufToB64(pkcs8);
  const credentialId = randomHex(16);
  const publicPem = spkiToPem(spki);
  // La PRIVADA se queda SOLO aca, en el localStorage del CEO (lo que roba el XSS).
  localStorage.setItem("hb_privkey_ceo", privB64);
  localStorage.setItem("hb_current_user", "ceo");
  return { credentialId, publicPem };
}
"""


def _wait_for_bank(page):
    """Espera (sin rendirse) a que el banco responda OK en /inbox. Loguea el
    último error cada tanto para poder diagnosticar si algo falla."""
    last_err = None
    i = 0
    while True:
        try:
            resp = page.goto(f"{BANK_URL}/inbox", wait_until="load")
            if resp is not None and resp.ok:
                return True
            last_err = f"status {resp.status if resp else 'sin respuesta'}"
        except Exception as e:
            last_err = repr(e)
        if i % 10 == 0:
            print(f"[agente] esperando al banco en {BANK_URL}/inbox ... (último: {last_err})", flush=True)
        i += 1
        time.sleep(1)


def _provision_ceo(page):
    """Genera la passkey del CEO en el navegador y aprovisiona la publica al banco."""
    gen = page.evaluate(_GEN_PASSKEY_JS)
    headers = {"X-Agent-Token": AGENT_TOKEN, "Content-Type": "application/json"}
    payload = {"username": "ceo", "credential_id": gen["credentialId"], "public_key": gen["publicPem"]}
    resp = page.request.post(f"{BANK_URL}/internal/provision-ceo", data=payload, headers=headers)
    if resp.ok:
        print("[agente] Passkey del CEO generada y PUBLICA aprovisionada al banco.")
        return True
    if resp.status == 409:
        # El banco ya tiene una credencial del CEO (one-shot). Si solo se reinicio
        # el agente, la privada recien generada NO coincide con esa credencial.
        print("[agente] AVISO: el banco ya tenia una credencial del CEO (one-shot). "
              "Si reiniciaste solo el agente, reseteá todo con 'docker compose restart' "
              "para que banco y agente queden sincronizados.")
        return False
    print(f"[agente] ERROR al aprovisionar ({resp.status}): {resp.text()}")
    return False


def _take_pending_request(page):
    """Devuelve (pending: bool, url: str|None). La url la elige quien invita al
    admin desde el portal de soporte (:5001)."""
    try:
        resp = page.request.get(f"{BANK_URL}/internal/agent/pending",
                                headers={"X-Agent-Token": AGENT_TOKEN})
        if resp.ok:
            data = resp.json()
            return bool(data.get("pending")), data.get("url")
    except Exception as e:
        print(f"[agente] aviso al consultar pending: {e}")
    return False, None


def _visit(page, url, motivo):
    """El CEO abre `url` (la que le indicaron) y corre lo que haya ahí (XSS)."""
    print(f"[agente] El CEO abre {url} [{motivo}]...")
    page.goto(url, wait_until="load")
    page.wait_for_timeout(RENDER_WAIT_MS)  # deja correr cualquier XSS guardado


def run():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        # Flags necesarios en Docker: sin sandbox y sin /dev/shm (que suele ser
        # chico y hace crashear a Chromium al navegar). Ademas, Chromium solo
        # expone `crypto.subtle` (WebCrypto) en "contextos seguros" (HTTPS o
        # localhost); como el banco se sirve por HTTP en un host no-localhost
        # (BANK_URL, p.ej. http://banco_app:5000), hay que decirle a Chromium
        # que trate ese origen como seguro o `crypto.subtle` queda `undefined`
        # y falla la generacion de la passkey del CEO.
        browser = p.chromium.launch(args=[
            "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
            f"--unsafely-treat-insecure-origin-as-secure={BANK_URL}",
        ])
        context = browser.new_context()
        page = context.new_page()

        if not _wait_for_bank(page):
            print("[agente] No se pudo contactar al banco. Saliendo.")
            return
        _provision_ceo(page)
        print("[agente] CEO listo (passkey en localStorage, sin sesión bancaria).")

        default_url = f"{BANK_URL}/inbox"
        last_periodic = time.time()
        while True:
            try:
                pending, url = _take_pending_request(page)
                if pending:
                    _visit(page, url or default_url, "pedido de soporte")
                    last_periodic = time.time()
                elif (time.time() - last_periodic) >= PERIODIC_SECONDS:
                    _visit(page, default_url, "revisión periódica")
                    last_periodic = time.time()
            except Exception as e:  # nunca morir por un error puntual
                print(f"[agente] aviso: {e}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    run()
