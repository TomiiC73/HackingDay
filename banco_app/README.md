# HackerBank — CTF "Passwordless de Cartón"

Desafío sobre autenticación **passwordless / FIDO2 / WebAuthn**.

## La idea

HackerBank usa un login estilo **Windows Hello / WebAuthn** (ceremonia
`options → assert`). Guarda las claves *casi* bien: como FIDO2 real, el servidor
solo almacena **claves públicas**. Pero comete el pecado de dejar la **clave
privada de cada passkey en `localStorage`** (accesible por JavaScript). Combinado
con un **Stored XSS**, eso permite robar la clave privada del CEO y entrar a su
cuenta.

Además, el "Windows Hello" está **mal implementado**: al loguearte se invoca el
**PIN real de Windows Hello**, pero su credencial se **descarta** — la
autenticación real corre con una clave de software en `localStorage`. El factor
fuerte es puro teatro.

El aprendizaje: en Windows Hello / FIDO2 real la clave privada vive en hardware
(TPM/Secure Enclave) y **JavaScript nunca puede leerla** — el mismo XSS no robaría
nada.

## Cómo se juega (resumen)

Herramientas: **Burp Suite**, **DevTools** del navegador y un poco de Python.

1. **Reconocimiento:** login de la cuenta de práctica `t3ny` en `/login` (Windows
   Hello) y análisis de la ceremonia (`options → keys → assert`). El PIN que pide
   es teatro: la auth real firma con la clave de `localStorage`.
2. **IDOR:** `GET /auth/keys/<id>` filtra el `credential_id` de cualquier usuario;
   enumerando se identifica al **CEO** y se guarda su `credential_id`.
3. **Stored XSS:** se deja un mensaje con un payload en "Mensajes al
   administrador" (la **vista previa** lo delata al renderizar HTML sin escapar);
   desde el **portal de soporte** (`:5001`) se pide que el **agente CEO** lea su
   bandeja, y el payload roba su **clave privada** de `localStorage`.
4. **Firma:** con el `credential_id` (paso 2) y la clave robada (paso 3) se firma
   un `clientDataJSON` fresco del CEO (desde la consola con `helloForge()`) y se
   hace el `assert` → **código ganador**. (El server no vincula el challenge que
   emitió — `VULN-3` — pero igual valida binding + firma, así que la clave robada
   es imprescindible.)

El writeup completo está en [`INSTRUCTOR_GUIDE.md`](INSTRUCTOR_GUIDE.md).

## Requisitos

- **Docker** + Docker Compose (recomendado). El build del **agente** baja la
  imagen oficial de Playwright (trae Chromium), así que la primera vez tarda.

## Cómo levantarlo

```bash
docker compose up -d --build      # desde la raíz del repo
```

Levanta **tres servicios**:

| Servicio    | Puerto | Qué es |
|-------------|--------|--------|
| `banco_app` | 5000   | El banco: login Windows Hello, IDOR, `/inbox` (XSS), `/collected`. |
| `agente`    | —      | Navegador del CEO (Playwright). Genera su passkey, revisa `/inbox`. |
| `soporte`   | 5001   | Portal aparte con el botón "avisar al administrador". |

La app queda en **http://localhost:5000** y el portal de soporte en
**http://localhost:5001**. `seed.py` recrea la base en cada arranque (el CEO
arranca **sin credencial**: la genera el agente y le aprovisiona solo la pública).
Para resetear entre participantes: `docker compose restart` (reinicia todo junto,
así banco y agente quedan sincronizados).

## Usuarios de laboratorio

| Usuario  | Rol      | Para qué sirve |
|----------|----------|----------------|
| `t3ny`   | práctica | La cuenta del "atacante": registra su passkey y entra; desde ahí deja mensajes y ataca. |
| `ceo`    | objetivo | Su cuenta tiene el código ganador. La revisa el agente (la víctima del XSS). |
| `lmoreno`, `dferreyra`, `sibarra` | señuelos | Para que la enumeración del IDOR tenga sentido. |

## Verificar la solución

[`solve.py`](solve.py) ejecuta el ataque completo y imprime la flag:

```bash
pip install requests cryptography
python solve.py            # contra http://localhost:5000
```

## Stack técnico

- **Backend:** Python + Flask + SQLite.
- **Criptografía:** ECDSA P-256 (la misma de WebAuthn) vía `cryptography`.
- **Agente víctima:** Playwright + Chromium headless (`agente/agent.py`),
  contenedor aparte.
- **Portal de soporte:** Flask simple (`soporte/`), contenedor aparte en `:5001`.
- **Frontend:** HTML + CSS + JavaScript vanilla; la passkey se genera con
  WebCrypto y su clave privada vive en `localStorage`. El login invoca el PIN
  real de Windows Hello (teatro) vía `navigator.credentials.create()`.

## Estructura (del repo)

```
docker-compose.yml    Orquesta los tres servicios (banco_app, agente, soporte)
banco_app/
  app.py            Rutas Flask: páginas + ceremonia Windows Hello + mensajes/inbox/collect + endpoints internos
  config.py         Configuración (usuario de práctica, TTL, cooldown, AGENT_TOKEN)
  db.py             SQLite: users, credentials, messages, collected, bot_requests
  crypto_utils.py   Generar par (seed/señuelos) y verificar firma (sobre clientDataJSON)
  seed.py           Siembra usuarios (el CEO arranca SIN credencial)
  solve.py          Solución de referencia (writeup ejecutable)
  static/js/script.js   Passkey WebCrypto + Windows Hello (teatro) + consola (signChallenge, helloForge)
  templates/        landing, login, dashboard, mensajes, inbox, collected, _fido2_diagram
agente/
  agent.py          Navegador del CEO (Playwright): genera la passkey y revisa /inbox
soporte/
  soporte.py        Portal de soporte (:5001) con el botón de aviso
INSTRUCTOR_GUIDE.md   Guía del organizador: solución, teoría, rúbrica y montaje
```
