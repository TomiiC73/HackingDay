# CLAUDE.md

Guía para trabajar en este repositorio.

## Qué es este proyecto

**HackingDay** es un CTF (desafío de ciberseguridad) **educativo y ético** para
el Hacking Day de Córdoba, sobre autenticación **passwordless / FIDO2 /
WebAuthn**. La app es un banco ficticio ("HackerBank"). El estudiante encadena un
**IDOR** y un **Stored XSS** (estilo "Blog de Pepe", con bot víctima) para robar
la clave privada del CEO y entrar a su cuenta.

> IMPORTANTE: las vulnerabilidades son **intencionales y son el objeto del
> ejercicio**. No hay que "arreglarlas": están comentadas con `VULN` en el
> código. Todos los datos son ficticios; no procesa dinero real.

La app vive en [`banco_app/`](banco_app/).

## Estructura

```
banco_app/
  app.py            Rutas Flask + API passwordless + mensajes/inbox/collect (vulns con VULN)
  config.py         Configuración (usuario de práctica, TTL, cooldown, rutas)
  db.py             DAO SQLite: users, credentials, messages, collected, bot_requests
  crypto_utils.py   ECDSA P-256: generar par (seed), verificar firma
  seed.py           Siembra usuarios; aprovisiona la passkey del CEO -> ceo_passkey.json
  bot.py            Bot "CEO" headless (Playwright): la víctima del Stored XSS
  solve.py          Solución de referencia (writeup ejecutable)
  static/js/script.js   Passkey WebCrypto + funciones de consola (signChallenge, hbForge)
  templates/        landing, login, dashboard, mensajes, inbox, collected, _fido2_diagram
  README.md / INSTRUCTOR_GUIDE.md
```

## Cómo levantar y probar

```bash
cd banco_app
docker compose up -d --build      # http://localhost:5000  (el build trae Chromium; tarda)
```

Imagen base: `mcr.microsoft.com/playwright/python` (trae Chromium para el bot).
El contenedor corre `seed.py`, el bot (`bot.py`) y `app.py` juntos.

Validar el ataque completo (imprime la flag): `python solve.py` (desde el host,
con `requests` + `cryptography`). Resetear entre participantes: `docker compose restart`.

## Diseño del desafío (para no romperlo sin querer)

**Base (bien hecha):** como FIDO2 real, el servidor SOLO guarda claves públicas
(tabla `credentials`). La clave privada de cada passkey se genera en el cliente
(WebCrypto) y vive en `localStorage` bajo `hb_privkey_<usuario>`.

**Las cuatro capas:**
1. **Reconocimiento:** login de la cuenta de práctica (`config.PRACTICE_USERNAME`,
   = `t3ny`) en `/login`: `register → challenge → keys → verify`.
2. **IDOR:** `GET /auth/keys/<user_id>` devuelve el `credential_id` (público) de
   cualquiera. Enumerando se identifica al CEO (`7013`) y se guarda su credential_id.
3. **Stored XSS:** el estudiante deja un mensaje en `/mensajes` (POST `/messages`)
   con un payload; `/inbox` lo renderiza **sin sanitizar** (`| safe`). Con la
   "ingeniería social" (`/social/notify`, 1/min) se dispara el **bot CEO**
   (`bot.py`), que tiene la clave privada del CEO en su `localStorage` pero **NO
   una sesión bancaria**. El payload roba `hb_privkey_ceo` y lo exfiltra a
   `/collect`; se lee en `/collected`.
4. **Firma:** con el credential_id (Capa 2) y la clave robada (Capa 3), se firma
   un challenge fresco del CEO (`hbForge()` en la consola F12, o Python) y se
   hace `verify` → sesión CEO → flag.

**Invariantes a NO romper:**
- `/auth/verify` es **honesto** (valida binding credencial↔usuario + firma). El
  ataque no explota un bug de verify: explota que la clave privada era robable.
- El **bot CEO no tiene sesión bancaria** (solo la passkey en localStorage). Es lo
  que evita que el XSS robe la flag directo del dashboard; obliga a completar el
  flujo. No le des sesión al bot.
- El **CEO tiene el registro cerrado** (`passkey_registration_open=0`) para que
  nadie le registre una passkey nueva y saltee el robo.
- **Cripto:** ECDSA P-256; firma en el cable = raw r‖s (64 bytes) hex (WebCrypto).
  La privada se maneja como PKCS8 base64 (lo que exporta WebCrypto).
- **Flag:** MD5 ficticio en `seed.py` (`CEO_WINNING_CODE`), determinístico.

## Convenciones

- Todo el proyecto y su documentación están en **español (es-AR)**.
- SQL siempre **parametrizado**.
- Comentarios del backend: explican *dónde* está cada vulnerabilidad y *por qué*.

## Nota sobre `HackerTech/`

Si existe una carpeta `HackerTech/`, es un **clon de referencia de otro repo**.
Está en `.gitignore` y **no forma parte** de este proyecto.
