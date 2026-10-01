# CLAUDE.md

Guía para trabajar en este repositorio.

## Qué es este proyecto

**HackingDay** es un CTF (desafío de ciberseguridad) **educativo y ético** para
el Hacking Day de Córdoba, sobre autenticación **passwordless / FIDO2 /
WebAuthn**, con un login estilo **Windows Hello**. La app es un banco ficticio
("HackerBank"). El estudiante encadena un **IDOR** y un **Stored XSS** (con agente
víctima) para robar la clave privada del CEO y entrar a su cuenta.

> IMPORTANTE: las vulnerabilidades son **intencionales y son el objeto del
> ejercicio**. No hay que "arreglarlas": están comentadas con `VULN` en el
> código. Todos los datos son ficticios; no procesa dinero real.

El banco vive en [`banco_app/`](banco_app/); el agente víctima en
[`agente/`](agente/) y el portal de soporte en [`soporte/`](soporte/).

## Estructura

```
docker-compose.yml  Orquesta 3 servicios: banco_app (5000), agente, soporte (5001)
banco_app/
  app.py            Rutas Flask + ceremonia Windows Hello (options/assert) + mensajes/inbox/collect + endpoints internos (vulns con VULN)
  config.py         Configuración (usuario de práctica, TTL, cooldown, AGENT_TOKEN, SOPORTE_PUBLIC_URL)
  db.py             DAO SQLite: users, credentials, messages, collected, bot_requests
  crypto_utils.py   ECDSA P-256: generar par (seed), verificar firma (sobre clientDataJSON)
  seed.py           Siembra usuarios; el CEO arranca SIN credencial (la aprovisiona el agente)
  solve.py          Solución de referencia (writeup ejecutable)
  static/js/script.js   Passkey WebCrypto + Windows Hello (teatro) + consola (signChallenge, helloForge)
  templates/        landing, login, dashboard, mensajes, inbox, collected, _fido2_diagram
  README.md / INSTRUCTOR_GUIDE.md
agente/
  agent.py          Navegador del CEO (Playwright): genera la passkey del CEO, aprovisiona la pública y revisa /inbox
  Dockerfile / requirements.txt
soporte/
  soporte.py        Portal de soporte (:5001) con el botón "avisar al administrador"
  templates/soporte.html · Dockerfile · requirements.txt
```

## Cómo levantar y probar

```bash
docker compose up -d --build      # desde la raíz del repo
# banco http://localhost:5000  ·  soporte http://localhost:5001  (el build del agente trae Chromium; tarda)
```

Tres servicios: `banco_app` (base liviana de Python), `agente` (base
`mcr.microsoft.com/playwright/python`, trae Chromium) y `soporte`. El banco corre
`seed.py` + `app.py`; el agente genera la passkey del CEO y le aprovisiona la
pública por un endpoint interno (con token).

Validar el ataque completo (imprime la flag): `python solve.py` (desde el host,
con `requests` + `cryptography`). Resetear entre participantes: `docker compose
restart` (reinicia todo junto; banco y agente deben resetear a la vez).

## Diseño del desafío (para no romperlo sin querer)

**Base (bien hecha):** como FIDO2 real, el servidor SOLO guarda claves públicas
(tabla `credentials`). La clave privada de cada passkey se genera en el cliente
(WebCrypto) y vive en `localStorage` bajo `hb_privkey_<usuario>`.

**Teatro de Windows Hello:** el login invoca el PIN real del SO con
`navigator.credentials.create()` y **descarta** la credencial; la auth real corre
con la clave de software de `localStorage`. El factor fuerte es puro teatro (ese
es el "mal implementado").

**Las cuatro capas:**
1. **Reconocimiento:** login de la cuenta de práctica (`config.PRACTICE_USERNAME`,
   = `t3ny`) en `/login` con Windows Hello: `register → hello/options → keys →
   hello/assert`.
2. **IDOR:** `GET /auth/keys/<user_id>` devuelve el `credential_id` (público) de
   cualquiera. Enumerando se identifica al CEO (`7013`) y se guarda su credential_id.
3. **Stored XSS:** el estudiante deja un mensaje en `/mensajes` (POST `/messages`)
   con un payload; `/inbox` (y la **vista previa** de `/mensajes`) lo renderizan
   **sin sanitizar** (`| safe`). Desde el portal de soporte (`:5001`, que postea a
   `/social/notify`, 1/min) se dispara el **agente CEO** (`agente/agent.py`), que
   tiene la clave privada del CEO en su `localStorage` pero **NO una sesión
   bancaria**. El payload roba `hb_privkey_ceo` y lo exfiltra a `/collect`; se lee
   en `/collected`.
4. **Firma:** con el credential_id (Capa 2) y la clave robada (Capa 3), se arma y
   firma un `clientDataJSON` fresco del CEO (`helloForge()` en la consola F12, o
   Python) y se hace `hello/assert` → sesión CEO → flag.

**Invariantes a NO romper:**
- `/auth/hello/assert` es **honesto en lo que importa** (valida binding
  credencial↔usuario + firma contra la pública guardada). El ataque no explota un
  bug de binding/firma: explota que la clave privada era robable.
- **VULN-3 (challenge no vinculado):** `hello/assert` toma el challenge del
  `clientDataJSON` del cliente y NO lo valida contra el emitido (ni chequea
  `origin`). Es un fallo WebAuthn realista; NO le saques el binding ni la firma
  (si no, se puede entrar sin robar la clave y se trivializa el CTF).
- El **agente CEO no tiene sesión bancaria** (solo la passkey en localStorage). Es
  lo que evita que el XSS robe la flag directo del dashboard. No le des sesión.
- El **CEO arranca sin credencial y con el registro cerrado**
  (`passkey_registration_open=0`). La passkey la **genera el agente** y aprovisiona
  solo la pública por `/internal/provision-ceo` (con `X-Agent-Token`, one-shot). No
  expongas ese endpoint sin token ni le saques el one-shot: sería un bypass (dejar
  registrarle una passkey nueva al CEO saltea el robo).
- **Cripto:** ECDSA P-256; firma en el cable = raw r‖s (64 bytes) hex (WebCrypto),
  sobre los bytes del `clientDataJSON`. La privada se maneja como PKCS8 base64.
- **Flag:** MD5 ficticio en `seed.py` (`CEO_WINNING_CODE`), determinístico.

## Convenciones

- Todo el proyecto y su documentación están en **español (es-AR)**.
- SQL siempre **parametrizado**.
- Comentarios del backend: explican *dónde* está cada vulnerabilidad y *por qué*.

## Nota sobre `HackerTech/`

Si existe una carpeta `HackerTech/`, es un **clon de referencia de otro repo**.
Está en `.gitignore` y **no forma parte** de este proyecto.
