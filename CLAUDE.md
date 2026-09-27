# CLAUDE.md

Guía para trabajar en este repositorio.

## Qué es este proyecto

**HackingDay** es un CTF (desafío de ciberseguridad) **educativo y ético** para
el Hacking Day de Córdoba, sobre autenticación **passwordless / FIDO2 /
WebAuthn**. La app es un banco ficticio ("HackerBank") con un login passwordless
implementado **mal a propósito**: el estudiante lo ataca para entender, por
contraste, cómo funciona FIDO2 real.

> IMPORTANTE: las vulnerabilidades de esta app son **intencionales y son el
> objeto del ejercicio**. No hay que "arreglarlas": están comentadas con el
> string `VULN` en el código para que el organizador entienda el diseño. Todos
> los datos son ficticios; no procesa dinero real.

La app vive en [`banco_app/`](banco_app/). Reutiliza la identidad visual de una
landing fintech (Tailwind, oscuro/dorado, Inter) para ser inmersiva.

## Estructura

```
banco_app/
  app.py            Rutas Flask + API del flujo passwordless (vuln marcada con VULN)
  config.py         Configuración (challenge TTL, curva, etc.)
  db.py             DAO SQLite parametrizado (tablas users y credentials)
  crypto_utils.py   ECDSA P-256: generación de par (seed), verificación de firma
  seed.py           Recrea la base y siembra usuarios (alumno, ceo, señuelos)
  solve.py          Solución de referencia (writeup ejecutable)
  static/js/script.js   Passkey WebCrypto (genera par, registra, firma) del frontend
  templates/        landing.html, login.html, dashboard.html, _fido2_diagram.html
  README.md         Para el participante
  INSTRUCTOR_GUIDE.md   Para el organizador (solución, teoría, rúbrica, montaje)
```

## Cómo levantar y probar

```bash
cd banco_app
docker compose up -d --build      # http://localhost:5000
```

Sin Docker: `pip install -r requirements.txt && python seed.py && python app.py`.

Validar el ataque completo (imprime el código ganador):

```bash
cd banco_app
python solve.py
```

Resetear el entorno entre participantes: `docker compose restart` (seed.py
recrea la base con claves nuevas en cada arranque; no hay estado persistente).

## Diseño del desafío (para no romperlo sin querer)

- **El servidor NO guarda claves privadas** (como FIDO2 real): solo públicas, en
  la tabla `credentials`. Cada passkey se genera en el cliente (`script.js` con
  WebCrypto, o el atacante en Python) y su privada nunca viaja.
- **La única VULN (binding credencial→usuario):** en `POST /auth/verify` el
  server valida que la firma sea correcta para la clave pública de la credencial
  presentada, pero **no** valida que esa credencial pertenezca al `username`
  reclamado. Falta, a propósito, el chequeo `credential["user_id"] == user["id"]`.
  No agregar ese chequeo salvo que se quiera "arreglar" el desafío.
- **El ataque:** registrar una passkey propia en una cuenta con registro abierto
  (`POST /auth/register` sobre `alumno`), pedir un challenge del `ceo`, firmarlo
  con la clave propia y mandar `POST /auth/verify` con `username: ceo` +
  `credential_id` propio → entra como CEO.
- **Anti-atajo:** el `ceo` tiene `passkey_registration_open=0` (registro
  cerrado, passkey aprovisionada en el seed), así nadie puede simplemente
  registrar una passkey nueva para el CEO. Mantener ese flag en 0 para el CEO.
- **Cripto:** ECDSA **P-256 (secp256r1)**. La firma en el "cable" es **raw r‖s
  (64 bytes) en hex** (formato WebCrypto); el servidor la convierte a DER para
  verificar. `script.js` y `solve.py` dependen de esta convención.
- **Flag:** MD5 ficticio en `seed.py` (`CEO_WINNING_CODE`), determinístico.

## Convenciones

- Todo el proyecto y su documentación están en **español (es-AR)**.
- SQL siempre **parametrizado** (el desafío es de autorización/cripto, no de
  inyección SQL — mantenerlo así para no dispersar el foco pedagógico).
- Comentarios del backend: explican *dónde* está cada vulnerabilidad intencional
  y *por qué*, para el organizador.

## Nota sobre `HackerTech/`

Si existe una carpeta `HackerTech/`, es un **clon de referencia de otro repo**
(la versión con WebAuthn real de la que se tomó el diseño visual). Está en
`.gitignore` y **no forma parte** de este proyecto.
