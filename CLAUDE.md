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
  app.py            Rutas Flask + API del flujo passwordless (vulns marcadas con VULN)
  config.py         Configuración (incluye BACKUP_KEY, la clave del XOR)
  db.py             DAO SQLite parametrizado
  crypto_utils.py   ECDSA P-256: generación de claves, (de)codificación, verificación de firma
  seed.py           Recrea la base y siembra usuarios (alumno, ceo, señuelos) con sus claves
  solve.py          Solución de referencia (writeup ejecutable)
  static/js/script.js   (De)codificación + firma WebCrypto + flujo de login del frontend
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

- **La cadena de ataque tiene 3 capas:** (1) reconocer el flujo `challenge →
  keys → verify`; (2) IDOR en `GET /auth/keys/<user_id>` + decodificar la clave
  privada leyendo `script.js`; (3) firmar un challenge del CEO con la clave
  robada y hacer `POST /auth/verify`.
- **Cripto:** ECDSA **P-256 (secp256r1)**, la misma curva de WebAuthn real. La
  firma en el "cable" es **raw r‖s (64 bytes) en hex** (formato WebCrypto); el
  servidor la convierte a DER para verificar. Mantener esta convención: el
  frontend (`script.js`) y `solve.py` dependen de ella.
- **Codificación:** `base64(XOR(base64(PEM), BACKUP_KEY))`. La `BACKUP_KEY`
  está **a propósito** duplicada en `config.py` (server) y `script.js` (cliente).
  Si se cambia, cambiarla en ambos lados.
- **user_id:** en el rango `70xx` (no 1/2) para forzar la enumeración; la
  respuesta del IDOR incluye `username`/`display_name` para que se pueda
  identificar al CEO al enumerar. `alumno=7042`, `ceo=7013`.
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
