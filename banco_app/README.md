# HackerBank — CTF "Passwordless de Cartón"

Desafío de ciberseguridad (CTF) **educativo y ético** para el **Hacking Day de
Córdoba**, sobre autenticación **passwordless / FIDO2 / WebAuthn**.

> ⚠️ **Entorno educativo.** HackerBank es un banco ficticio. No procesa dinero
> real y todo (cuentas, CEO, "código ganador") es inventado. La app está **rota
> a propósito** para atacarla y entender, por contraste, cómo funciona FIDO2 real.

## La idea

HackerBank guarda las claves *casi* bien: como FIDO2 real, el servidor solo
almacena **claves públicas**. Pero comete el pecado de dejar la **clave privada
de cada passkey en `localStorage`** (accesible por JavaScript). Combinado con un
**Stored XSS**, eso permite robar la clave privada del CEO y entrar a su cuenta.

El aprendizaje: en FIDO2 real la clave privada vive en hardware (TPM/Secure
Enclave) y **JavaScript nunca puede leerla** — el mismo XSS no robaría nada.

## Cómo se juega (resumen)

Herramientas: **Burp Suite**, **DevTools** del navegador y un poco de Python.

1. **Reconocimiento:** login de la cuenta de práctica `t3ny` en `/login` y
   análisis del flujo passwordless (`register → challenge → keys → verify`).
2. **IDOR:** `GET /auth/keys/<id>` filtra el `credential_id` de cualquier usuario;
   enumerando se identifica al **CEO** y se guarda su `credential_id`.
3. **Stored XSS:** se deja un mensaje con un payload en "Mensajes al
   administrador"; con la ingeniería social se fuerza al **bot CEO** a leer su
   bandeja, y el payload roba su **clave privada** de `localStorage`.
4. **Firma:** con el `credential_id` (paso 2) y la clave robada (paso 3) se firma
   un challenge fresco del CEO (desde la consola con `hbForge()`) y se entra →
   **código ganador**.

El writeup completo está en [`INSTRUCTOR_GUIDE.md`](INSTRUCTOR_GUIDE.md).

## Requisitos

- **Docker** + Docker Compose (recomendado). El build baja la imagen oficial de
  Playwright (trae Chromium para el bot CEO), así que la primera vez tarda.

## Cómo levantarlo

```bash
cd banco_app
docker compose up -d --build
```

La app queda en **http://localhost:5000**. El contenedor corre el `seed`, la app
y el **bot CEO** (headless) juntos. `seed.py` recrea la base en cada arranque.
Para resetear entre participantes: `docker compose restart`.

## Usuarios de laboratorio

| Usuario  | Rol      | Para qué sirve |
|----------|----------|----------------|
| `t3ny`   | práctica | La cuenta del "atacante": registra su passkey y entra; desde ahí deja mensajes y ataca. |
| `ceo`    | objetivo | Su cuenta tiene el código ganador. La revisa un bot (la víctima del XSS). |
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
- **Bot víctima:** Playwright + Chromium headless (`bot.py`).
- **Frontend:** HTML + CSS + JavaScript vanilla; la passkey se genera con
  WebCrypto y su clave privada vive en `localStorage`.

## Estructura

```
app.py            Rutas Flask: páginas + API passwordless + mensajes/inbox/collect
config.py         Configuración (usuario de práctica, TTL, cooldown, rutas)
db.py             SQLite: users, credentials, messages, collected, bot_requests
crypto_utils.py   Generar par (seed) y verificar firma
seed.py           Siembra usuarios; aprovisiona la passkey del CEO (ceo_passkey.json)
bot.py            Bot "CEO" headless (Playwright) — la víctima del Stored XSS
solve.py          Solución de referencia (writeup ejecutable)
static/js/script.js   Passkey WebCrypto + funciones de consola (signChallenge, hbForge)
templates/        landing, login, dashboard, mensajes, inbox, collected, _fido2_diagram
INSTRUCTOR_GUIDE.md   Guía del organizador: solución, teoría, rúbrica y montaje
```
