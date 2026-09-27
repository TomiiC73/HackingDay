# HackerBank — CTF "Passwordless de Cartón"

Desafío de ciberseguridad (CTF) **educativo y ético** para el **Hacking Day de
Córdoba**, orientado a estudiantes de Ingeniería en Sistemas que están
aprendiendo sobre autenticación **passwordless / FIDO2 / WebAuthn**.

> ⚠️ **Entorno educativo.** HackerBank es un banco ficticio. No procesa dinero
> real, no está conectado a ningún sistema bancario y todas las credenciales,
> cuentas y el "código ganador" son inventados. La app está **rota a
> propósito** para que se pueda atacar y así entender, por contraste, cómo
> funciona FIDO2 real.

## La idea

HackerBank promociona un login "passwordless y biométrico, seguro como una
passkey". Y hasta guarda las claves bien: **como FIDO2 real, el servidor solo
guarda claves públicas** — la privada de cada passkey vive del lado del cliente
y nunca viaja. No hay ninguna clave que robar.

El problema es más sutil: cuando verificás tu identidad, el servidor comprueba
que tu firma sea válida, pero **no comprueba de quién es la credencial que
firma**. Le falta el *binding* entre la credencial y el usuario. El objetivo del
desafío es aprovechar eso: **registrar tu propia passkey y usarla para entrar a
la cuenta del CEO** y leer el código ganador.

El aprendizaje: un servidor WebAuthn correcto siempre verifica la firma contra
las credenciales **registradas de ese usuario** (`allowCredentials`), nunca
contra cualquier credencial válida. Sin ese chequeo, tu passkey sirve para
entrar como cualquiera.

## Cómo se juega (resumen)

La herramienta protagonista es **Burp Suite**, apoyada por las DevTools del
navegador y un poco de Python:

1. **Reconocimiento:** mapear el flujo passwordless (`/auth/register` →
   `/auth/challenge` → `/auth/verify`) logueándote con el usuario de práctica
   `alumno`, que registra su passkey y entra.
2. **Registrás tu passkey:** generás tu propio par de claves y registrás la
   pública en una cuenta con registro abierto (`alumno`). Tu clave privada nunca
   sale de tu lado.
3. **Suplantás al CEO:** pedís un challenge del `ceo`, lo firmás con **tu**
   clave y lo mandás a `/auth/verify` con `username: ceo` pero **tu**
   `credential_id`. Como el server no valida el binding, entrás como CEO →
   **código ganador** (un hash MD5).

El writeup completo, con requests exactos y el script de resolución, está en
[`INSTRUCTOR_GUIDE.md`](INSTRUCTOR_GUIDE.md) (material para el organizador).

## Requisitos

- **Docker** + Docker Compose (forma recomendada), **o**
- **Python 3.10+** para correrlo sin Docker.

## Cómo levantarlo

### Opción A — Docker (recomendada)

```bash
cd banco_app
docker compose up -d --build
```

La app queda en **http://localhost:5000**. `seed.py` corre solo en cada
arranque y **recrea la base desde cero** (resiembra los usuarios y le aprovisiona
al CEO su passkey), así el entorno queda limpio para el próximo participante.
Para resetear entre participantes: `docker compose restart`.

### Opción B — Python local

```bash
cd banco_app
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
python seed.py               # siembra la base (usuarios + passkey del CEO)
python app.py                # levanta Flask en el puerto 5000
```

## Usuarios de laboratorio

| Usuario  | Rol                | Para qué sirve |
|----------|--------------------|----------------|
| `alumno` | práctica           | Registra su passkey y entra: sirve para entender el flujo y para dejar ahí tu credencial. |
| `ceo`    | objetivo           | Su cuenta contiene el código ganador (la flag). Registro de passkeys cerrado. |
| `lmoreno`, `dferreyra`, `sibarra` | señuelos | Cuentas de relleno con registro abierto. |

No hay contraseñas: el único "factor" es la firma del challenge. Que esa firma
no esté atada al usuario correcto es, justamente, el problema que el desafío
expone.

## Verificar la solución

El repositorio incluye [`solve.py`](solve.py), la solución de referencia que
ejecuta el ataque y termina imprimiendo el código ganador:

```bash
pip install requests cryptography
python solve.py                      # contra http://localhost:5000
```

## Stack técnico

- **Backend:** Python + Flask.
- **Criptografía:** ECDSA con curva **P-256 (secp256r1)** — la misma de
  WebAuthn real — vía la librería `cryptography`.
- **Base de datos:** SQLite.
- **Frontend:** HTML + CSS (Tailwind CDN) + JavaScript vanilla; la passkey se
  genera con **WebCrypto** y su clave privada nunca sale del navegador.

## Estructura

```
app.py            Rutas Flask: páginas + API del flujo passwordless (vuln marcada con VULN)
config.py         Configuración centralizada
db.py             Acceso a datos SQLite (parametrizado): tablas users y credentials
crypto_utils.py   Generación de par (para el seed) y verificación de firma
seed.py           Siembra usuarios; aprovisiona la passkey del CEO (solo pública)
solve.py          Solución de referencia (writeup ejecutable)
static/js/script.js   Passkey WebCrypto: genera par, registra y firma el login
templates/        landing.html, login.html, dashboard.html, _fido2_diagram.html
INSTRUCTOR_GUIDE.md   Guía del organizador: solución paso a paso, teoría y rúbrica
```
