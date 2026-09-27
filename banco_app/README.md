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
passkey". Pero un desarrollador junior lo implementó copiando el flujo de FIDO2
**sin entenderlo**: la clave privada de cada usuario está guardada del lado del
servidor y es accesible por la red. El objetivo del desafío es **robar la clave
privada del CEO, firmar un challenge en su nombre y entrar a su cuenta** para
leer el código ganador.

El pecado capital que enseña el desafío: *tener una clave privada accesible del
lado del cliente o del servidor.* FIDO2 real es seguro justamente porque la
clave privada vive en hardware inextraíble (TPM/Secure Enclave) y solo viajan
la clave pública y las firmas.

## Cómo se juega (resumen)

La herramienta protagonista es **Burp Suite**, apoyada por las DevTools del
navegador y un poco de Python. La cadena de ataque tiene 3 capas:

1. **Reconocimiento:** mapear el flujo pseudo-WebAuthn (`/auth/challenge` →
   firma → `/auth/verify`) logueándose con el usuario de práctica `alumno`.
2. **Robo de la clave:** descubrir el endpoint `/auth/keys/<user_id>` con
   **IDOR** (no valida autorización), enumerar los `user_id` para encontrar al
   CEO y descargar su clave privada **codificada**; leer el JS del frontend para
   decodificarla.
3. **Suplantación:** firmar con Python un challenge fresco del CEO usando la
   clave robada y enviarlo a `/auth/verify` → login como CEO → **código
   ganador** (un hash MD5).

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
arranque y **recrea la base desde cero** (genera claves nuevas y resiembra los
usuarios), así el entorno queda limpio para el próximo participante. Para
resetear entre participantes: `docker compose restart`.

### Opción B — Python local

```bash
cd banco_app
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
python seed.py               # siembra la base (usuarios + claves)
python app.py                # levanta Flask en el puerto 5000
```

## Usuarios de laboratorio

| Usuario  | Rol                | Para qué sirve |
|----------|--------------------|----------------|
| `alumno` | práctica           | Loguearse normalmente y entender el flujo passwordless. |
| `ceo`    | objetivo           | Su cuenta contiene el código ganador (la flag). |
| `lmoreno`, `dferreyra`, `sibarra` | señuelos | Para que la enumeración de `user_id` tenga sentido. |

No hay contraseñas: el único "factor" es la firma del challenge. Ese es,
justamente, el problema que el desafío expone.

## Verificar la solución

El repositorio incluye [`solve.py`](solve.py), la solución de referencia que
encadena las 3 capas y termina imprimiendo el código ganador:

```bash
pip install requests cryptography
python solve.py                      # contra http://localhost:5000
```

## Stack técnico

- **Backend:** Python + Flask.
- **Criptografía:** ECDSA con curva **P-256 (secp256r1)** — la misma de
  WebAuthn real — vía la librería `cryptography`.
- **Base de datos:** SQLite.
- **Frontend:** HTML + CSS (Tailwind CDN) + JavaScript vanilla, con la función
  de (de)codificación de la clave a la vista.

## Estructura

```
app.py            Rutas Flask: páginas + API del flujo passwordless (con las vulns marcadas)
config.py         Configuración centralizada (incluye la clave de "codificación")
db.py             Acceso a datos SQLite (parametrizado)
crypto_utils.py   Generación de claves, codificación y verificación de firma
seed.py           Siembra usuarios (alumno, ceo, señuelos) con sus pares de claves
solve.py          Solución de referencia (writeup ejecutable)
static/js/script.js   (De)codificación + firma WebCrypto + flujo de login del frontend
templates/        landing.html, login.html, dashboard.html, _fido2_diagram.html
INSTRUCTOR_GUIDE.md   Guía del organizador: solución paso a paso, teoría y rúbrica
```
