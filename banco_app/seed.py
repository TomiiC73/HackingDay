"""
Siembra de datos del CTF passwordless (HackerBank / Hacking Day Cordoba).

Borra y recrea la base en CADA corrida. Como en FIDO2 real, el servidor NO
guarda claves privadas: a cada cuenta se le aprovisiona una passkey guardando
solo su clave PUBLICA.

Usuarios:
  - t3ny     -> cuenta de practica (el "atacante"). Registra su passkey al
                loguearse (el navegador genera el par); arranca sin credencial.
  - ceo      -> tiene el CODIGO GANADOR (flag). Arranca SIN credencial y con el
                registro cerrado: su passkey la genera el contenedor del agente
                (agente/agent.py), que guarda la privada en SU localStorage y
                aprovisiona solo la PUBLICA al banco por un endpoint interno. El
                banco nunca ve la privada del CEO.
  - senuelos -> con passkey sembrada (para que el IDOR de /auth/keys tenga a
                quien enumerar), registro abierto.

Uso:
    python seed.py
"""
import config
import crypto_utils
import db

CEO_WINNING_CODE = "f27ad11c21afef4f4c54a3930698f616"

# (id, username, display_name, role, registration_open, balance_ars, cbu, alias, account_note, winning_code)
USERS = [
    (7042, config.PRACTICE_USERNAME, "Usuario de práctica", "practica", 1,
     184320.50, "0000007000042000042001", "practica.hb",
     "Cuenta de práctica del laboratorio. Registrá tu passkey y logueate para entender el flujo.",
     None),
    (7013, "ceo", "Ricardo Vega — CEO de HackerBank", "ceo", 0,
     98750000.00, "0000007000013000013001", "ricardo.vega.ceo",
     "Cuenta ejecutiva. Passkey aprovisionada por IT.",
     CEO_WINNING_CODE),
    (7025, "lmoreno", "Lucía Moreno", "senuelo", 1,
     642100.00, "0000007000025000025001", "lucia.moreno.hb", "Caja de ahorro en pesos.", None),
    (7031, "dferreyra", "Diego Ferreyra", "senuelo", 1,
     1230500.75, "0000007000031000031001", "diego.ferreyra.hb", "Caja de ahorro en pesos.", None),
    (7058, "sibarra", "Sofía Ibarra", "senuelo", 1,
     58900.00, "0000007000058000058001", "sofia.ibarra.hb", "Caja de ahorro en pesos.", None),
]


def seed():
    db.reset_db()
    db.init_db()
    for (user_id, username, display_name, role, registration_open, balance_ars,
         cbu, alias, account_note, winning_code) in USERS:
        db.insert_user(
            user_id=user_id, username=username, display_name=display_name, role=role,
            passkey_registration_open=registration_open, balance_ars=balance_ars,
            cbu=cbu, alias=alias, account_note=account_note, winning_code=winning_code,
        )
        extra = ""
        if role == "senuelo":
            # Senuelos: passkey sembrada (solo la publica) para que el IDOR de
            # /auth/keys tenga a quien enumerar junto al CEO.
            priv_b64, pub_pem = crypto_utils.generate_credential()
            cred_id = crypto_utils.generate_credential_id()
            db.add_credential(cred_id, user_id, pub_pem)
            extra = "  [passkey aprovisionada]"
        elif role == "ceo":
            # El CEO arranca SIN credencial: la aprovisiona el agente al arrancar
            # (genera el par en su navegador, guarda la privada en su localStorage
            # y manda solo la publica por /internal/provision-ceo). Registro
            # cerrado para que nadie le registre una passkey nueva por la web.
            extra = "  [sin credencial -> la aprovisiona el agente]"
        print(f"  [{role:8}] id={user_id}  {username:10}  ({display_name}){extra}")
    print()
    print(f"Cuenta de practica: '{config.PRACTICE_USERNAME}'. Flag del CEO: {CEO_WINNING_CODE}")


if __name__ == "__main__":
    print("Sembrando datos del CTF passwordless...\n")
    seed()
