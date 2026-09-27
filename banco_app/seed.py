"""
Siembra de datos del CTF passwordless (HackerBank / Hacking Day Cordoba).

Borra y recrea la base en CADA corrida. Como en FIDO2 real, el servidor NO
guarda claves privadas: al CEO se le aprovisiona una passkey guardando solo su
clave publica (la privada se genera y se descarta aca mismo, nadie la conserva).

Usuarios:
  - alumno    -> cuenta de practica. Registro de passkeys ABIERTO (registration_open=1).
  - ceo       -> tiene el CODIGO GANADOR (flag) y una passkey ya aprovisionada.
                 Registro de passkeys CERRADO (registration_open=0): nadie puede
                 auto-registrarle una passkey nueva, asi el atacante se ve
                 forzado a la confusion de credencial (usar SU passkey contra el
                 username del CEO en /auth/verify).
  - senuelos  -> cuentas de relleno, registro abierto.

Uso:
    python seed.py
"""
import crypto_utils
import db

# Codigo ganador (flag) ficticio, formato MD5 para ser coherente con la
# plataforma softwareseguro.com.ar. Es
# md5("hackerbank-passwordless-de-carton-hackingday-cba-2026").
CEO_WINNING_CODE = "f27ad11c21afef4f4c54a3930698f616"

# (id, username, display_name, role, registration_open, balance_ars, cbu, alias, account_note, winning_code)
USERS = [
    (7042, "alumno", "Alumno de Prueba", "alumno", 1,
     184320.50, "0000007000042000042001", "alumno.hb",
     "Cuenta de práctica del laboratorio. Registrá tu passkey y logueate para entender el flujo.",
     None),
    (7013, "ceo", "Ricardo Vega — CEO de HackerBank", "ceo", 0,
     98750000.00, "0000007000013000013001", "ricardo.vega.ceo",
     "Cuenta ejecutiva. Passkey aprovisionada por IT; auto-registro deshabilitado.",
     CEO_WINNING_CODE),
    (7025, "lmoreno", "Lucía Moreno", "senuelo", 1,
     642100.00, "0000007000025000025001", "lucia.moreno.hb",
     "Caja de ahorro en pesos.", None),
    (7031, "dferreyra", "Diego Ferreyra", "senuelo", 1,
     1230500.75, "0000007000031000031001", "diego.ferreyra.hb",
     "Caja de ahorro en pesos.", None),
    (7058, "sibarra", "Sofía Ibarra", "senuelo", 1,
     58900.00, "0000007000058000058001", "sofia.ibarra.hb",
     "Caja de ahorro en pesos.", None),
]


def seed():
    db.reset_db()
    db.init_db()
    for (user_id, username, display_name, role, registration_open, balance_ars,
         cbu, alias, account_note, winning_code) in USERS:
        db.insert_user(
            user_id=user_id,
            username=username,
            display_name=display_name,
            role=role,
            passkey_registration_open=registration_open,
            balance_ars=balance_ars,
            cbu=cbu,
            alias=alias,
            account_note=account_note,
            winning_code=winning_code,
        )
        # Al CEO se le aprovisiona una passkey (solo la clave publica; la
        # privada se descarta). El resto arranca sin passkey y la registra.
        extra = ""
        if role == "ceo":
            _priv_pem, pub_pem = crypto_utils.generate_keypair_pem()
            cred_id = crypto_utils.generate_credential_id()
            db.add_credential(cred_id, user_id, pub_pem)
            extra = "  [passkey aprovisionada, registro cerrado]"
        print(f"  [{role:8}] id={user_id}  {username:10}  ({display_name}){extra}")
    print()
    print("Base sembrada. Usuario de practica: 'alumno'.")
    print(f"Flag en la cuenta del CEO: {CEO_WINNING_CODE}")


if __name__ == "__main__":
    print("Sembrando datos del CTF passwordless...\n")
    seed()
