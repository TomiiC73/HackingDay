"""
Siembra de datos del CTF passwordless (HackerBank / Hacking Day Cordoba).

Borra y recrea la base en CADA corrida, generando un par de claves ECDSA P-256
nuevo para cada usuario y guardando la privada "ofuscada" (ver crypto_utils).
Asi cada arranque del contenedor deja el entorno limpio y reproducible, ideal
para resetear entre participantes.

Usuarios (IDs cortos y enumerables, en el rango 70xx, NO 1/2 para que el
alumno tenga que descubrirlos):
  - 7042  alumno   -> el estudiante se loguea normalmente para aprender el flujo
  - 7013  ceo      -> su cuenta contiene el CODIGO GANADOR (la flag)
  - 7025  senuelo  (Lucia Moreno)
  - 7031  senuelo  (Diego Ferreyra)
  - 7058  senuelo  (Sofia Ibarra)

Uso:
    python seed.py
"""
import crypto_utils
import db

# Codigo ganador (flag) ficticio, formato MD5 para ser coherente con la
# plataforma softwareseguro.com.ar. Es
# md5("hackerbank-passwordless-de-carton-hackingday-cba-2026").
CEO_WINNING_CODE = "f27ad11c21afef4f4c54a3930698f616"

# (id, username, display_name, role, balance_ars, cbu, alias, account_note, winning_code)
USERS = [
    (7042, "alumno", "Alumno de Prueba", "alumno",
     184320.50, "0000007000042000042001", "alumno.hb",
     "Cuenta de práctica del laboratorio. Usá este usuario para entender el flujo.",
     None),
    (7013, "ceo", "Ricardo Vega — CEO de HackerBank", "ceo",
     98750000.00, "0000007000013000013001", "ricardo.vega.ceo",
     "Cuenta ejecutiva. Acceso restringido.",
     CEO_WINNING_CODE),
    (7025, "lmoreno", "Lucía Moreno", "senuelo",
     642100.00, "0000007000025000025001", "lucia.moreno.hb",
     "Caja de ahorro en pesos.", None),
    (7031, "dferreyra", "Diego Ferreyra", "senuelo",
     1230500.75, "0000007000031000031001", "diego.ferreyra.hb",
     "Caja de ahorro en pesos.", None),
    (7058, "sibarra", "Sofía Ibarra", "senuelo",
     58900.00, "0000007000058000058001", "sofia.ibarra.hb",
     "Caja de ahorro en pesos.", None),
]


def seed():
    db.reset_db()
    db.init_db()
    for (user_id, username, display_name, role, balance_ars, cbu, alias,
         account_note, winning_code) in USERS:
        priv_pem, pub_pem = crypto_utils.generate_keypair_pem()
        obfuscated = crypto_utils.obfuscate_private_key(priv_pem)
        db.insert_user(
            user_id=user_id,
            username=username,
            display_name=display_name,
            role=role,
            public_key_pem=pub_pem,
            private_key_obfuscated=obfuscated,
            balance_ars=balance_ars,
            cbu=cbu,
            alias=alias,
            account_note=account_note,
            winning_code=winning_code,
        )
        print(f"  [{role:8}] id={user_id}  {username:10}  ({display_name})")
    print()
    print("Base sembrada. Usuario de practica: 'alumno' (id 7042).")
    print(f"Flag en la cuenta del CEO (id 7013): {CEO_WINNING_CODE}")


if __name__ == "__main__":
    print("Sembrando datos del CTF passwordless...\n")
    seed()
