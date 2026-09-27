"""
Capa de acceso a datos (DAO) del CTF passwordless.

Toda consulta usa placeholders "?" de sqlite3 (parametrizada): el desafio no es
de inyeccion SQL, es de AUTORIZACION (falta de binding credencial->usuario en
/auth/verify). Se mantiene el codigo limpio en ese aspecto para que el foco
pedagogico quede en el flujo passwordless.

Modelo de datos (como FIDO2 real):
  - `users`: la cuenta. NO guarda ninguna clave.
  - `credentials`: las passkeys registradas. Solo la clave PUBLICA de cada una;
    la privada vive del lado del cliente y nunca llega al servidor.

Cada credencial pertenece a un usuario (columna user_id). El "pecado" del
desafio es que /auth/verify no usa esa pertenencia para nada (ver app.py).
"""
import sqlite3
from contextlib import contextmanager

from config import DATABASE_PATH


@contextmanager
def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def reset_db():
    """Borra el esquema entero para recrearlo desde cero. seed.py lo usa asi
    cada arranque del contenedor empieza limpio (util para resetear el entorno
    entre participantes del evento)."""
    with get_connection() as conn:
        conn.executescript(
            """
            DROP TABLE IF EXISTS credentials;
            DROP TABLE IF EXISTS users;
            """
        )


def init_db():
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,              -- 'alumno', 'ceo', 'senuelo'
                -- Si esta cuenta permite auto-registrar passkeys por la web.
                -- El CEO lo tiene en 0 (su passkey la aprovisiona IT): asi el
                -- atacante no puede simplemente registrar una passkey nueva
                -- para el CEO, y se ve forzado a la confusion de credencial.
                passkey_registration_open INTEGER NOT NULL DEFAULT 1,
                balance_ars REAL NOT NULL DEFAULT 0,
                cbu TEXT NOT NULL DEFAULT '',
                alias TEXT NOT NULL DEFAULT '',
                account_note TEXT NOT NULL DEFAULT '',
                winning_code TEXT               -- solo el CEO lo tiene (la flag)
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                public_key_pem TEXT NOT NULL,    -- SOLO la clave publica
                created_at TEXT DEFAULT (datetime('now'))
            );
            """
        )


# --------------------------------------------------------------------
# Usuarios
# --------------------------------------------------------------------
def insert_user(user_id, username, display_name, role, balance_ars, cbu, alias,
                account_note, passkey_registration_open=1, winning_code=None):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users
                (id, username, display_name, role, passkey_registration_open,
                 balance_ars, cbu, alias, account_note, winning_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, display_name, role, passkey_registration_open,
             balance_ars, cbu, alias, account_note, winning_code),
        )


def get_user_by_username(username):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None


# --------------------------------------------------------------------
# Credenciales (passkeys)
# --------------------------------------------------------------------
def add_credential(credential_id, user_id, public_key_pem):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO credentials (credential_id, user_id, public_key_pem)
            VALUES (?, ?, ?)
            """,
            (credential_id, user_id, public_key_pem),
        )


def get_credential(credential_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()
        return dict(row) if row else None


def get_credential_ids_for_user(user_id):
    """Los credential_id de un usuario (lo que un cliente honesto usaria como
    allowCredentials). El atacante los ignora: esa es la gracia del desafio."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT credential_id FROM credentials WHERE user_id = ?", (user_id,)
        ).fetchall()
        return [r["credential_id"] for r in rows]
