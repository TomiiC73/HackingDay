"""
Capa de acceso a datos (DAO) del CTF passwordless.

Toda consulta usa placeholders "?" de sqlite3 (parametrizada), asi el IDOR del
desafio NO es una inyeccion SQL: la vulnerabilidad es de AUTORIZACION (se
puede pedir la clave de cualquier user_id), no de inyeccion. Se mantiene el
codigo limpio en ese aspecto para que el foco pedagogico quede en el flujo
passwordless y no se disperse.

Tabla `users` (VULNERABILIDAD INTENCIONAL): guarda tanto la clave publica como
la PRIVADA "codificada". En FIDO2 real solo existiria la publica.
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
        conn.executescript("DROP TABLE IF EXISTS users;")


def init_db():
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,          -- id "corto" no autoincremental (enumerable)
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,              -- 'alumno', 'ceo', 'senuelo'
                -- Par de claves ECDSA P-256 del usuario:
                public_key_pem TEXT NOT NULL,
                private_key TEXT NOT NULL,   -- <- el pecado (Capa 2)
                -- Datos de presentacion de la cuenta:
                balance_ars REAL NOT NULL DEFAULT 0,
                cbu TEXT NOT NULL DEFAULT '',
                alias TEXT NOT NULL DEFAULT '',
                account_note TEXT NOT NULL DEFAULT '',
                winning_code TEXT               -- solo el CEO lo tiene (la flag)
            );
            """
        )


def insert_user(user_id, username, display_name, role, public_key_pem,
                private_key, balance_ars, cbu, alias, account_note,
                winning_code=None):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users
                (id, username, display_name, role, public_key_pem,
                 private_key, balance_ars, cbu, alias, account_note,
                 winning_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, display_name, role, public_key_pem,
             private_key, balance_ars, cbu, alias, account_note,
             winning_code),
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
