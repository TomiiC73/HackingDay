"""
Capa de acceso a datos (DAO) del CTF passwordless.

Toda consulta usa placeholders "?" de sqlite3 (parametrizada): el desafio no es
de inyeccion SQL. Los pecados son un IDOR (que filtra el credential_id de otros
usuarios) y un Stored XSS (el inbox del CEO renderiza mensajes sin sanitizar),
que juntos permiten robar la clave privada del CEO.

Modelo de datos (como FIDO2 real, el servidor solo guarda claves PUBLICAS):
  - users        : las cuentas.
  - credentials  : las passkeys registradas (solo la clave PUBLICA).
  - messages     : "mensajes al administrador" que el CEO ve en su inbox (XSS).
  - collected    : buzon donde el payload XSS exfiltra lo que roba.
  - bot_requests : cola de "pedidos" para que el bot CEO visite su inbox.
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
    with get_connection() as conn:
        conn.executescript(
            """
            DROP TABLE IF EXISTS bot_requests;
            DROP TABLE IF EXISTS collected;
            DROP TABLE IF EXISTS messages;
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
                role TEXT NOT NULL,              -- 'practica', 'ceo', 'senuelo'
                -- Si la cuenta permite auto-registrar passkeys por la web. El
                -- CEO lo tiene en 0 (su passkey la aprovisiona el seed), asi
                -- nadie puede registrarle una passkey nueva y entrar sin robar
                -- su clave privada.
                passkey_registration_open INTEGER NOT NULL DEFAULT 1,
                balance_ars REAL NOT NULL DEFAULT 0,
                cbu TEXT NOT NULL DEFAULT '',
                alias TEXT NOT NULL DEFAULT '',
                account_note TEXT NOT NULL DEFAULT '',
                winning_code TEXT
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                credential_id TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                public_key_pem TEXT NOT NULL,    -- SOLO la clave publica
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_username TEXT NOT NULL,
                body TEXT NOT NULL,              -- se renderiza SIN sanitizar (XSS)
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS collected (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS bot_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_at TEXT DEFAULT (datetime('now')),
                done INTEGER NOT NULL DEFAULT 0,
                url TEXT                          -- URL que el agente debe visitar
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
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


# --------------------------------------------------------------------
# Credenciales (passkeys) - solo clave publica
# --------------------------------------------------------------------
def add_credential(credential_id, user_id, public_key_pem):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO credentials (credential_id, user_id, public_key_pem) VALUES (?, ?, ?)",
            (credential_id, user_id, public_key_pem),
        )


def get_credential(credential_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()
        return dict(row) if row else None


def get_primary_credential_for_user(user_id):
    """La credencial (mas reciente) de un usuario. Es lo que devuelve el
    endpoint con IDOR: credential_id + clave publica (nunca la privada)."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM credentials WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


# --------------------------------------------------------------------
# Mensajes al administrador (superficie del Stored XSS)
# --------------------------------------------------------------------
def add_message(from_username, body):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO messages (from_username, body) VALUES (?, ?)",
            (from_username, body),
        )


def get_all_messages():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM messages ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]


# --------------------------------------------------------------------
# Buzon de exfiltracion
# --------------------------------------------------------------------
def add_collected(data):
    with get_connection() as conn:
        conn.execute("INSERT INTO collected (data) VALUES (?)", (data,))


def get_all_collected():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM collected ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


# --------------------------------------------------------------------
# Cola del bot CEO (disparo por "ingenieria social")
# --------------------------------------------------------------------
def enqueue_bot_visit(url=None):
    with get_connection() as conn:
        conn.execute("INSERT INTO bot_requests (url) VALUES (?)", (url,))


def last_bot_request_epoch():
    """Segundos (epoch) del ultimo pedido, para el rate-limit. None si no hay."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT strftime('%s', requested_at) AS ts FROM bot_requests ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return int(row["ts"]) if row and row["ts"] is not None else None


def take_pending_bot_visit():
    """Marca como hecho el pedido pendiente mas viejo y devuelve su dict
    {id, url} (o None). Lo usa el agente para saber que URL visitar."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, url FROM bot_requests WHERE done = 0 ORDER BY id ASC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        conn.execute("UPDATE bot_requests SET done = 1 WHERE id = ?", (row["id"],))
        return {"id": row["id"], "url": row["url"]}
