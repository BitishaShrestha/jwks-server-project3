"""User registration and auth logging, stored in the same SQLite database."""

import sqlite3
import uuid
from contextlib import closing

from argon2 import PasswordHasher

from keys import DB_FILE

CREATE_USERS_SQL = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
"""

CREATE_AUTH_LOGS_SQL = """
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
"""


def make_password_hasher():
    """Argon2id hasher with the settings this project uses.

    time_cost: 3 passes, memory_cost: 64 MiB, parallelism: 4 lanes,
    hash_len: 32 byte hash, salt_len: 16 byte random salt per password.
    """
    return PasswordHasher(
        time_cost=3,
        memory_cost=64 * 1024,  # in KiB
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )


class UsernameTakenError(Exception):
    """Raised when the username or email is already registered."""


class UserStore:
    """Users table and auth_logs table. All queries use ? placeholders."""

    def __init__(self, db_path=DB_FILE, hasher=None):
        self.db_path = db_path
        self.hasher = hasher or make_password_hasher()
        with closing(self._connect()) as conn, conn:
            conn.execute(CREATE_USERS_SQL)
            conn.execute(CREATE_AUTH_LOGS_SQL)

    def _connect(self):
        """Open a connection with foreign keys on (SQLite turns them off by default)."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def register(self, username, email=None):
        """Create a user with a random UUIDv4 password and return the password.

        Only the Argon2 hash is stored; the plain password is returned once
        and never saved.
        """
        password = str(uuid.uuid4())
        password_hash = self.hasher.hash(password)
        try:
            with closing(self._connect()) as conn, conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash, email) "
                    "VALUES (?, ?, ?)",
                    (username, password_hash, email),
                )
        except sqlite3.IntegrityError as err:
            raise UsernameTakenError(str(err)) from err
        return password

    def find_user_id(self, username):
        """Return the id for a username, or None if there's no such user."""
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row[0] if row else None

    def log_auth(self, request_ip, user_id):
        """Record one successful /auth request and update the user's last_login."""
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
                (request_ip, user_id),
            )
            if user_id is not None:
                conn.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user_id,),
                )
