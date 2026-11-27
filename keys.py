"""RSA key generation and encrypted SQLite storage for the JWKS server."""

import base64
import hashlib
import os
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB_FILE = "totally_not_my_privateKeys.db"

# Name of the environment variable that holds the AES secret.
AES_KEY_ENV = "NOT_MY_KEY"
NONCE_SIZE = 12  # 96 bit nonce, the recommended size for AES-GCM

# How long the valid key lasts, and how long ago the expired key "expired".
VALID_KEY_LIFETIME = 60 * 60  # 1 hour
EXPIRED_KEY_AGE = 60 * 60  # expired 1 hour ago

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""


@dataclass
class KeyRecord:
    """One RSA key pair along with its kid and expiry time (unix seconds)."""

    kid: int
    private_key: rsa.RSAPrivateKey
    expires_at: int

    def is_expired(self, now=None):
        """Return True if this key's expiry time has passed."""
        if now is None:
            now = time.time()
        return self.expires_at <= now

    def private_pem(self):
        """Private key as PEM bytes, which is what PyJWT wants for signing."""
        return serialize_key(self.private_key)

    def to_jwk(self):
        """Public half of the key as a JWK dictionary."""
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(self.kid),  # JWK kids are strings
            "n": _b64url_int(numbers.n),
            "e": _b64url_int(numbers.e),
        }


def _b64url_int(value):
    """Base64url encode an integer with no padding, as JWK requires."""
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def serialize_key(private_key):
    """Turn a key object into PKCS1 PEM bytes so SQLite can store it."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS1
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_key(pem):
    """Turn PEM bytes read from the database back into a key object."""
    return serialization.load_pem_private_key(pem, password=None)


def load_aes_key():
    """Read NOT_MY_KEY from the environment and turn it into a 256 bit AES key.

    The variable can be any string, so it's run through SHA-256 to get
    exactly 32 bytes. The secret only ever lives in the environment, never in
    the code or the database.
    """
    secret = os.environ.get(AES_KEY_ENV)
    if not secret:
        raise RuntimeError(f"Set the {AES_KEY_ENV} environment variable first")
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt_key(pem, aes_key):
    """Encrypt PEM bytes with AES-256-GCM.

    A fresh random nonce (the IV) is made for every key and stored in front
    of the ciphertext, so the result is nonce + ciphertext + GCM tag.
    """
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(aes_key).encrypt(nonce, pem, None)


def decrypt_key(blob, aes_key):
    """Undo encrypt_key. Raises InvalidTag if the key or data is wrong."""
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def generate_private_key():
    """Make a new 2048 bit RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class KeyStore:
    """Stores RSA keys in a SQLite file so they survive a server restart.

    Every query uses ? placeholders, so values are never pasted into the
    SQL text. That's what keeps these queries safe from SQL injection.
    """

    def __init__(self, db_path=DB_FILE, aes_key=None):
        self.db_path = db_path
        self.aes_key = aes_key or load_aes_key()
        self._create_table()
        # Make sure there's one usable key and one expired key to test with.
        now = int(time.time())
        if self.get_key(expired=False) is None:
            self.add_key(generate_private_key(), now + VALID_KEY_LIFETIME)
        if self.get_key(expired=True) is None:
            self.add_key(generate_private_key(), now - EXPIRED_KEY_AGE)

    def _connect(self):
        """Open a new connection. One per call keeps this safe across threads."""
        return sqlite3.connect(self.db_path)

    def _create_table(self):
        """Create the keys table using the schema the project requires."""
        with closing(self._connect()) as conn, conn:
            conn.execute(CREATE_TABLE_SQL)

    def add_key(self, private_key, expires_at):
        """Save a key to the database and return the kid SQLite assigned.

        The key is serialized to PKCS1 PEM, then AES encrypted, so the
        database never holds a readable private key.
        """
        blob = encrypt_key(serialize_key(private_key), self.aes_key)
        with closing(self._connect()) as conn, conn:
            cur = conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (blob, int(expires_at)),
            )
            return cur.lastrowid

    def get_key(self, expired=False):
        """Read one expired or one unexpired key, or None if there isn't one."""
        if expired:
            sql = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1"
        else:
            sql = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1"
        with closing(self._connect()) as conn:
            row = conn.execute(sql, (int(time.time()),)).fetchone()
        return self._row_to_record(row) if row else None

    def unexpired_keys(self):
        """All keys that are still good, these are the ones in the JWKS."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
                (int(time.time()),),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def jwks(self):
        """Build the JWKS document (only unexpired keys)."""
        return {"keys": [k.to_jwk() for k in self.unexpired_keys()]}

    def _row_to_record(self, row):
        """Decrypt a (kid, key, exp) database row and turn it into a KeyRecord."""
        kid, blob, exp = row
        pem = decrypt_key(blob, self.aes_key)
        return KeyRecord(kid=kid, private_key=deserialize_key(pem), expires_at=exp)
