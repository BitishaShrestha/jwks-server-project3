import base64
import sqlite3
import time
from contextlib import closing

import pytest
from cryptography.exceptions import InvalidTag

from keys import (
    KeyRecord,
    KeyStore,
    decrypt_key,
    deserialize_key,
    encrypt_key,
    generate_private_key,
    load_aes_key,
    serialize_key,
)


def rows(store):
    with closing(sqlite3.connect(store.db_path)) as conn:
        return conn.execute("SELECT kid, key, exp FROM keys").fetchall()


def test_table_is_created_with_two_keys(store):
    assert len(rows(store)) == 2


def test_store_has_one_valid_and_one_expired_key(store):
    assert not store.get_key(expired=False).is_expired()
    assert store.get_key(expired=True).is_expired()


def test_keys_are_encrypted_in_the_database(store):
    for _, blob, _ in rows(store):
        assert b"PRIVATE KEY" not in blob
        # Decrypting gives back PKCS1 PEM.
        pem = decrypt_key(blob, store.aes_key)
        assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_encrypt_uses_a_fresh_nonce_each_time():
    aes_key = load_aes_key()
    pem = serialize_key(generate_private_key())
    first, second = encrypt_key(pem, aes_key), encrypt_key(pem, aes_key)
    assert first != second
    assert decrypt_key(first, aes_key) == decrypt_key(second, aes_key) == pem


def test_wrong_secret_cannot_decrypt(store, monkeypatch):
    monkeypatch.setenv("NOT_MY_KEY", "some-other-secret")
    _, blob, _ = rows(store)[0]
    with pytest.raises(InvalidTag):
        decrypt_key(blob, load_aes_key())


def test_aes_key_is_256_bits():
    assert len(load_aes_key()) == 32


def test_missing_secret_is_an_error(monkeypatch, tmp_path):
    monkeypatch.delenv("NOT_MY_KEY")
    with pytest.raises(RuntimeError, match="NOT_MY_KEY"):
        KeyStore(tmp_path / "x.db")


def test_keys_survive_a_restart(store):
    # Opening the same file again reuses the keys instead of making new ones.
    before = rows(store)
    again = KeyStore(store.db_path)
    assert rows(again) == before


def test_kids_are_unique(store):
    kids = [kid for kid, _, _ in rows(store)]
    assert len(kids) == len(set(kids))


def test_add_key_returns_new_kid(store):
    kid = store.add_key(generate_private_key(), time.time() + 60)
    assert kid == 3
    assert len(store.unexpired_keys()) == 2


def test_jwks_only_contains_unexpired_keys(store):
    kids = [k["kid"] for k in store.jwks()["keys"]]
    assert kids == [str(store.get_key(expired=False).kid)]


def test_serialize_round_trip():
    key = generate_private_key()
    loaded = deserialize_key(serialize_key(key))
    assert loaded.private_numbers() == key.private_numbers()


def test_is_expired_with_explicit_now():
    key = KeyRecord(kid=1, private_key=generate_private_key(), expires_at=1000)
    assert key.is_expired(now=2000)
    assert not key.is_expired(now=500)


def test_jwk_fields(store):
    jwk = store.get_key(expired=False).to_jwk()
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert isinstance(jwk["kid"], str)
    # e for 65537 is "AQAB" in base64url
    assert jwk["e"] == "AQAB"
    # n must be valid base64url with no padding
    assert "=" not in jwk["n"]
    base64.urlsafe_b64decode(jwk["n"] + "==")


def test_private_pem_format(store):
    pem = store.get_key(expired=False).private_pem()
    assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
