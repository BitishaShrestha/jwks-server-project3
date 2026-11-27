import sqlite3
from contextlib import closing

import pytest
from argon2 import PasswordHasher

from users import UserStore, UsernameTakenError, make_password_hasher


def query(store, sql, args=()):
    with closing(sqlite3.connect(store.db_path)) as conn:
        return conn.execute(sql, args).fetchall()


def test_tables_are_created(users):
    names = {r[0] for r in query(users, "SELECT name FROM sqlite_master")}
    assert {"users", "auth_logs"} <= names


def test_users_table_columns(users):
    cols = [r[1] for r in query(users, "PRAGMA table_info(users)")]
    assert cols == [
        "id", "username", "password_hash", "email", "date_registered", "last_login",
    ]


def test_auth_logs_table_columns(users):
    cols = [r[1] for r in query(users, "PRAGMA table_info(auth_logs)")]
    assert cols == ["id", "request_ip", "request_timestamp", "user_id"]


def test_register_stores_argon2_hash_not_password(users):
    password = users.register("alice", "alice@example.com")
    [(stored_hash,)] = query(
        users, "SELECT password_hash FROM users WHERE username = ?", ("alice",)
    )
    assert password not in stored_hash
    assert stored_hash.startswith("$argon2id$")
    assert users.hasher.verify(stored_hash, password)


def test_duplicate_username_and_email_rejected(users):
    users.register("bob", "bob@example.com")
    with pytest.raises(UsernameTakenError):
        users.register("bob", "other@example.com")
    with pytest.raises(UsernameTakenError):
        users.register("bobby", "bob@example.com")


def test_find_user_id(users):
    users.register("carol")
    assert users.find_user_id("carol") == 1
    assert users.find_user_id("nobody") is None


def test_log_auth_records_ip_and_updates_last_login(users):
    users.register("dave")
    users.log_auth("10.0.0.1", 1)
    assert query(users, "SELECT request_ip, user_id FROM auth_logs") == [
        ("10.0.0.1", 1)
    ]
    [(last_login,)] = query(users, "SELECT last_login FROM users WHERE id = 1")
    assert last_login is not None


def test_log_auth_unknown_user_must_be_null(users):
    users.log_auth("10.0.0.1", None)
    with pytest.raises(sqlite3.IntegrityError):
        users.log_auth("10.0.0.1", 999)  # foreign key is enforced


def test_default_hasher_settings():
    hasher = make_password_hasher()
    assert hasher.time_cost == 3
    assert hasher.memory_cost == 65536
    assert hasher.parallelism == 4
    assert hasher.hash_len == 32
    assert hasher.salt_len == 16


def test_default_hasher_used_when_none_given(tmp_path):
    assert isinstance(UserStore(tmp_path / "u.db").hasher, PasswordHasher)
