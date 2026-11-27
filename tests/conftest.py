import pytest
from argon2 import PasswordHasher

from app import create_app
from keys import KeyStore
from users import UserStore


@pytest.fixture(autouse=True)
def aes_secret(monkeypatch):
    """Every test gets a throwaway NOT_MY_KEY so no real secret is needed."""
    monkeypatch.setenv("NOT_MY_KEY", "test-only-secret")


@pytest.fixture
def store(tmp_path):
    return KeyStore(tmp_path / "test.db")


@pytest.fixture
def users(store):
    # Cheap Argon2 settings keep the tests fast; the app uses stronger ones.
    fast = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    return UserStore(store.db_path, hasher=fast)


@pytest.fixture
def client(store, users):
    return create_app(store, users).test_client()
