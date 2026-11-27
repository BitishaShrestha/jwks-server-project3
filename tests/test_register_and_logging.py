import sqlite3
import uuid
from contextlib import closing

import jwt

from app import create_app
from rate_limiter import RateLimiter


def logs(store):
    with closing(sqlite3.connect(store.db_path)) as conn:
        return conn.execute("SELECT request_ip, user_id FROM auth_logs").fetchall()


def test_register_returns_uuid4_password(client):
    resp = client.post("/register", json={"username": "u1", "email": "u1@x.com"})
    assert resp.status_code == 201
    password = resp.get_json()["password"]
    assert uuid.UUID(password).version == 4


def test_register_without_email(client):
    assert client.post("/register", json={"username": "u2"}).status_code == 201


def test_register_duplicate_is_409(client):
    client.post("/register", json={"username": "u3", "email": "u3@x.com"})
    resp = client.post("/register", json={"username": "u3", "email": "new@x.com"})
    assert resp.status_code == 409


def test_register_bad_input_is_400(client):
    assert client.post("/register", data="not json").status_code == 400
    assert client.post("/register", json=["list"]).status_code == 400
    assert client.post("/register", json={"email": "a@b.c"}).status_code == 400
    assert client.post("/register", json={"username": "  "}).status_code == 400
    resp = client.post("/register", json={"username": "u4", "email": 5})
    assert resp.status_code == 400


def test_auth_is_logged_with_user_id(client, store):
    password = client.post(
        "/register", json={"username": "u5", "email": "u5@x.com"}
    ).get_json()["password"]
    resp = client.post("/auth", json={"username": "u5", "password": password})
    assert resp.status_code == 200
    claims = jwt.decode(
        resp.get_data(as_text=True), options={"verify_signature": False}
    )
    assert claims["sub"] == "u5"
    assert logs(store) == [("127.0.0.1", 1)]


def test_auth_with_basic_auth_is_logged(client, store):
    client.post("/register", json={"username": "u6"})
    client.post("/auth", auth=("u6", "whatever"))
    assert logs(store) == [("127.0.0.1", 1)]


def test_auth_unknown_user_logged_with_null(client, store):
    client.post("/auth")
    client.post("/auth", json={"username": "ghost", "password": "x"})
    assert logs(store) == [("127.0.0.1", None), ("127.0.0.1", None)]


def test_auth_rate_limited_and_429s_not_logged(store, users):
    client = create_app(store, users, RateLimiter(limit=10, window=60)).test_client()
    codes = [client.post("/auth").status_code for _ in range(15)]
    assert codes == [200] * 10 + [429] * 5
    assert len(logs(store)) == 10


def test_jwks_is_not_rate_limited(store, users):
    client = create_app(store, users, RateLimiter(limit=1, window=60)).test_client()
    assert all(
        client.get("/.well-known/jwks.json").status_code == 200 for _ in range(5)
    )
