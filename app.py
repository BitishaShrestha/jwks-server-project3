"""Flask app for the JWKS server.

Endpoints:
    GET  /.well-known/jwks.json  -> public keys that haven't expired
    POST /auth                   -> a signed JWT (add ?expired for an expired one)
    POST /register               -> create a user and return a generated password

Keys are stored AES encrypted in SQLite (see keys.py). Users and auth logs
live in the same database (see users.py).
"""

import sqlite3
import time

import jwt
from flask import Flask, jsonify, request

from keys import KeyStore, generate_private_key, VALID_KEY_LIFETIME
from rate_limiter import RateLimiter
from users import UserStore, UsernameTakenError

TOKEN_LIFETIME = 5 * 60  # normal tokens last 5 minutes


def create_app(key_store=None, user_store=None, rate_limiter=None):
    """Build the Flask app. Stores and the limiter can be passed in for testing."""
    app = Flask(__name__)
    store = key_store or KeyStore()
    users = user_store or UserStore(store.db_path)
    limiter = rate_limiter or RateLimiter(limit=10, window=1.0)

    @app.errorhandler(sqlite3.Error)
    def database_error(_err):
        """Return a generic 500 so database details never leak to the client."""
        return jsonify({"error": "internal server error"}), 500

    @app.route("/.well-known/jwks.json", methods=["GET"])
    def jwks():
        """Return the public JWKS built from every unexpired key in the DB."""
        return jsonify(store.jwks())

    @app.route("/register", methods=["POST"])
    def register():
        """Register a user from {"username": ..., "email": ...}.

        Responds 201 with {"password": "<UUIDv4>"}. The password is hashed
        with Argon2 before it's stored.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "expected a JSON object"}), 400
        username = body.get("username")
        email = body.get("email")
        if not isinstance(username, str) or not username.strip():
            return jsonify({"error": "username is required"}), 400
        if email is not None and not isinstance(email, str):
            return jsonify({"error": "email must be a string"}), 400

        try:
            password = users.register(username, email)
        except UsernameTakenError:
            return jsonify({"error": "username or email already registered"}), 409
        return jsonify({"password": password}), 201

    @app.route("/auth", methods=["POST"])
    def auth():
        """Return a JWT signed with a key read from the database.

        A valid key is used by default; ?expired switches to an expired key
        and an exp claim in the past. Limited to 10 requests per second per
        IP; extra requests get 429 and are not logged.
        """
        if not limiter.allow(request.remote_addr):
            return jsonify({"error": "too many requests"}), 429

        # User auth is mocked: Basic auth or a JSON body are both accepted
        # without checking. The mere presence of ?expired counts.
        expired = "expired" in request.args
        key = store.get_key(expired=expired)
        if key is None:
            # The valid key ran out while the server was up, so make a new one.
            store.add_key(generate_private_key(), int(time.time()) + VALID_KEY_LIFETIME)
            key = store.get_key(expired=False)

        if expired:
            exp = key.expires_at  # already in the past
        else:
            exp = int(time.time()) + TOKEN_LIFETIME

        username = _request_username()
        payload = {
            "sub": username or "fakeuser",
            "iat": int(time.time()),
            "exp": exp,
        }
        # kid goes in the header so clients know which key to verify with.
        token = jwt.encode(
            payload,
            key.private_pem(),
            algorithm="RS256",
            headers={"kid": str(key.kid)},
        )
        # Only successful requests are logged. user_id is NULL for unknown users.
        user_id = users.find_user_id(username) if username else None
        users.log_auth(request.remote_addr, user_id)
        # Send the raw JWT as the body.
        return token, 200, {"Content-Type": "text/plain; charset=utf-8"}

    return app


def _request_username():
    """Username from the JSON body or HTTP Basic auth, or None if neither has one."""
    body = request.get_json(silent=True)
    if isinstance(body, dict) and isinstance(body.get("username"), str):
        return body["username"]
    if request.authorization and request.authorization.username:
        return request.authorization.username
    return None


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
