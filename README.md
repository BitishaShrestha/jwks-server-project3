# JWKS Server (Project 3: encryption, users, logging, rate limiting)

A small Flask server that publishes RSA public keys as a JWKS and issues signed
JWTs. Project 3 builds on Project 2 (SQLite key storage) and adds:

- **AES encryption** of the private keys stored in the database
- **User registration** with Argon2 password hashing (`POST /register`)
- **Logging** of every successful `POST /auth` request in `auth_logs`
- A **rate limiter** on `POST /auth` (10 requests per second, then 429)

## Endpoints

| Method & path | What it does |
|---|---|
| `GET /.well-known/jwks.json` | Public halves of all unexpired keys |
| `POST /auth` | Signed RS256 JWT (`?expired` for one signed with an expired key) |
| `POST /register` | Body `{"username": "...", "email": "..."}` -> `201 {"password": "<UUIDv4>"}` |

## How it works

### AES encryption of private keys
- The AES secret comes from the `NOT_MY_KEY` environment variable. It is
  hashed with SHA-256 to get a 256 bit key. The server refuses to start
  without it, and it is never written to the code, the repo or the database.
- Each private key is serialized to PKCS1 PEM and then encrypted with
  **AES-256-GCM**. A new random 12 byte nonce (IV) is created for every key and
  stored in front of the ciphertext in the `key` column, so the `keys` schema
  from Project 2 stays the same. GCM also authenticates the data, so a wrong
  secret or tampered row fails to decrypt instead of producing garbage.

### Users and `/register`
- The `users` table uses the schema from the assignment.
- `/register` generates a password with `uuid.uuid4()`, hashes it with
  **Argon2id** (`time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`,
  `hash_len=32`, `salt_len=16`), stores only the hash, and returns the
  password once. Duplicate usernames or emails get `409`, bad input gets `400`.

### Auth logging
- The `auth_logs` table uses the schema from the assignment (with foreign keys
  enforced).
- Each successful `/auth` request stores the request IP, the timestamp
  (`CURRENT_TIMESTAMP`) and the user's id, and updates that user's
  `last_login`. The username comes from the JSON body or HTTP Basic auth.
  Unknown users are logged with a `NULL` user_id. User authentication is still
  mocked as in Projects 1 and 2: the password is not checked.

### Rate limiter
- `rate_limiter.py` implements a sliding time-window limiter per client IP:
  at most 10 `/auth` requests in any 1 second window. Extra requests get
  `429 Too Many Requests` and are **not** logged.

All SQL uses `?` parameters to prevent SQL injection.

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask app and endpoints |
| `keys.py` | RSA key generation, AES encryption, `keys` table |
| `users.py` | `users` and `auth_logs` tables, Argon2 hashing |
| `rate_limiter.py` | Sliding window rate limiter |
| `tests/` | pytest test suite |

## Setup and run

```
pip install -r requirements.txt
```

Set the secret (pick your own value, never commit it), then start the server.

PowerShell:
```
$env:NOT_MY_KEY = "your-own-secret"
python app.py
```

Git Bash:
```
export NOT_MY_KEY="your-own-secret"
python app.py
```

The server listens on http://localhost:8080. If you have an old
`totally_not_my_privateKeys.db` from Project 2 (unencrypted keys), delete it
first.

## Tests and lint

```
python -m pytest --cov=. --cov-report=term-missing
python -m flake8 .
```

The tests set their own throwaway `NOT_MY_KEY`, so you don't need to set it.

## AI usage

AI (Claude) was used to take help on this project. See [AI_USAGE.md](AI_USAGE.md) for the
acknowledgement and the list of prompts.

## Screenshots

- `screenshots/gradebot.png` - the course Gradebot client running against the server
- `screenshots/coverage.png` - pytest coverage report
