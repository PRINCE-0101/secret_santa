# Secret Santa API

A beginner-friendly backend for a private Secret Santa draw. Participants can register and log in, an organizer runs the draw once, and each participant can retrieve only their own giftee. Signups lock automatically after the draw.

## Features

- Signup and login with PBKDF2 password hashing and signed bearer tokens; logout revokes the current token.
- Organizer-only participant list, draw, and reset operations.
- Draw is one single cycle: nobody gets themselves, each person gives to and receives from exactly one participant, and reciprocal pairs are avoided when there are at least three participants.
- Wishlist can be edited by its owner and read only by that owner's assigned giver.
- Atomic draw transaction; repeat draw and signup after lock are rejected.
- SQLite database, Dockerfile, interactive OpenAPI docs.

## Run locally

Requires Python 3.10 or newer.

```bash
cd secret-santa
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env`, then replace both values with private random secrets. The app loads `.env` automatically. `JWT_SECRET` must be at least 32 characters; `ADMIN_INVITE_CODE` must be at least 12 characters.

```bash
uvicorn main:app --reload
```

API documentation: <http://127.0.0.1:8000/docs>
Health check: <http://127.0.0.1:8000/health>

## Quick start

1. Register the organizer first with `POST /auth/signup`, including the configured `organizer_code`.
2. Register participants using the same endpoint without `organizer_code`.
3. Sign in as organizer with `POST /auth/login` and copy its `access_token`.
4. In Swagger's **Authorize** dialog, enter `Bearer YOUR_TOKEN`.
5. Organizer checks `GET /participants`, then calls `POST /draw/run`.
6. Each participant logs in separately and calls `GET /my-giftee`.
7. Participants can set their own list with `PUT /my-wishlist`; their assigned giver can read it through `GET /my-giftee/wishlist`.

For signup, organizer request body example:

```json
{"name":"Event Organizer","email":"organizer@example.com","password":"change-this-password","organizer_code":"private-organizer-code"}
```

Participant request body:

```json
{"name":"Aanya","email":"aanya@example.com","password":"change-this-password"}
```

For protected routes add this HTTP header:

```text
Authorization: Bearer <access_token>
```

## Endpoints

| Method | Route | Access | Purpose |
|---|---|---|---|
| GET | `/health` | public | Liveness check |
| POST | `/auth/signup` | public, until draw | Create participant; organizer code optionally creates organizer |
| POST | `/auth/login` | public | Get bearer token |
| POST | `/auth/logout` | signed in | Revoke current bearer token |
| GET | `/me` | signed in | Current account |
| GET | `/draw/status` | signed in | Signup lock and participant count |
| GET | `/participants` | organizer | Participant roster |
| POST | `/draw/run` | organizer | Run draw and lock signup |
| GET | `/my-giftee` | signed in | Caller’s assigned recipient only |
| PUT | `/my-wishlist` | participant | Update caller’s wishlist |
| GET | `/my-giftee/wishlist` | signed in | Wishlist of caller’s giftee only |
| POST | `/draw/reset` | organizer | Development/event reset; clears assignments and reopens signup |

Logging out revokes that token on the server; the client should also clear its local copy. The API intentionally has no participant-facing endpoint for viewing the full mapping. `/draw/reset` is for development or a deliberate organizer reset and deletes the existing assignments.

## Run with Docker

```bash
docker build -t secret-santa-api .
docker run --rm -p 8000:8000 \
  -e JWT_SECRET='replace-with-a-long-random-secret' \
  -e ADMIN_INVITE_CODE='private-organizer-code' \
  -v secret-santa-data:/data \
  secret-santa-api
```

## Tests

```bash
pip install -r requirements.txt
pytest -q
```

## Design notes

Assignments are stored as giver → giftee rows with unique constraints on both sides. The draw shuffles participants and maps each person to the next person in a circular list. That creates a valid one-to-one cycle, guarantees no self-match, and prevents two-person swaps when the participant count is at least three. Two participants cannot meet the no-mutual-pairs rule, so the API requires at least three. Organizer accounts are created through a shared invite code; keep it private and rotate it after the organizer has registered.

Before a real deployment, use HTTPS, a strong `JWT_SECRET`, a private database volume, backups, and a secret manager. Anyone who can access the database file can inspect stored assignments, so restrict server and database access to the organizer/runtime.
