"""Secret Santa API: private assignments, signup lock, and giver-only wishlists."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, EmailStr, Field

load_dotenv()

DB_PATH = Path(os.getenv("DATABASE_PATH", "secret_santa.db"))
JWT_SECRET = os.getenv("JWT_SECRET", "")
ADMIN_INVITE_CODE = os.getenv("ADMIN_INVITE_CODE", "")
TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7

@asynccontextmanager
async def lifespan(_: FastAPI):
    if len(JWT_SECRET) < 32:
        raise RuntimeError("Set JWT_SECRET to a random value of at least 32 characters")
    if len(ADMIN_INVITE_CODE) < 12:
        raise RuntimeError("Set ADMIN_INVITE_CODE to a private value of at least 12 characters")
    init_db()
    yield


app = FastAPI(title="Secret Santa API", version="1.0.0", description="Private Secret Santa draw backend", lifespan=lifespan)


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def transaction():
    conn = db_connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with transaction() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          wishlist TEXT NOT NULL DEFAULT '',
          role TEXT NOT NULL DEFAULT 'participant' CHECK(role IN ('participant','organizer')),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS draw_state (
          id INTEGER PRIMARY KEY CHECK(id = 1),
          is_locked INTEGER NOT NULL DEFAULT 0 CHECK(is_locked IN (0,1)),
          created_at TEXT
        );
        INSERT OR IGNORE INTO draw_state(id, is_locked) VALUES(1,0);
        CREATE TABLE IF NOT EXISTS revoked_tokens (
          token_hash TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assignments (
          giver_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
          giftee_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          CHECK(giver_id <> giftee_id)
        );
        """)


def password_hash(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        computed = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(computed.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(user_id: int) -> str:
    import json
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps({"sub": user_id, "exp": int(time.time()) + TOKEN_TTL_SECONDS}, separators=(",", ":")).encode())
    body = f"{header}.{payload}"
    sig = hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{b64url(sig)}"


def decode_token(token: str) -> int:
    import base64, json
    try:
        header, payload, signature = token.split(".")
        body = f"{header}.{payload}"
        expected = b64url(hmac.new(JWT_SECRET.encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if int(data["exp"]) < int(time.time()):
            raise ValueError("expired")
        return int(data["sub"])
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc


class SignupInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    organizer_code: Optional[str] = None


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class WishlistInput(BaseModel):
    wishlist: str = Field(max_length=2000)


def current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    uid = decode_token(authorization[7:].strip())
    token = authorization[7:].strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = db_connect()
    try:
        row = conn.execute("SELECT id,name,email,role FROM users WHERE id=?", (uid,)).fetchone()
        revoked = conn.execute("SELECT 1 FROM revoked_tokens WHERE token_hash=? AND expires_at>?",
                               (token_hash, int(time.time()))).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    if revoked:
        raise HTTPException(status_code=401, detail="Token has been logged out")
    return dict(row)


def organizer(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "organizer":
        raise HTTPException(status_code=403, detail="Organizer access required")
    return user


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/signup", status_code=201)
def signup(data: SignupInput):
    with transaction() as conn:
        state = conn.execute("SELECT is_locked FROM draw_state WHERE id=1").fetchone()
        if state["is_locked"]:
            raise HTTPException(status_code=409, detail="Signups are locked because the draw has run")
        role = "participant"
        if data.organizer_code:
            if not ADMIN_INVITE_CODE or not hmac.compare_digest(data.organizer_code, ADMIN_INVITE_CODE):
                raise HTTPException(status_code=403, detail="Invalid organizer invite code")
            role = "organizer"
        try:
            cur = conn.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                               (data.name.strip(), data.email.lower(), password_hash(data.password), role))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Email is already registered") from exc
        uid = cur.lastrowid
    return {"id": uid, "name": data.name.strip(), "email": data.email.lower(), "role": role, "access_token": make_token(uid), "token_type": "bearer"}


@app.post("/auth/login")
def login(data: LoginInput):
    conn = db_connect()
    try:
        row = conn.execute("SELECT id,name,email,role,password_hash FROM users WHERE email=? COLLATE NOCASE", (data.email,)).fetchone()
    finally:
        conn.close()
    if row is None or not verify_password(data.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return {"access_token": make_token(row["id"]), "token_type": "bearer", "user": {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]}}


@app.post("/auth/logout")
def logout(authorization: str = Header(...), _: dict = Depends(current_user)):
    token = authorization.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with transaction() as conn:
        conn.execute("DELETE FROM revoked_tokens WHERE expires_at<=?", (int(time.time()),))
        conn.execute("INSERT OR IGNORE INTO revoked_tokens(token_hash,expires_at) VALUES(?,?)",
                     (token_hash, int(time.time()) + TOKEN_TTL_SECONDS))
    return {"message": "Logged out successfully"}


@app.get("/me")
def me(user: dict = Depends(current_user)):
    return user


@app.get("/draw/status")
def draw_status(user: dict = Depends(current_user)):
    conn = db_connect()
    try:
        state = conn.execute("SELECT is_locked,created_at FROM draw_state WHERE id=1").fetchone()
        count = conn.execute("SELECT COUNT(*) AS n FROM users WHERE role='participant'").fetchone()["n"]
    finally:
        conn.close()
    return {"locked": bool(state["is_locked"]), "participant_count": count, "draw_at": state["created_at"]}


@app.get("/participants")
def participants(_: dict = Depends(organizer)):
    conn = db_connect()
    try:
        rows = conn.execute("SELECT id,name,email,created_at FROM users WHERE role='participant' ORDER BY id").fetchall()
        return {"participants": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.post("/draw/run")
def run_draw(_: dict = Depends(organizer)):
    import random
    with transaction() as conn:
        state = conn.execute("SELECT is_locked FROM draw_state WHERE id=1").fetchone()
        if state["is_locked"]:
            raise HTTPException(status_code=409, detail="Draw has already run")
        ids = [r["id"] for r in conn.execute("SELECT id FROM users WHERE role='participant' ORDER BY id").fetchall()]
        if len(ids) < 3:
            raise HTTPException(status_code=400, detail="At least 3 participants are required")
        random.SystemRandom().shuffle(ids)
        # A single cycle prevents self assignments and reciprocal pairs for N >= 3.
        pairs = list(zip(ids, ids[1:] + ids[:1]))
        conn.executemany("INSERT INTO assignments(giver_id,giftee_id) VALUES(?,?)", pairs)
        conn.execute("UPDATE draw_state SET is_locked=1, created_at=CURRENT_TIMESTAMP WHERE id=1")
    return {"message": "Draw completed and signups locked", "participant_count": len(ids)}


@app.get("/my-giftee")
def my_giftee(user: dict = Depends(current_user)):
    conn = db_connect()
    try:
        row = conn.execute("SELECT u.id,u.name FROM assignments a JOIN users u ON u.id=a.giftee_id WHERE a.giver_id=?", (user["id"],)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="No assignment yet")
    return {"giftee": dict(row)}


@app.put("/my-wishlist")
def update_wishlist(data: WishlistInput, user: dict = Depends(current_user)):
    if user["role"] != "participant":
        raise HTTPException(status_code=403, detail="Only participants have wishlists")
    conn = db_connect()
    try:
        conn.execute("UPDATE users SET wishlist=? WHERE id=?", (data.wishlist.strip(), user["id"]))
        conn.commit()
    finally:
        conn.close()
    return {"message": "Wishlist updated"}


@app.get("/my-giftee/wishlist")
def giftee_wishlist(user: dict = Depends(current_user)):
    conn = db_connect()
    try:
        row = conn.execute("""SELECT u.name,u.wishlist FROM assignments a
                              JOIN users u ON u.id=a.giftee_id WHERE a.giver_id=?""", (user["id"],)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="No assignment yet")
    return {"giftee_name": row["name"], "wishlist": row["wishlist"]}

