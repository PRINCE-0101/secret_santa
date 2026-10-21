import os

os.environ.setdefault("JWT_SECRET", "test-secret-long-enough-for-local-tests")

from main import decode_token, make_token, password_hash, verify_password


def test_password_is_salted_and_verifiable():
    first = password_hash("correct horse battery staple")
    second = password_hash("correct horse battery staple")
    assert first != second
    assert verify_password("correct horse battery staple", first)
    assert not verify_password("wrong password", first)


def test_token_round_trip():
    token = make_token(42)
    assert decode_token(token) == 42


def test_tampered_token_fails():
    token = make_token(42)
    parts = token.split(".")
    parts[1] = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    try:
        decode_token(".".join(parts))
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 401
    else:
        raise AssertionError("Tampered token should be rejected")
