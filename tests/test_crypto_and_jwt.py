import base64
import json
from datetime import datetime, timezone, timedelta

import pytest

from oci_upst_session_manager import (
    decrypt_refresh_token,
    decode_jwt_exp,
    encrypt_refresh_token,
)


# Test intent: verify that encrypt_refresh_token and decrypt_refresh_token
# are inverse operations given the same passphrase (round-trip correctness).
def test_encrypt_decrypt_refresh_token_roundtrip():
    rt = "my-refresh-token"
    pw = "s3cret-passphrase"

    enc = encrypt_refresh_token(rt, pw)
    dec = decrypt_refresh_token(enc, pw)

    assert dec == rt


# Test intent: ensure the encrypted refresh token JSON payload has the
# expected shape and that core fields are valid base64 data.
def test_encrypt_refresh_token_produces_json_payload():
    rt = "another-token"
    pw = "password"

    enc = encrypt_refresh_token(rt, pw)
    obj = json.loads(enc)

    assert obj["enc"] == "AESGCM"
    assert obj["kdf"] == "PBKDF2-HMAC-SHA256"
    assert isinstance(obj["iter"], int)
    # salt, nonce, ct should be base64 strings that decode without error
    base64.b64decode(obj["salt"])
    base64.b64decode(obj["nonce"])
    base64.b64decode(obj["ct"])


# Test intent: confirm that using the wrong passphrase to decrypt a token
# results in an error rather than silently returning incorrect data.
def test_decrypt_refresh_token_with_wrong_passphrase_raises():
    rt = "token-value"
    pw = "right-pass"
    wrong_pw = "wrong-pass"

    enc = encrypt_refresh_token(rt, pw)

    with pytest.raises(Exception):
        decrypt_refresh_token(enc, wrong_pw)


def _make_jwt_with_exp(exp_ts: int) -> str:
    header = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp_ts}).encode()).decode().rstrip("=")
    return f"{header}.{payload}.sig"


# Test intent: decode_jwt_exp should return a datetime corresponding to
# the exp claim when the JWT payload is well-formed and contains exp.
def test_decode_jwt_exp_valid():
    exp_ts = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    token = _make_jwt_with_exp(exp_ts)

    dt = decode_jwt_exp(token)
    assert dt is not None
    assert int(dt.timestamp()) == exp_ts


# Test intent: decode_jwt_exp should return None when the JWT is missing
# an exp claim or is not a structurally valid JWT at all.
def test_decode_jwt_exp_missing_or_malformed():
    # No exp claim
    header = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({}).encode()).decode().rstrip("=")
    token_no_exp = f"{header}.{payload}.sig"
    assert decode_jwt_exp(token_no_exp) is None

    # Malformed token
    assert decode_jwt_exp("not-a-jwt") is None
