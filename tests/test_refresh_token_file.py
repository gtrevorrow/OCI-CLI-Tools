from pathlib import Path

import pytest

from oci_upst_session_manager import save_refresh_token, load_refresh_token


# Test intent: verify that saving a refresh token without a passphrase stores
# it as plaintext and that load_refresh_token returns the original value.
def test_save_and_load_refresh_token_plain(tmp_path: Path):
    path = tmp_path / "rt_plain"

    save_refresh_token(str(path), "plain-rt", passphrase=None)

    assert path.read_text(encoding="utf-8").strip() == "plain-rt"
    loaded = load_refresh_token(str(path), passphrase=None)
    assert loaded == "plain-rt"


# Test intent: verify that when a passphrase is provided, the on-disk refresh
# token is encrypted (not in plaintext) and load_refresh_token can decrypt it.
def test_save_and_load_refresh_token_encrypted(tmp_path: Path):
    path = tmp_path / "rt_enc"

    save_refresh_token(str(path), "enc-rt", passphrase="pw")

    raw = path.read_text(encoding="utf-8")
    assert "enc-rt" not in raw  # should not store plaintext

    loaded = load_refresh_token(str(path), passphrase="pw")
    assert loaded == "enc-rt"


# Test intent: confirm that attempting to load an encrypted refresh token
# without providing a passphrase raises a RuntimeError and does not silently
# return garbage or plaintext.
def test_load_encrypted_refresh_token_without_passphrase_errors(tmp_path: Path):
    path = tmp_path / "rt_enc"

    # First store encrypted
    save_refresh_token(str(path), "enc-rt", passphrase="pw")

    with pytest.raises(RuntimeError):
        load_refresh_token(str(path), passphrase=None)
