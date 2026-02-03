import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest import mock

import pytest

import oci_upst_session_manager as mgr


def _write_jwt_with_exp(path: Path, exp_ts: int):
    # Helper intent: write a minimal JWT-like string to disk with a specific
    # exp timestamp so tests can simulate valid/expired UPST tokens.
    import base64
    import json

    header = base64.urlsafe_b64encode(b"{}" ).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp_ts}).encode()).decode().rstrip("=")
    token = f"{header}.{payload}.sig"
    path.write_text(token, encoding="utf-8")


# Test intent: when a valid (non-expiring) UPST is present on disk, ensure_session
# should short-circuit and avoid making any HTTP calls for refresh or auth.
def test_ensure_session_noop_when_upst_valid(tmp_path):
    # Prepare a valid UPST file with future exp
    base_dir, token_path, key_path, rt_path, pid_path = mgr.resolve_oci_paths(
        "dummy-config", "prof"
    )
    # Redirect SESSION_ROOT via monkeypatch of resolve_oci_paths
    def fake_resolve_oci_paths(config_file, profile_name):
        base = tmp_path / profile_name
        base.mkdir(parents=True, exist_ok=True)
        return (
            str(base),
            str(base / "token"),
            str(base / "private_key.pem"),
            str(base / "refresh_token"),
            str(base / "woci_refresh.pid"),
        )

    with mock.patch.object(mgr, "resolve_oci_paths", side_effect=fake_resolve_oci_paths):
        # After patch, re-compute paths under tmp_path
        _, token_path, _, rt_path, _ = mgr.resolve_oci_paths("dummy", "prof")
        token_path = Path(token_path)
        rt_path = Path(rt_path)
        future_exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        _write_jwt_with_exp(token_path, future_exp)

        # ensure_session should return without calling OAuth or refresh
        with mock.patch("requests.post") as m_post, mock.patch.object(mgr, "oauth_authorization_code_flow") as m_oauth:
            mgr.ensure_session(mock.Mock(config_file="dummy", profile_name="prof", token_url=None), None, mgr.REFRESH_TOKEN_KDF_ITERATIONS)
            m_post.assert_not_called()
            m_oauth.assert_not_called()


# Test intent: if the UPST is expired but a refresh token exists, ensure_session
# should perform a refresh_token grant + token exchange and update both UPST and
# refresh token files.
def test_ensure_session_uses_refresh_token_when_upst_expired(tmp_path):
    def fake_resolve_oci_paths(config_file, profile_name):
        base = tmp_path / profile_name
        base.mkdir(parents=True, exist_ok=True)
        return (
            str(base),
            str(base / "token"),
            str(base / "private_key.pem"),
            str(base / "refresh_token"),
            str(base / "woci_refresh.pid"),
        )

    with mock.patch.object(mgr, "resolve_oci_paths", side_effect=fake_resolve_oci_paths):
        _, token_path, _, rt_path, _ = mgr.resolve_oci_paths("dummy", "prof")
        token_path = Path(token_path)
        rt_path = Path(rt_path)

        # Expired UPST
        past_exp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        _write_jwt_with_exp(token_path, past_exp)
        rt_path.write_text("rt-value", encoding="utf-8")

        # Mock refresh token call and token exchange
        def fake_post(url, data=None, auth=None):
            class R:
                def raise_for_status(self):
                    pass

                def json(self):
                    return {"access_token": "new-at", "refresh_token": "new-rt"}

            return R()

        def fake_exchange(url, client_id, client_secret, public_key_b64, access_token):
            assert access_token == "new-at"
            return {"token": "new-upst"}

        args = mock.Mock(
            config_file="dummy",
            profile_name="prof",
            token_url="https://example.com/token",
            auth_client_id="ac",
            auth_client_secret=None,
            client_id="cid",
            client_secret="csec",
            region=None,
        )

        with mock.patch("requests.post", side_effect=fake_post) as m_post, \
             mock.patch.object(mgr, "token_exchange_jwt_to_upst", side_effect=fake_exchange):
            mgr.ensure_session(args, None, mgr.REFRESH_TOKEN_KDF_ITERATIONS)

        # UPST and refresh token files should be updated
        assert token_path.read_text(encoding="utf-8").strip() == "new-upst"
        assert rt_path.read_text(encoding="utf-8").strip() == "new-rt"


# Test intent: if refresh using the stored refresh token fails, ensure_session
# should fall back to the interactive auth code flow, then perform token
# exchange and update the stored UPST and refresh token accordingly.
def test_ensure_session_falls_back_to_auth_code_flow_when_refresh_fails(tmp_path):
    def fake_resolve_oci_paths(config_file, profile_name):
        base = tmp_path / profile_name
        base.mkdir(parents=True, exist_ok=True)
        return (
            str(base),
            str(base / "token"),
            str(base / "private_key.pem"),
            str(base / "refresh_token"),
            str(base / "woci_refresh.pid"),
        )

    with mock.patch.object(mgr, "resolve_oci_paths", side_effect=fake_resolve_oci_paths):
        _, token_path, _, rt_path, _ = mgr.resolve_oci_paths("dummy", "prof")
        token_path = Path(token_path)
        rt_path = Path(rt_path)

        past_exp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        _write_jwt_with_exp(token_path, past_exp)
        rt_path.write_text("rt-value", encoding="utf-8")

        # Make refresh call fail
        def failing_post(url, data=None, auth=None):
            class R:
                def raise_for_status(self):
                    from requests import HTTPError
                    raise HTTPError("boom")

                def json(self):
                    return {}

            return R()

        # OAuth flow returns new tokens
        def fake_oauth(args):
            return {"access_token": "ac-from-auth", "refresh_token": "rt-from-auth"}

        def fake_exchange(url, client_id, client_secret, public_key_b64, access_token):
            assert access_token == "ac-from-auth"
            return {"token": "upst-from-auth"}

        args = mock.Mock(
            config_file="dummy",
            profile_name="prof",
            token_url="https://example.com/token",
            auth_client_id="ac",
            auth_client_secret=None,
            client_id="cid",
            client_secret="csec",
            region=None,
        )

        with mock.patch("requests.post", side_effect=failing_post), \
             mock.patch.object(mgr, "oauth_authorization_code_flow", side_effect=fake_oauth), \
             mock.patch.object(mgr, "token_exchange_jwt_to_upst", side_effect=fake_exchange):
            mgr.ensure_session(args, None, mgr.REFRESH_TOKEN_KDF_ITERATIONS)

        assert token_path.read_text(encoding="utf-8").strip() == "upst-from-auth"
        assert rt_path.read_text(encoding="utf-8").strip() == "rt-from-auth"
