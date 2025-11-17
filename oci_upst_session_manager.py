#!/usr/bin/env python3
# MIT License
# Copyright (c) 2025 Gordon Trevorrow
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Author: Gordon Trevorrow

import argparse
import base64
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlparse, parse_qs
from typing import Optional
import configparser

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG = logging.getLogger("oci-upst-manager")
OCI_DIRNAME= ".oci"
OCI_CONFIG_FILENAME = "config"
SESSION_DIRNAME = "sessions"
SESSION_TOKEN_FILENAME = "token"
SESSION_KEY_FILENAME = "private_key.pem"
SESSION_REFRESH_TOKEN_FILENAME = "refresh_token"
SESSION_ROOT = os.path.join(os.path.expanduser(os.path.join(f"~/{OCI_DIRNAME}",SESSION_DIRNAME)))
# Always use 2048-bit RSA keys
RSA_KEY_BITS = 2048
# KDF iterations for refresh token encryption (constant)
REFRESH_TOKEN_KDF_ITERATIONS = 200_000
# Default manager config filename for auto-discovery
MANAGER_DEFAULT_FILENAME = "woci_manager.ini"
# ---------- Utils ----------

def setup_logging(level_str: str) -> None:
    level = getattr(logging, level_str.upper(), logging.INFO)
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    LOG.addHandler(h)
    LOG.setLevel(level)


def b64_basic(client_id: str, client_secret: str) -> str:
    return base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()


def b64_der_spki(pubkey) -> str:
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode()


def ensure_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        os.chmod(os.path.dirname(path), 0o700)
    except Exception:
        pass


def write_secret_file(path: str, content: bytes) -> None:
    ensure_dir(path)
    with open(path, "wb") as f:
        f.write(content)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def parse_interval_to_seconds(value: str) -> int:
    s = value.strip().lower()
    if s.endswith("h"):
        minutes = int(s[:-1]) * 60
    elif s.endswith("m"):
        minutes = int(s[:-1])
    else:
        minutes = int(s)
    if minutes < 0:
        raise ValueError("refresh interval must be >= 0 minutes (0 disables background refresh)")
    if minutes == 0:
        return 0
    if minutes > 60:
        LOG.warning("refresh interval %d > 60; clamping to 60 due to session limits", minutes)
        minutes = 60
    return minutes * 60


# ---------- OAuth PKCE (S256) helpers ----------

import secrets
import hashlib


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


# ---------- Local redirect server ----------

class CodeHandler(BaseHTTPRequestHandler):
    server_version = "CodeHandler/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        allowed_path = getattr(self.server, "callback_path", "/callback")
        if parsed.path != allowed_path:
            self.send_response(404)
            self.end_headers()
            return
        q = parse_qs(parsed.query)
        code = q.get("code", [None])[0]
        state = q.get("state", [None])[0]
        self.server.captured = {"code": code, "state": state}
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>Authentication complete. You can close this window.</body></html>")

    def log_message(self, fmt, *args):
        # silence default HTTP server log
        return


class CodeServer(HTTPServer):
    def __init__(self, host, port, callback_path):
        # type: ignore[arg-type]
        super().__init__((host, port), CodeHandler)
        self.callback_path = callback_path
        self.captured = None


# ---------- Refresh token encryption helpers ----------

def derive_key(passphrase: str, salt: bytes, iterations: int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_refresh_token(rt: str, passphrase: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, rt.encode("utf-8"), None)
    payload = {
        "enc": "AESGCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iter": iterations,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    }
    return json.dumps(payload)


def decrypt_refresh_token(enc_json: str, passphrase: str) -> str:
    obj = json.loads(enc_json)
    if not isinstance(obj, dict) or obj.get("enc") != "AESGCM":
        raise ValueError("Unsupported encrypted refresh token format")
    iterations = int(obj.get("iter", 200_000))
    salt = base64.b64decode(obj["salt"])  # type: ignore[index]
    nonce = base64.b64decode(obj["nonce"])  # type: ignore[index]
    ct = base64.b64decode(obj["ct"])  # type: ignore[index]
    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode("utf-8")


def save_refresh_token(path: str, rt: str, passphrase: Optional[str], iterations: int = 200_000) -> None:
    if passphrase:
        content = encrypt_refresh_token(rt, passphrase, iterations).encode("utf-8")
    else:
        content = rt.encode("utf-8")
    write_secret_file(path, content)


def load_refresh_token(path: str, passphrase: Optional[str]) -> str:
    with open(path, "r", encoding="utf-8") as f:
        data = f.read()
    # Detect encrypted JSON
    try:
        obj = json.loads(data)
        if isinstance(obj, dict) and obj.get("enc") == "AESGCM":
            if not passphrase:
                raise RuntimeError("Refresh token is encrypted; supply a passphrase via --refresh-token-passphrase-prompt or --refresh-token-passphrase-env.")
            return decrypt_refresh_token(data, passphrase)
    except json.JSONDecodeError:
        pass
    return data.strip()


def get_rt_passphrase(args) -> Optional[str]:
    # prompt takes precedence
    if getattr(args, "refresh_token_passphrase_prompt", False):
        import getpass
        pw = getpass.getpass("Enter refresh token passphrase: ")
        if not pw:
            LOG.warning("Empty passphrase entered; refresh token will be stored unencrypted.")
            return None
        return pw
    env_name = getattr(args, "refresh_token_passphrase_env", None)
    if env_name:
        pw = os.environ.get(env_name)
        if pw:
            return pw
        LOG.warning("Env var %s is not set or empty; refresh token will be stored unencrypted.", env_name)
    return None


# ---------- Core flows ----------

def oauth_authorization_code_flow(args) -> dict:
    verifier, challenge = pkce_pair()
    state = base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")

    # spin up local server
    callback_path = "/callback"
    port = args.redirect_port
    server = CodeServer("127.0.0.1", port, callback_path)
    th = threading.Thread(target=server.serve_forever, daemon=True)
    th.start()

    redirect_uri = f"http://127.0.0.1:{port}{callback_path}"

    # Use authz_base_url as the full authorization endpoint URL
    auth_url = args.authz_base_url + "?" + urlencode({
        "response_type": "code",
        "client_id": args.client_id,
        "redirect_uri": redirect_uri,
        "scope": args.scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    LOG.info("Auth URL: %s", auth_url)
    LOG.info("Opening browser for authorization...")
    try:
        import webbrowser
        opened = webbrowser.open(auth_url)
        if not opened:
            LOG.warning("webbrowser.open returned False; attempting macOS 'open' fallback.")
            if sys.platform == 'darwin':
                try:
                    import subprocess
                    subprocess.run(["open", auth_url], check=False)
                except Exception:
                    LOG.warning("macOS 'open' fallback failed; manually open the URL above.")
            else:
                LOG.warning("No platform fallback; manually open the URL above.")
    except Exception:
        LOG.info("Browser open failed; manually open the URL above.")

    # wait for callback
    LOG.info("Waiting for authorization response at %s", redirect_uri)
    while server.captured is None:
        time.sleep(0.2)

    code = server.captured["code"]
    got_state = server.captured["state"]
    server.shutdown()

    if not code or got_state != state:
        raise RuntimeError("Authorization failed or state mismatch")

    # exchange code for tokens
    token_url = args.token_url
    if not token_url:
        raise RuntimeError("token_url is required; provide it via CLI or manager-config")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": args.client_id,
        "code_verifier": verifier,
    }
    auth = None
    if args.client_secret:
        auth = (args.client_id, args.client_secret)
    resp = requests.post(token_url, data=data, auth=auth)
    resp.raise_for_status()
    tok = resp.json()
    if "access_token" not in tok or "refresh_token" not in tok:
        raise RuntimeError("Token endpoint did not return access_token and refresh_token")
    return tok


def token_exchange_jwt_to_upst(token_exchange_url: str, client_id: str, client_secret: str, public_key_b64: str, access_token: str) -> dict:
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if client_secret:
        headers["Authorization"] = f"Basic {b64_basic(client_id, client_secret)}"
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requested_token_type": "urn:oci:token-type:oci-upst",
        "public_key": public_key_b64,
        "subject_token": access_token,
        "subject_token_type": "jwt",
    }
    resp = requests.post(token_exchange_url, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()


def generate_rsa(key_bits: int):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_bits, backend=default_backend())


def resolve_oci_paths(config_file: str, profile_name: str):
    """Return paths for UPST (session) token, private key and refresh token.

    Use the OCI CLI session layout: ~/.oci/sessions/<profile_name>/security_token
    """
    sessions_root = SESSION_ROOT
    base_dir = os.path.join(sessions_root, profile_name)
    token_path = os.path.join(base_dir, SESSION_TOKEN_FILENAME)
    key_path = os.path.join(base_dir, SESSION_KEY_FILENAME)
    rt_path = os.path.join(base_dir, SESSION_REFRESH_TOKEN_FILENAME)
    return base_dir, token_path, key_path, rt_path


def update_oci_config(config_file: str, profile_name: str, region: Optional[str], key_file: str, token_file: str):
    # keep it simple: append/update lines in the INI style file
    # We won't introduce a dependency; we'll do a minimal INI update.
    lines = []
    if os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()

    def set_kv(section: str, key: str, value: Optional[str]):
        nonlocal lines
        out = []
        in_sec = False
        found_sec = False
        set_key = False
        for ln in lines:
            if ln.strip().startswith("[") and ln.strip().endswith("]"):
                if in_sec and not set_key and value is not None:
                    out.append(f"{key}={value}")
                in_sec = (ln.strip() == f"[{section}]")
                out.append(ln)
                if in_sec:
                    found_sec = True
                continue
            if in_sec and value is not None and ln.strip().startswith(f"{key}="):
                out.append(f"{key}={value}")
                set_key = True
            else:
                out.append(ln)
        if not found_sec:
            out.append(f"[{section}]")
            # On first creation, write what we know; region is optional.
            if region:
                out.append(f"region={region}")
            out.append(f"key_file={key_file}")
            out.append(f"security_token_file={token_file}")
            # Also add the current key if provided and not one of the above
            if value is not None and key not in ("region", "key_file", "security_token_file"):
                out.append(f"{key}={value}")
        else:
            if not set_key and value is not None:
                out.append(f"{key}={value}")
        lines = out

    # ensure base keys exist
    set_kv(profile_name, "region", region)
    set_kv(profile_name, "key_file", key_file)
    set_kv(profile_name, "security_token_file", token_file)

    with open(config_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    try:
        os.chmod(config_file, 0o600)
    except Exception:
        pass


def save_initial_materials(args, key, upst: str, refresh_token: str, rt_passphrase: Optional[str], rt_iterations: int):
    base_dir, token_path, key_path, rt_path = resolve_oci_paths(args.config_file, args.profile_name)
    write_secret_file(key_path, key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    write_secret_file(token_path, upst.encode())
    save_refresh_token(rt_path, refresh_token, rt_passphrase, rt_iterations)
    update_oci_config(args.config_file, args.profile_name, args.region, key_path, token_path)
    LOG.info("Wrote key, UPST, and refresh token; updated OCI config for profile '%s'", args.profile_name)


def decode_jwt_exp(token_str: str) -> Optional[datetime]:
    try:
        parts = token_str.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        # base64url decode
        pad = '=' * (-len(payload_b64) % 4) # calc the b64 padding mising from JWT payloads
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)):
            return None
        return datetime.fromtimestamp(int(exp), tz=timezone.utc)
    except Exception:
        return None


def perform_exchange_and_save(args, access_token: str, maybe_refresh_token: Optional[str], rt_passphrase: Optional[str], rt_iterations: int) -> None:
    base_dir, token_path, key_path, rt_path = resolve_oci_paths(args.config_file, args.profile_name)
    key = None  # type: ignore[assignment]
    if not os.path.exists(key_path):
        LOG.info("No key found; generating new RSA key and updating profile.")
        key = generate_rsa(RSA_KEY_BITS)
        write_secret_file(key_path, key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        update_oci_config(args.config_file, args.profile_name, args.region, key_path, token_path)
    else:
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    pub_b64 = b64_der_spki(key.public_key())
    if not args.client_secret:
        raise RuntimeError("client_secret is required for OCI IAM token exchange but was not provided")
    exchange_url = args.token_exchange_url or args.token_url
    exch = token_exchange_jwt_to_upst(exchange_url, args.client_id, args.client_secret or "", pub_b64, access_token)
    upst = exch["token"]
    write_secret_file(token_path, upst.encode())
    if maybe_refresh_token:
        save_refresh_token(rt_path, maybe_refresh_token, rt_passphrase, rt_iterations)


def ensure_session(args, rt_passphrase: Optional[str], rt_iterations: int) -> None:
    base_dir, token_path, key_path, rt_path = resolve_oci_paths(args.config_file, args.profile_name)
    # 1) If UPST exists and not expiring in next 60s, do nothing
    if os.path.exists(token_path):
        try:
            with open(token_path, "r", encoding="utf-8") as f:
                upst = f.read().strip()
            exp = decode_jwt_exp(upst)
            if exp and exp > datetime.now(timezone.utc) + timedelta(seconds=60):
                LOG.info("Existing UPST valid until %s; no refresh needed.", exp.isoformat())
                return
            else:
                LOG.info("Existing UPST missing/near expiry; will attempt refresh or re-auth.")
        except Exception:
            LOG.info("Could not read existing UPST; will attempt refresh or re-auth.")

    # 2) If refresh_token exists, use it to refresh AT and exchange to UPST
    if os.path.exists(rt_path):
        try:
            refresh_token = load_refresh_token(rt_path, rt_passphrase)
            token_url = args.token_url
            if not token_url:
                raise RuntimeError("token_url is required for refresh; provide it via CLI or manager-config")
            data = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": args.client_id,
            }
            auth = None
            if args.client_secret:
                auth = (args.client_id, args.client_secret)
            resp = requests.post(token_url, data=data, auth=auth)
            resp.raise_for_status()
            tok = resp.json()
            access_token = tok["access_token"]
            new_rt = tok.get("refresh_token", refresh_token)
            perform_exchange_and_save(args, access_token, new_rt, rt_passphrase, rt_iterations)
            LOG.info("Session refreshed from refresh_token.")
            return
        except Exception as e:
            LOG.warning("Refresh using refresh_token failed: %s", e)

    # 3) Fall back to interactive Authorization Code flow
    LOG.info("Starting Authorization Code flow to obtain new session.")
    tokens = oauth_authorization_code_flow(args)
    perform_exchange_and_save(args, tokens["access_token"], tokens.get("refresh_token"), rt_passphrase, rt_iterations)
    LOG.info("New session created via Authorization Code flow.")


def refresh_cycle(args, stop_event: threading.Event, rt_passphrase: Optional[str], rt_iterations: int):
    seconds = parse_interval_to_seconds(args.refresh_interval)
    if seconds == 0:
        LOG.info("Background refresh disabled (refresh-interval=0).")
        return
    base_dir, token_path, key_path, rt_path = resolve_oci_paths(args.config_file, args.profile_name)
    token_url = args.token_url
    if not token_url:
        LOG.error("token_url is required for refresh cycle; provide it via CLI or manager-config")
        return
    exchange_url = args.token_exchange_url or token_url
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    pub_b64 = b64_der_spki(key.public_key())
    while not stop_event.is_set():
        next_run = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        mins = seconds // 60
        LOG.info("Next refresh in %d minute(s) (at %s UTC)", mins, next_run.isoformat())
        if stop_event.wait(timeout=seconds):
            break
        try:
            refresh_token = load_refresh_token(rt_path, rt_passphrase)
        except Exception:
            LOG.error("Refresh token missing or cannot be decrypted; cannot refresh. Exiting loop.")
            break
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": args.client_id,
        }
        auth = None
        if args.client_secret:
            auth = (args.client_id, args.client_secret)
        try:
            resp = requests.post(token_url, data=data, auth=auth)
            resp.raise_for_status()
            tok = resp.json()
            access_token = tok["access_token"]
            new_rt = tok.get("refresh_token")
        except Exception as e:
            LOG.error("Token refresh failed: %s", e)
            continue
        try:
            exch = token_exchange_jwt_to_upst(exchange_url, args.client_id, args.client_secret or "", pub_b64, access_token)
            upst = exch["token"]
        except Exception as e:
            LOG.error("Token exchange failed: %s", e)
            continue
        try:
            write_secret_file(token_path, upst.encode())
            if new_rt:
                save_refresh_token(rt_path, new_rt, rt_passphrase, rt_iterations)
            LOG.info("Refresh completed successfully at %s UTC", datetime.now(timezone.utc).isoformat())
        except Exception as e:
            LOG.error("Failed to write refreshed materials: %s", e)


def run_cmd_passthrough(cmd_args: list[str], profile_name: Optional[str]) -> int:
    import subprocess
    # Ensure we invoke OCI and default to security_token auth for this profile
    full = ["oci"]
    already_has_profile = any(a == "--profile" or a.startswith("--profile=") for a in cmd_args)
    already_has_auth = any(a == "--auth" or a.startswith("--auth=") for a in cmd_args)
    if profile_name and not already_has_profile:
        full.extend(["--profile", profile_name])
    if not already_has_auth:
        full.extend(["--auth", "security_token"])
    full.extend(cmd_args)
    LOG.info("Executing passthrough command: %s", " ".join(full))
    try:
        rc = subprocess.run(full).returncode
        return rc
    except FileNotFoundError as e:
        LOG.error("Command not found: %s", e)
        return 127
    except Exception as e:
        LOG.error("Command error: %s", e)
        return 1


def main():
    p = argparse.ArgumentParser(description="OCI UPST session manager: Authorization Code + Refresh Token + Token Exchange + interval refresh", allow_abbrev=False)
    # Profile/OCI config
    p.add_argument("--profile-name", default=None, help="OCI profile name to create/update")
    p.add_argument("--region", default=None, help="OCI region, e.g., us-ashburn-1")
    p.add_argument("--config-file", default=None, help="Path to OCI config (default: ~/.oci/config)")
    # OAuth/AuthZ
    p.add_argument("--authz-base-url", default=None, help="Full authorization endpoint URL (e.g., https://idcs-xxx.identity.oraclecloud.com/oauth2/v1/authorize)")
    p.add_argument("--token-url", default=None, help="Token endpoint URL (required)")
    p.add_argument("--client-id", default=None, help="OAuth client id")
    p.add_argument("--client-secret", default=None, help="OAuth client secret (required for OCI IAM token exchange)")
    p.add_argument("--scope", default=None, help="Requested scopes (must include offline_access to get a refresh token)")
    p.add_argument("--redirect-port", type=int, default=None, help="Local redirect port (default 8181)")
    # Token exchange
    p.add_argument("--token-exchange-url", default=None, help="Token exchange URL (default: --token-url)")
    # Crypto
    # removed --key-bits; always 2048
    # Schedule/Logging
    p.add_argument("--refresh-interval", default=None, help="Refresh interval: 0 (disable), or 45, 45m, 1h (max 60m; default 0)")
    p.add_argument("--log-level", default=None, help="Logging level (DEBUG, INFO, WARNING, ERROR; default INFO)")
    # Refresh token encryption
    p.add_argument("--refresh-token-passphrase-env", default=None, help="Env var name holding passphrase to encrypt/decrypt refresh token")
    p.add_argument("--refresh-token-passphrase-prompt", action="store_true", help="Prompt for passphrase to encrypt/decrypt refresh token")
    # removed --refresh-token-kdf-iterations; use constant REFRESH_TOKEN_KDF_ITERATIONS
    # Manager config file (INI)
    p.add_argument("--manager-config", default=None, help="Path to optional INI config file (OCI style). If omitted, the wrapper will look for '" + MANAGER_DEFAULT_FILENAME + "' beside the OCI --config-file (or in ~/.oci when --config-file not supplied). CLI flags override values from this file.")
    p.add_argument("--manager-config-section", default=None, help="Section name inside manager INI to load (resolution order: explicit --manager-config-section, --profile-name, DEFAULT pseudo-section, first real section)")

    args, passthrough = p.parse_known_args()

    # Extract --profile from passthrough if present (forms: --profile value OR --profile=value)
    # --------------------------------------------------------------------------------------
    # Profile Resolution Semantics (DOCUMENTATION):
    # The effective profile name governs:
    #   - The OCI config profile section to read/update (key_file, security_token_file, region)
    #   - The session artifacts folder: ~/.oci/sessions/<profile>/
    #   - Refresh token encryption / storage path
    # Precedence order (highest first):
    #   1. --profile-name (wrapper-specific flag)
    #   2. Passthrough --profile (OCI CLI flag captured from remaining args)
    #   3. Selected manager-config section name (explicit --manager-config-section OR auto-picked)
    #      If DEFAULT pseudo-section is used, its values are merged but do not supply a section name;
    #      you still need a profile from (1) or (2) or any real section.
    # Failure mode:
    #   If after precedence evaluation no profile is determined, the wrapper exits with a clear error.
    # Manager Config Auto-Discovery:
    #   If --manager-config is omitted, we look for a file named `woci_manager.ini` in the same directory
    #   as the resolved OCI --config-file (or ~/.oci by default). If found, it is loaded.
    # Section Resolution (manager config):
    #   1. Explicit --manager-config-section (if present)
    #   2. Section named exactly as --profile-name (if provided and exists)
    #   3. Section named exactly as passthrough --profile (if --profile-name not provided and exists)
    #   4. DEFAULT pseudo-section (only if neither profile-name nor passthrough profile specified)
    #   5. First real section fallback
    # Notes:
    #   - DEFAULT pseudo-section only contributes key/value pairs but is not itself a profile name.
    #   - Values from the chosen section are used only when CLI flags are absent (CLI overrides config).
    #   - Required runtime values: authz_base_url, token_url, client_id, client_secret, scope.
    #   - client_secret is mandatory for OCI IAM token exchange.
    # --------------------------------------------------------------------------------------
    cli_profile = None
    i = 0
    while i < len(passthrough):
        token = passthrough[i]
        if token == '--profile':
            if i + 1 < len(passthrough):
                cli_profile = passthrough[i+1]
            break
        elif token.startswith('--profile='):
            cli_profile = token.split('=', 1)[1]
            break
        i += 1

    ini_section_data = {}
    auto_manager_path = None
    selected_section_name = None  # record chosen section for fallback profile resolution
    # Auto-discover manager config if not explicitly provided
    if not args.manager_config:
        # Determine base directory from --config-file or default ~/.oci
        cfg_path = args.config_file or os.path.expanduser(os.path.join(f"~/{OCI_DIRNAME}", OCI_CONFIG_FILENAME))
        cfg_dir = os.path.dirname(cfg_path)
        candidate = os.path.join(cfg_dir, MANAGER_DEFAULT_FILENAME)
        if os.path.exists(candidate):
            auto_manager_path = candidate
    manager_path = args.manager_config or auto_manager_path
    if manager_path:
        cp = configparser.ConfigParser()
        try:
            read_files = cp.read(manager_path)
            if not read_files:
                if args.manager_config:
                    print(f"Failed to read manager-config file: {manager_path}", file=sys.stderr)
                    sys.exit(2)
            else:
                # Section resolution order:
                # 1. Explicit --manager-config-section
                # 2. Section named exactly as --profile-name (if provided and exists)
                # 3. Section named exactly as passthrough --profile (if --profile-name not provided and exists)
                # 4. DEFAULT pseudo-section (only if neither profile-name nor passthrough profile specified)
                # 5. First real section fallback
                if args.manager_config_section and args.manager_config_section in cp:
                    selected_section_name = args.manager_config_section
                elif args.profile_name and args.profile_name in cp:
                    selected_section_name = args.profile_name
                elif (not args.profile_name and cli_profile and cli_profile in cp):
                    selected_section_name = cli_profile
                elif (not args.profile_name and not cli_profile and not args.manager_config_section and cp.defaults()):
                    # Use DEFAULT values directly
                    ini_section_data = {k: v for k, v in cp.defaults().items()}
                    selected_section_name = 'DEFAULT'
                if selected_section_name is None and not ini_section_data:
                    real_sections = cp.sections()
                    if real_sections:
                        selected_section_name = real_sections[0]
                if selected_section_name:
                    # Only populate if not already using DEFAULT pseudo-section
                    if selected_section_name != 'DEFAULT':
                        ini_section_data = {k: v for k, v in cp[selected_section_name].items()}
                elif args.manager_config and not ini_section_data:
                    print("No usable section found in manager-config file.", file=sys.stderr)
                    sys.exit(2)
        except Exception as e:
            if args.manager_config:
                print(f"Error reading manager-config: {e}", file=sys.stderr)
                sys.exit(2)

    DEFAULTS = {
        "config_file": os.path.expanduser(os.path.join(f"~/{OCI_DIRNAME}", OCI_CONFIG_FILENAME)),
        "redirect_port": 8181,
        "refresh_interval": "0",
        "log_level": "INFO",
    }

    def pick(name, cli_val, cast=None):
        if cli_val is not None:
            return cli_val
        if name in ini_section_data and ini_section_data[name] != "":
            return cast(ini_section_data[name]) if cast else ini_section_data[name]
        return DEFAULTS.get(name)

    # Merge values
    args.profile_name = pick("profile_name", args.profile_name)
    args.region = pick("region", args.region)
    args.config_file = pick("config_file", args.config_file)
    args.authz_base_url = pick("authz_base_url", args.authz_base_url)
    args.token_url = pick("token_url", args.token_url)
    args.client_id = pick("client_id", args.client_id)
    args.client_secret = pick("client_secret", args.client_secret)
    args.scope = pick("scope", args.scope)
    args.redirect_port = pick("redirect_port", args.redirect_port, int)
    args.token_exchange_url = pick("token_exchange_url", args.token_exchange_url)
    args.refresh_interval = pick("refresh_interval", args.refresh_interval)
    args.log_level = pick("log_level", args.log_level)

    # Resolve effective profile name precedence: --profile-name > passthrough --profile > selected section name
    if not args.profile_name:
        if cli_profile:
            args.profile_name = cli_profile
        elif selected_section_name:
            args.profile_name = selected_section_name

    if not args.profile_name:
        print("Could not determine profile name: supply --profile-name, --profile, or ensure manager config has a section.", file=sys.stderr)
        sys.exit(2)

    # Encryption flags
    ini_prompt = ini_section_data.get("refresh_token_passphrase_prompt", "false").lower() == "true"
    args.refresh_token_passphrase_prompt = bool(args.refresh_token_passphrase_prompt) or ini_prompt
    if args.refresh_token_passphrase_env is None:
        args.refresh_token_passphrase_env = ini_section_data.get("refresh_token_passphrase_env")

    # Required args (excluding profile_name which we resolved separately)
    missing = [k for k in ["authz_base_url", "token_url", "client_id", "client_secret", "scope"] if getattr(args, k) in (None, "")]
    if missing:
        print(f"Missing required options: {', '.join(missing)}. Provide via CLI or manager-config.", file=sys.stderr)
        sys.exit(2)

    # Validation of URL shape (must look like http/https)
    bad = []
    for nm in ["authz_base_url", "token_url", "token_exchange_url"]:
        val = getattr(args, nm, None)
        if val and not (val.startswith("http://") or val.startswith("https://")):
            bad.append((nm, val))
    if bad:
        print("Invalid URL value(s): " + ", ".join(f"{n}='{v}'" for n,v in bad) + "; must start with http:// or https://", file=sys.stderr)
        sys.exit(2)

    setup_logging(args.log_level)

    LOG.info("Resolved config: profile=%s authz_url=%s token_url=%s exchange_url=%s scope='%s' source_profile_cli=%s section=%s", args.profile_name, args.authz_base_url, args.token_url, args.token_exchange_url or args.token_url, args.scope, cli_profile, selected_section_name)
    LOG.info("Profile resolution precedence applied (profile-name > passthrough --profile > section name). Using profile '%s'.", args.profile_name)

    rt_passphrase = get_rt_passphrase(args)
    rt_iters = REFRESH_TOKEN_KDF_ITERATIONS

    try:
        ensure_session(args, rt_passphrase, rt_iters)
    except Exception as e:
        LOG.error("Failed to ensure session: %s", e)
        sys.exit(1)

    seconds = parse_interval_to_seconds(args.refresh_interval)
    stop_event = threading.Event()
    th = None
    if seconds > 0:
        def handle_signal(signum, _):
            LOG.info("Signal %s received; stopping.", signum)
            stop_event.set()
        import signal as pysignal
        pysignal.signal(pysignal.SIGINT, handle_signal)
        pysignal.signal(pysignal.SIGTERM, handle_signal)
        th = threading.Thread(target=refresh_cycle, args=(args, stop_event, rt_passphrase, rt_iters), daemon=True)
        th.start()

    rc = 0
    if passthrough:
        LOG.info("OCI passthrough args: %s", " ".join(passthrough))
        rc = run_cmd_passthrough(passthrough, args.profile_name)
    else:
        LOG.info("No passthrough command specified. Session ensured; exiting (interval=%s).", args.refresh_interval)

    if th is not None:
        try:
            while not stop_event.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            stop_event.set()
        th.join(timeout=5)

    sys.exit(rc)


if __name__ == "__main__":
    main()
