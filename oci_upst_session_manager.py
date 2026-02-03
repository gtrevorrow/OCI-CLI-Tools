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
import errno
import signal
import atexit
from importlib.metadata import version as pkg_version, PackageNotFoundError
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
OCI_DIRNAME = ".oci"
OCI_CONFIG_FILENAME = "config"
SESSION_DIRNAME = "sessions"
SESSION_TOKEN_FILENAME = "token"
SESSION_KEY_FILENAME = "private_key.pem"
SESSION_REFRESH_TOKEN_FILENAME = "refresh_token"
SESSION_DAEMON_PID_FILENAME = "woci_refresh.pid"
SESSION_ROOT = os.path.expanduser(os.path.join(f"~/{OCI_DIRNAME}", SESSION_DIRNAME))
# Always use 2048-bit RSA keys
RSA_KEY_BITS = 2048
# KDF iterations for refresh token encryption (constant). Increase to increase CPU cost for attackers
REFRESH_TOKEN_KDF_ITERATIONS = 200_000
# Default manager config filename for auto-discovery
MANAGER_DEFAULT_FILENAME = "woci_manager.ini"
# Package version (from pyproject.toml via importlib.metadata)
try:
    __version__ = pkg_version("oci-cli-tools")
except PackageNotFoundError:
    __version__ = "dev"
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


# ---------- OAuth PKCE (S256) helpers ----------

import secrets
import hashlib


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
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
        self.wfile.write(
            b"<html><body>Authentication complete. You can close this window.</body></html>"
        )

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


def save_refresh_token(
    path: str, rt: str, passphrase: Optional[str], iterations: int = 200_000
) -> None:
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
                raise RuntimeError(
                    "Refresh token is encrypted; supply a passphrase via --refresh-token-passphrase-prompt or --refresh-token-passphrase-env."
                )
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
            LOG.warning(
                "Empty passphrase entered; refresh token will be stored unencrypted."
            )
            return None
        return pw
    env_name = getattr(args, "refresh_token_passphrase_env", None)
    if env_name:
        pw = os.environ.get(env_name)
        if pw:
            return pw
        LOG.warning(
            "Env var %s is not set or empty; refresh token will be stored unencrypted.",
            env_name,
        )
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
    auth_url = (
        args.authz_base_url
        + "?"
        + urlencode(
            {
                "response_type": "code",
                "client_id": args.auth_client_id,
                "redirect_uri": redirect_uri,
                "scope": args.scope,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
    )
    LOG.info("Auth URL: %s", auth_url)
    LOG.info("Opening browser for authorization...")
    try:
        import webbrowser

        opened = webbrowser.open(auth_url)
        if not opened:
            LOG.warning(
                "webbrowser.open returned False; attempting macOS 'open' fallback."
            )
            if sys.platform == "darwin":
                try:
                    import subprocess

                    subprocess.run(["open", auth_url], check=False)
                except Exception:
                    LOG.warning(
                        "macOS 'open' fallback failed; manually open the URL above."
                    )
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
        raise RuntimeError(
            "token_url is required; provide it via CLI or manager-config"
        )
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": args.auth_client_id,
        "code_verifier": verifier,
    }
    auth = None
    if args.auth_client_secret:
        auth = (args.auth_client_id, args.auth_client_secret)
    resp = requests.post(token_url, data=data, auth=auth)
    resp.raise_for_status()
    tok = resp.json()
    if "access_token" not in tok or "refresh_token" not in tok:
        raise RuntimeError(
            "Token endpoint did not return access_token and refresh_token"
        )
    return tok


def token_exchange_jwt_to_upst(
    token_exchange_url: str,
    client_id: str,
    client_secret: str,
    public_key_b64: str,
    access_token: str,
) -> dict:
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
    return rsa.generate_private_key(
        public_exponent=65537, key_size=key_bits, backend=default_backend()
    )


def resolve_oci_paths(config_file: str, profile_name: str):
    """Return paths for UPST (session) token, private key and refresh token.

    Use the OCI CLI session layout: ~/.oci/sessions/<profile_name>/security_token
    """
    sessions_root = SESSION_ROOT
    base_dir = os.path.join(sessions_root, profile_name)
    token_path = os.path.join(base_dir, SESSION_TOKEN_FILENAME)
    key_path = os.path.join(base_dir, SESSION_KEY_FILENAME)
    rt_path = os.path.join(base_dir, SESSION_REFRESH_TOKEN_FILENAME)
    pid_path = os.path.join(base_dir, SESSION_DAEMON_PID_FILENAME)
    return base_dir, token_path, key_path, rt_path, pid_path


def update_oci_config(
    config_file: str,
    profile_name: str,
    region: Optional[str],
    key_file: str,
    token_file: str,
):
    # Upsert semantics: update existing keys in-place, add if missing, and drop duplicates.
    lines: list[str] = []
    if os.path.exists(config_file):
        with open(config_file, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()

    desired = {
        "key_file": key_file,
        "security_token_file": token_file,
    }
    if region is not None:
        desired["region"] = region

    out: list[str] = []
    in_target = False
    found_target = False
    seen: dict[str, bool] = {k: False for k in desired}

    def append_missing() -> None:
        for k, v in desired.items():
            if not seen.get(k):
                out.append(f"{k}={v}")
                seen[k] = True

    for ln in lines:
        stripped = ln.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_target:
                append_missing()
            in_target = stripped == f"[{profile_name}]"
            out.append(ln)
            if in_target:
                found_target = True
            continue

        if in_target and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in desired:
                if not seen[key]:
                    out.append(f"{key}={desired[key]}")
                    seen[key] = True
                # Drop duplicate entries for managed keys
                continue
        out.append(ln)

    if in_target:
        append_missing()
    elif not found_target:
        out.append(f"[{profile_name}]")
        for k, v in desired.items():
            out.append(f"{k}={v}")

    with open(config_file, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    try:
        os.chmod(config_file, 0o600)
    except Exception:
        pass


def save_initial_materials(
    args,
    key,
    upst: str,
    refresh_token: str,
    rt_passphrase: Optional[str],
    rt_iterations: int,
):
    base_dir, token_path, key_path, rt_path, pid_path = resolve_oci_paths(
        args.config_file, args.profile_name
    )
    write_secret_file(
        key_path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    write_secret_file(token_path, upst.encode())
    save_refresh_token(rt_path, refresh_token, rt_passphrase, rt_iterations)
    update_oci_config(
        args.config_file, args.profile_name, args.region, key_path, token_path
    )
    LOG.info(
        "Wrote key, UPST, and refresh token; updated OCI config for profile '%s'",
        args.profile_name,
    )


def decode_jwt_exp(token_str: str) -> Optional[datetime]:
    try:
        parts = token_str.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        # base64url decode
        pad = "=" * (
            -len(payload_b64) % 4
        )  # calc the b64 padding mising from JWT payloads
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + pad))
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)):
            return None
        return datetime.fromtimestamp(int(exp), tz=timezone.utc)
    except Exception:
        return None


def perform_exchange_and_save(
    args,
    access_token: str,
    maybe_refresh_token: Optional[str],
    rt_passphrase: Optional[str],
    rt_iterations: int,
) -> str:
    base_dir, token_path, key_path, rt_path, pid_path = resolve_oci_paths(
        args.config_file, args.profile_name
    )
    key = None  # type: ignore[assignment]
    if not os.path.exists(key_path):
        LOG.info("No key found; generating new RSA key and updating profile.")
        key = generate_rsa(RSA_KEY_BITS)
        write_secret_file(
            key_path,
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        update_oci_config(
            args.config_file, args.profile_name, args.region, key_path, token_path
        )
    else:
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    pub_b64 = b64_der_spki(key.public_key())
    if not args.client_secret:
        raise RuntimeError(
            "client_secret is required for OCI IAM token exchange but was not provided"
        )
    exchange_url = args.token_exchange_url or args.token_url
    exch = token_exchange_jwt_to_upst(
        exchange_url, args.client_id, args.client_secret or "", pub_b64, access_token
    )
    upst = exch["token"]
    write_secret_file(token_path, upst.encode())
    if maybe_refresh_token:
        save_refresh_token(rt_path, maybe_refresh_token, rt_passphrase, rt_iterations)
    return upst


def ensure_session(
    args, rt_passphrase: Optional[str], rt_iterations: int, reauth: bool = False
) -> str:
    base_dir, token_path, key_path, rt_path, pid_path = resolve_oci_paths(
        args.config_file, args.profile_name
    )
    # 1) If UPST exists and not expiring in next 60s, do nothing
    if not reauth and os.path.exists(token_path):
        try:
            with open(token_path, "r", encoding="utf-8") as f:
                upst = f.read().strip()
            exp = decode_jwt_exp(upst)
            if exp and exp > datetime.now(timezone.utc) + timedelta(seconds=60):
                LOG.info(
                    "Existing UPST valid until %s; no refresh needed.", exp.isoformat()
                )
                return upst
            else:
                LOG.info(
                    "Existing UPST missing/near expiry; will attempt refresh or re-auth."
                )
        except Exception:
            LOG.info("Could not read existing UPST; will attempt refresh or re-auth.")

    # 2) If refresh_token exists, use it to refresh AT and exchange to UPST
    if not reauth and os.path.exists(rt_path):
        try:
            upst = refresh_from_refresh_token(args, rt_passphrase, rt_iterations)
            return upst
        except Exception as e:
            LOG.warning("Refresh using refresh_token failed: %s", e)

    # 3) Fall back to interactive Authorization Code flow
    LOG.info("Starting Authorization Code flow to obtain new session.")
    tokens = oauth_authorization_code_flow(args)
    upst = perform_exchange_and_save(
        args,
        tokens["access_token"],
        tokens.get("refresh_token"),
        rt_passphrase,
        rt_iterations,
    )
    LOG.info("New session created via Authorization Code flow.")
    return upst


def schedule_next_refresh(upst: str, safety_window_seconds: int) -> Optional[float]:
    exp = decode_jwt_exp(upst)
    if not exp:
        return None
    next_run = exp - timedelta(seconds=safety_window_seconds)
    return max((next_run - datetime.now(timezone.utc)).total_seconds(), 0.0)


def refresh_from_refresh_token(
    args, rt_passphrase: Optional[str], rt_iterations: int
) -> str:
    base_dir, token_path, key_path, rt_path, pid_path = resolve_oci_paths(
        args.config_file, args.profile_name
    )
    if not os.path.exists(rt_path):
        raise RuntimeError("No refresh token available for auto-refresh")
    refresh_token = load_refresh_token(rt_path, rt_passphrase)
    token_url = args.token_url
    if not token_url:
        raise RuntimeError(
            "token_url is required for refresh; provide it via CLI or manager-config"
        )
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": args.auth_client_id,
    }
    auth = None
    if args.auth_client_secret:
        auth = (args.auth_client_id, args.auth_client_secret)
    resp = requests.post(token_url, data=data, auth=auth)
    resp.raise_for_status()
    tok = resp.json()
    access_token = tok["access_token"]
    new_rt = tok.get("refresh_token", refresh_token)
    if new_rt != refresh_token:
        LOG.info("OIDC provider rotated the refresh token; storing the new value.")
    upst = perform_exchange_and_save(
        args, access_token, new_rt, rt_passphrase, rt_iterations
    )
    LOG.info("Session refreshed from refresh_token.")
    return upst


def start_auto_refresh_thread(
    args,
    rt_passphrase: Optional[str],
    rt_iterations: int,
    safety_window_seconds: int,
    initial_upst: Optional[str],
) -> threading.Thread:
    def _loop() -> None:
        min_backoff = 30
        current_upst = initial_upst
        while True:
            try:
                if not current_upst:
                    current_upst = ensure_session(args, rt_passphrase, rt_iterations)
                sleep_for = schedule_next_refresh(current_upst, safety_window_seconds)
                if sleep_for is None:
                    LOG.warning(
                        "Unable to determine UPST expiry; retrying in %ss.", min_backoff
                    )
                    time.sleep(min_backoff)
                    continue
                LOG.info(
                    "Next auto-refresh scheduled in %.0fs (safety window %ss).",
                    sleep_for,
                    safety_window_seconds,
                )
                time.sleep(sleep_for)
                current_upst = refresh_from_refresh_token(
                    args, rt_passphrase, rt_iterations
                )
            except Exception as e:
                LOG.warning("Auto-refresh attempt failed: %s", e)
                time.sleep(min_backoff)

    th = threading.Thread(target=_loop, daemon=True)
    th.start()
    return th


def is_pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError as e:
        if e.errno == errno.ESRCH:
            return False
        return True


def read_pid_file(pid_path: str) -> Optional[int]:
    if not os.path.exists(pid_path):
        return None
    try:
        with open(pid_path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            return None
        return int(raw)
    except Exception:
        return None


def write_pid_file(pid_path: str, pid: int) -> None:
    ensure_dir(pid_path)
    with open(pid_path, "w", encoding="utf-8") as f:
        f.write(str(pid))
    try:
        os.chmod(pid_path, 0o600)
    except Exception:
        pass


def remove_pid_file(pid_path: str) -> None:
    try:
        if os.path.exists(pid_path):
            os.remove(pid_path)
    except Exception:
        pass


def stop_daemon(pid_path: str, timeout_seconds: int = 5) -> bool:
    pid = read_pid_file(pid_path)
    if pid is None:
        LOG.info("No daemon PID file found.")
        return False
    if not is_pid_running(pid):
        LOG.info("Stale PID file found; removing.")
        remove_pid_file(pid_path)
        return False
    LOG.info("Stopping daemon PID %s", pid)
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception as e:
        LOG.error("Failed to send SIGTERM: %s", e)
        return False
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if not is_pid_running(pid):
            remove_pid_file(pid_path)
            LOG.info("Daemon stopped.")
            return True
        time.sleep(0.2)
    LOG.warning("Daemon did not stop in time; sending SIGKILL.")
    try:
        os.kill(pid, signal.SIGKILL)
    except Exception as e:
        LOG.error("Failed to send SIGKILL: %s", e)
        return False
    time.sleep(0.2)
    remove_pid_file(pid_path)
    return True


def daemon_status(pid_path: str) -> bool:
    pid = read_pid_file(pid_path)
    if pid is None:
        LOG.info("Daemon not running (no PID file).")
        return False
    if is_pid_running(pid):
        LOG.info("Daemon running with PID %s", pid)
        return True
    LOG.info("Daemon not running; stale PID file detected.")
    return False


def daemonize(pid_path: str) -> int:
    existing = read_pid_file(pid_path)
    if existing and is_pid_running(existing):
        raise RuntimeError(f"Daemon already running with PID {existing}")
    pid = os.fork()
    if pid > 0:
        return pid
    os.setsid()
    child_pid = os.getpid()
    write_pid_file(pid_path, child_pid)
    atexit.register(remove_pid_file, pid_path)
    return 0


def run_cmd_passthrough(cmd_args: list[str], profile_name: Optional[str]) -> int:
    import subprocess

    # Ensure we invoke OCI and default to security_token auth for this profile
    full = ["oci"]
    already_has_profile = any(
        a == "--profile" or a.startswith("--profile=") for a in cmd_args
    )
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
    passthrough_help = (
        "OCI CLI passthrough:\n"
        "  • Any flags not listed above are forwarded to the underlying 'oci' command.\n"
        "  • '--profile <name>' (OCI flag) is the canonical profile selector for both the wrapper and OCI.\n"
        "  • '--config-file' (OCI flag) is honored by oci; the wrapper auto-discovers woci_manager.ini in\n"
        "    the same directory (or ~/.oci as a fallback) unless '--manager-config' or 'WOCI_MANAGER_CONFIG' overrides it.\n"
        "  • You do not need to add '--' before OCI arguments; woci parses its own options first and leaves\n"
        "    the rest untouched.\n"
        "General flow:\n"
        "  woci [wrapper options] <oci service> <subcommand> [OCI options]\n"
        "Example:\n"
        "  woci --profile foo ce cluster generate-token --cluster-id OCID --region us-ashburn-1\n"
    )

    p = argparse.ArgumentParser(
        description="OCI UPST session manager: Authorization Code + Refresh Token + Token Exchange",
        allow_abbrev=False,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=passthrough_help,
        add_help=False,
    )
    p.add_argument(
        "-h",
        "--help",
        action="store_true",
        dest="wrapper_help",
        help="Show woci help and then display 'oci --help'",
    )

    # Profile/OCI config
    # profile-name removed; passthrough --profile is the sole selector
    p.add_argument("--region", default=None, help="OCI region, e.g., us-ashburn-1")
    p.add_argument(
        "--config-file",
        default=None,
        help="Path to OCI config (default: ~/.oci/config)",
    )
    # OAuth/AuthZ
    p.add_argument(
        "--authz-base-url",
        default=None,
        help="Full.authorization endpoint URL (e.g., https://idcs-xxx.identity.oraclecloud.com/oauth2/v1/authorize)",
    )
    p.add_argument("--token-url", default=None, help="Token endpoint URL (required)")
    p.add_argument(
        "--auth-client-id",
        default=None,
        help="OAuth/OIDC client id used for the Authorization Code + Refresh Token grants",
    )
    p.add_argument(
        "--auth-client-secret",
        default=None,
        help="OAuth/OIDC client secret for the Authorization/Refresh client",
    )
    p.add_argument(
        "--client-id",
        default=None,
        help="OCI token-exchange client id (Workload Identity Federation)",
    )
    p.add_argument(
        "--client-secret",
        default=None,
        help="OCI token-exchange client secret (required for OCI IAM token exchange)",
    )
    p.add_argument(
        "--scope",
        default=None,
        help="Requested scopes (must include offline_access to get a refresh token)",
    )
    p.add_argument(
        "--redirect-port",
        type=int,
        default=None,
        help="Local redirect port (provide via CLI or manager INI; commonly 8181)",
    )
    # Token exchange
    p.add_argument(
        "--token-exchange-url",
        default=None,
        help="Token exchange URL (default: --token-url)",
    )
    # Crypto
    # removed --key-bits; always 2048
    # Schedule/Logging
    p.add_argument(
        "--log-level",
        default=None,
        help="Logging level (DEBUG, INFO, WARNING, ERROR). If omitted, uses manager INI or INFO.",
    )
    p.add_argument(
        "--auto-refresh",
        action="store_true",
        help="Start background thread to refresh UPST before expiry",
    )
    p.add_argument(
        "--refresh-safety-window",
        type=int,
        default=None,
        help="Seconds before expiry to refresh UPST (default: 600)",
    )
    p.add_argument(
        "--daemon",
        action="store_true",
        help="Start a background daemon that refreshes UPST and exit",
    )
    p.add_argument(
        "--daemon-status",
        action="store_true",
        help="Show status of the refresh daemon for this profile",
    )
    p.add_argument(
        "--stop-daemon",
        action="store_true",
        help="Stop the refresh daemon for this profile",
    )
    # Refresh token encryption
    p.add_argument(
        "--refresh-token-passphrase-env",
        default=None,
        help="Env var name holding passphrase to encrypt/decrypt refresh token",
    )
    p.add_argument(
        "--refresh-token-passphrase-prompt",
        action="store_true",
        help="Prompt for passphrase to encrypt/decrypt refresh token",
    )
    # removed --refresh-token-kdf-iterations; use constant REFRESH_TOKEN_KDF_ITERATIONS
    # Manager config file (INI)
    p.add_argument(
        "--manager-config",
        default=None,
        help="Path to optional INI config file (OCI style). If omitted, the wrapper will look for '"
        + MANAGER_DEFAULT_FILENAME
        + "' beside the OCI --config-file (and then fall back to ~/.oci). CLI flags override values from this file.",
    )

    args, passthrough = p.parse_known_args()

    if getattr(args, "wrapper_help", False):
        p.print_help()
        sys.stdout.flush()
        print("\n--- OCI CLI help (oci --help) ---\n")
        try:
            import subprocess

            subprocess.run(["oci", "--help"], check=False)
        except FileNotFoundError:
            print(
                "oci executable not found on PATH; install OCI CLI to view its help.",
                file=sys.stderr,
            )
        sys.exit(0)

    # Extract --profile from passthrough if present (forms: --profile value OR --profile=value)
    # --------------------------------------------------------------------------------------
    # Profile Resolution Semantics (DOCUMENTATION):
    # The effective profile name governs:
    #   - The OCI config profile section to read/update (key_file, security_token_file, region)
    #   - The session artifacts folder: ~/.oci/sessions/<profile>/
    #   - Refresh token encryption / storage path
    # Unified source of truth:
    #   - Passthrough --profile is the canonical selector. If a manager-config section is explicitly chosen
    #     (or auto-selected), it must match the passthrough profile when provided. Conflicts are fatal.
    # Profile determination:
    #   1. Collect candidates from passthrough --profile and the selected manager-config section name.
    #   2. If multiple distinct values are present, exit with configuration error.
    #   3. If none are present, fall back to the OCI-style DEFAULT profile name.
    # Manager Config Auto-Discovery:
    #   If --manager-config is omitted, we look for a file named `woci_manager.ini` in the same directory
    #   as the resolved OCI --config-file. If not found there, we fall back to ~/.oci/woci_manager.ini.
    # Manager INI merging:
    #   Values are merged as [COMMON] base plus the selected section overrides. CLI flags override both.
    # Required runtime values: authz_base_url, token_url, client_id, client_secret, scope, redirect_port.
    # client_secret is mandatory for OCI IAM token exchange.
    # --------------------------------------------------------------------------------------
    cli_profile = None
    i = 0
    while i < len(passthrough):
        token = passthrough[i]
        if token == "--profile":
            if i + 1 < len(passthrough):
                cli_profile = passthrough[i + 1]
            break
        elif token.startswith("--profile="):
            cli_profile = token.split("=", 1)[1]
            break
        i += 1

    ini_section_data = {}
    auto_manager_path = None
    selected_section_name = None  # record chosen section for metadata
    # Auto-discover manager config if not explicitly provided
    if not args.manager_config:
        # Determine base directory from --config-file or default ~/.oci
        cfg_path = args.config_file or os.path.expanduser(
            os.path.join(f"~/{OCI_DIRNAME}", OCI_CONFIG_FILENAME)
        )
        cfg_dir = os.path.dirname(cfg_path)
        candidate = os.path.join(cfg_dir, MANAGER_DEFAULT_FILENAME)
        if os.path.exists(candidate):
            auto_manager_path = candidate
        else:
            fallback = os.path.expanduser(
                os.path.join(f"~/{OCI_DIRNAME}", MANAGER_DEFAULT_FILENAME)
            )
            if fallback != candidate and os.path.exists(fallback):
                auto_manager_path = fallback
    # Allow manager-config path to be provided via environment variable as well.
    # Precedence: CLI flag (--manager-config) > env var WOCI_MANAGER_CONFIG > auto-discovered file
    mgr_env = os.environ.get("WOCI_MANAGER_CONFIG")
    manager_path_source = None
    if args.manager_config:
        manager_path = args.manager_config
        manager_path_source = "cli"
    elif mgr_env:
        manager_path = mgr_env
        manager_path_source = "env"
    else:
        manager_path = auto_manager_path
        manager_path_source = "auto" if auto_manager_path else None

    cp = None
    common_data = {}
    if manager_path:
        cp = configparser.ConfigParser()
        try:
            read_files = cp.read(manager_path)
            if not read_files and args.manager_config:
                print(
                    f"Failed to read manager-config file: {manager_path}",
                    file=sys.stderr,
                )
                sys.exit(2)
            if read_files:
                # Collect [COMMON] values (shared defaults for all sections)
                if cp.has_section("COMMON"):
                    common_data.update({k: v for k, v in cp["COMMON"].items()})

                # Section resolution
                # Section resolution
                if cli_profile:
                    if cp.has_section(cli_profile):
                        selected_section_name = cli_profile
                else:
                    if cp.has_section("DEFAULT"):
                        selected_section_name = "DEFAULT"

                # Merge: [COMMON] base + selected section overrides (if present)
                ini_section_data = dict(common_data)
                if selected_section_name and selected_section_name in cp:
                    ini_section_data.update(
                        {k: v for k, v in cp[selected_section_name].items()}
                    )
        except Exception as e:
            # If the manager path came from CLI or env, treat errors as fatal. For auto discovery, ignore and continue.
            if manager_path_source in ("cli", "env"):
                print(f"Error reading manager-config: {e}", file=sys.stderr)
                sys.exit(2)

    # Remove hard-coded defaults; only retain fallback for OCI config file path
    DEFAULTS = {
        "config_file": os.path.expanduser(
            os.path.join(f"~/{OCI_DIRNAME}", OCI_CONFIG_FILENAME)
        ),
    }

    def pick(name, cli_val, cast=None):
        if cli_val is not None:
            return cli_val
        if name in ini_section_data and ini_section_data[name] != "":
            return cast(ini_section_data[name]) if cast else ini_section_data[name]
        return DEFAULTS.get(name)

    # Profile consistency enforcement (only passthrough --profile and section name)
    # Profile resolution
    if cli_profile:
        args.profile_name = cli_profile
    elif selected_section_name and selected_section_name != "COMMON":
        args.profile_name = selected_section_name
    else:
        # Fall back to OCI-style DEFAULT profile when nothing was specified
        args.profile_name = "DEFAULT"

    # Merge values
    args.region = pick("region", args.region)
    args.config_file = pick("config_file", args.config_file)
    if args.config_file is None:
        args.config_file = DEFAULTS["config_file"]
    args.authz_base_url = pick("authz_base_url", args.authz_base_url)
    args.token_url = pick("token_url", args.token_url)
    args.auth_client_id = pick("auth_client_id", args.auth_client_id)
    args.auth_client_secret = pick("auth_client_secret", args.auth_client_secret)
    args.client_id = pick("client_id", args.client_id)
    args.client_secret = pick("client_secret", args.client_secret)
    args.scope = pick("scope", args.scope)
    # No hard-coded default for redirect_port; must come from CLI or manager INI [DEFAULT]/section
    rp = pick("redirect_port", args.redirect_port)
    args.redirect_port = int(rp) if rp is not None else None
    args.refresh_safety_window = pick(
        "refresh_safety_window", args.refresh_safety_window, int
    )
    args.token_exchange_url = pick("token_exchange_url", args.token_exchange_url)
    args.log_level = pick("log_level", args.log_level)

    base_dir, token_path, key_path, rt_path, pid_path = resolve_oci_paths(
        args.config_file, args.profile_name
    )

    if args.daemon_status or args.stop_daemon:
        setup_logging(args.log_level or "INFO")
        if args.daemon_status:
            running = daemon_status(pid_path)
            sys.exit(0 if running else 1)
        if args.stop_daemon:
            stopped = stop_daemon(pid_path)
            sys.exit(0 if stopped else 1)

    # Encryption flags
    ini_prompt = (
        ini_section_data.get("refresh_token_passphrase_prompt", "false").lower()
        == "true"
    )
    args.refresh_token_passphrase_prompt = (
        bool(args.refresh_token_passphrase_prompt) or ini_prompt
    )
    if args.refresh_token_passphrase_env is None:
        args.refresh_token_passphrase_env = ini_section_data.get(
            "refresh_token_passphrase_env"
        )

    ini_auto_refresh = ini_section_data.get("auto_refresh", "false").lower() == "true"
    args.auto_refresh = bool(args.auto_refresh) or ini_auto_refresh

    if args.daemon and (args.daemon_status or args.stop_daemon):
        print(
            "--daemon cannot be combined with --daemon-status or --stop-daemon",
            file=sys.stderr,
        )
        sys.exit(2)

    # Required args check (expanded): require redirect_port to avoid unregistered redirect issues
    missing = [
        k
        for k in [
            "authz_base_url",
            "token_url",
            "auth_client_id",
            "client_id",
            "client_secret",
            "scope",
            "redirect_port",
        ]
        if getattr(args, k) in (None, "")
    ]
    if missing:
        print(
            f"Missing required options: {', '.join(missing)}. Provide via CLI or manager-config section (with optional [COMMON] shared values).",
            file=sys.stderr,
        )
        sys.exit(2)

    # Validation of URL shape (must look like http/https)
    bad = []
    for nm in ["authz_base_url", "token_url", "token_exchange_url"]:
        val = getattr(args, nm, None)
        if val and not (val.startswith("http://") or val.startswith("https://")):
            bad.append((nm, val))
    if bad:
        print(
            "Invalid URL value(s): "
            + ", ".join(f"{n}='{v}'" for n, v in bad)
            + "; must start with http:// or https://",
            file=sys.stderr,
        )
        sys.exit(2)

    setup_logging(args.log_level or "INFO")

    LOG.info("woci version %s", __version__)
    LOG.info(
        "Resolved config: profile=%s authz_url=%s token_url=%s exchange_url=%s scope='%s' redirect_port=%s section=%s",
        args.profile_name,
        args.authz_base_url,
        args.token_url,
        args.token_exchange_url or args.token_url,
        args.scope,
        args.redirect_port,
        selected_section_name,
    )

    # Improved detection: scan for "session" command, handling preceding flags
    session_index = -1
    for i, arg in enumerate(passthrough):
        if arg == "session":
            session_index = i
            break

    is_session_authenticate = False
    is_session_cmd = False

    if session_index != -1 and session_index + 1 < len(passthrough):
        subcmd = passthrough[session_index + 1]
        if subcmd == "authenticate":
            is_session_authenticate = True
            is_session_cmd = True
        elif subcmd == "refresh":
            is_session_cmd = True
    if is_session_cmd:
        LOG.info("Session ensured; skipping OCI session passthrough.")
        passthrough = []

    rt_passphrase = get_rt_passphrase(args)
    rt_iters = REFRESH_TOKEN_KDF_ITERATIONS
    refresh_safety_window = (
        int(args.refresh_safety_window)
        if args.refresh_safety_window is not None
        else 600
    )

    try:
        current_upst = ensure_session(
            args, rt_passphrase, rt_iters, reauth=is_session_authenticate
        )
    except Exception as e:
        LOG.error("Failed to ensure session: %s", e)
        sys.exit(1)

    if args.daemon:
        if passthrough:
            LOG.info("Daemon mode enabled; skipping OCI passthrough command.")
            passthrough = []
        try:
            parent_pid = daemonize(pid_path)
        except Exception as e:
            LOG.error("Failed to start daemon: %s", e)
            sys.exit(1)
        if parent_pid > 0:
            print(parent_pid)
            sys.exit(0)
        LOG.info("Daemon started with PID %s", os.getpid())
        start_auto_refresh_thread(
            args, rt_passphrase, rt_iters, refresh_safety_window, current_upst
        )
        while True:
            time.sleep(3600)

    if args.auto_refresh:
        LOG.info(
            "Starting auto-refresh thread with safety window %ss.",
            refresh_safety_window,
        )
        start_auto_refresh_thread(
            args, rt_passphrase, rt_iters, refresh_safety_window, current_upst
        )

    rc = 0
    if passthrough:
        LOG.info("OCI passthrough args: %s", " ".join(passthrough))
        rc = run_cmd_passthrough(passthrough, args.profile_name)
    else:
        LOG.info("No passthrough command specified. Session ensured; exiting.")

    sys.exit(rc)


if __name__ == "__main__":
    main()
