#!/usr/bin/env python3

"""
OCI CLI session wrapper: runs `oci session authenticate` and periodically refreshes
on a fixed interval (not derived from the token). The refresh interval is a
wrapper-only flag and is not passed through to the OCI CLI.

This wrapper does NOT parse or save the OCI CLI output. The OCI CLI writes
session state to the configured profile itself. Stdout/stderr from the CLI are
passed through to your terminal so you can complete any prompts.

Usage examples:
  - Authenticate and refresh every 45 minutes (default):
      ./oci_session_wrapper.py --profile-name test1 --region us-ashburn-1
  - Use custom commands:
      ./oci_session_wrapper.py \
        --auth-cmd "oci session authenticate" \
        --refresh-cmd "oci session refresh" \
        --refresh-interval 45
  - Use hours suffix for interval:
      ./oci_session_wrapper.py --refresh-interval 1h

Note:
  - The wrapper appends --profile-name to the authenticate command, and maps that same value to --profile
    for the refresh command, so no prompts appear on refresh.
"""

import argparse
import configparser
import logging
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

# TOML parsing: prefer stdlib tomllib (Python 3.11+), fallback to tomli if available
try:
    import tomllib as _tomllib
except Exception:
    try:
        import tomli as _tomllib
    except Exception:
        _tomllib = None

LOG = logging.getLogger("oci-session-wrapper")


def setup_logging(level_str: str) -> None:
    level = getattr(logging, level_str.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(level)


def run_cmd_passthrough(cmd: str) -> int:
    """Run a command with stdout/stderr passed through to this process.
    Returns the command's return code.
    """
    LOG.debug("Executing: %s", cmd)
    try:
        rc = subprocess.run(shlex.split(cmd)).returncode   # Note, this will not perform shell expansion
        if rc != 0:
            LOG.error("Command failed (rc=%s): %s", rc, cmd)
        return rc
    except FileNotFoundError as e:
        LOG.error("Command not found: %s", e)
        return 127
    except Exception as e:
        LOG.error("Command error: %s", e)
        return 1


def parse_refresh_interval_to_seconds(value: str) -> int:
    """Parse refresh interval string to seconds.
    Accepts: integer minutes (e.g., "45"), minutes with 'm' suffix ("45m"), or hours with 'h' suffix ("1h").
    Bare numbers are minutes. Enforces 1 <= minutes <= 60 (values above 60 are clamped with a warning).
    """
    s = value.strip().lower()
    minutes: int

    # hours suffix
    if s.endswith("h"):
        num = s[:-1].strip()
        if not num:
            raise ValueError("Invalid --refresh-interval: missing number before 'h'")
        minutes = int(num) * 60
    # minutes suffix
    elif s.endswith("m"):
        num = s[:-1].strip()
        if not num:
            raise ValueError("Invalid --refresh-interval: missing number before 'm'")
        minutes = int(num)
    else:
        # bare integer -> minutes
        minutes = int(s)

    if minutes < 1:
        raise ValueError("--refresh-interval must be at least 1 minute")
    if minutes > 60:
        LOG.warning("--refresh-interval %d > 60; clamping to 60 minutes due to OCI session limits.", minutes)
        minutes = 60
    return minutes * 60


def has_flag(tokens, name: str) -> bool:
    for t in tokens:
        if t == name or t.startswith(name + "="):
            return True
    return False


def augment_auth_cmd(cmd: str, profile_name: Optional[str], region: Optional[str], config_file: Optional[str]) -> str:
    """Append --profile-name, --region, --config-file for authenticate."""
    tokens = shlex.split(cmd)
    if profile_name and not has_flag(tokens, "--profile-name") and not has_flag(tokens, "--profile"):
        tokens += ["--profile-name", profile_name]
    if region and not has_flag(tokens, "--region"):
        tokens += ["--region", region]
    if config_file and not has_flag(tokens, "--config-file"):
        tokens += ["--config-file", config_file]
    # Use shlex.join for safe quoting
    try:
        return shlex.join(tokens)
    except AttributeError:
        # Fallback for very old Python (shouldn't happen): naive join
        return " ".join(shlex.quote(t) for t in tokens)


def augment_refresh_cmd(cmd: str, profile_name: Optional[str], region: Optional[str], config_file: Optional[str]) -> str:
    """Append --profile (mapped from profile_name), --region, --config-file for refresh."""
    tokens = shlex.split(cmd)
    if profile_name and not has_flag(tokens, "--profile") and not has_flag(tokens, "--profile-name"):
        tokens += ["--profile", profile_name]
    if region and not has_flag(tokens, "--region"):
        tokens += ["--region", region]
    if config_file and not has_flag(tokens, "--config-file"):
        tokens += ["--config-file", config_file]
    # Use shlex.join for safe quoting
    try:
        return shlex.join(tokens)
    except AttributeError:
        # Fallback for very old Python (shouldn't happen): naive join
        return " ".join(shlex.quote(t) for t in tokens)


def is_ini_file(path: str) -> bool:
    """Quick heuristic to decide if a file is INI-style (OCI config) vs TOML/YAML.
    We look for a [section] on the first few lines.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for _ in range(20):
                line = f.readline()
                if not line:
                    break
                if line.strip().startswith("[") and line.strip().endswith("]"):
                    return True
    except Exception:
        pass
    return False


def load_profile_from_toml(path: str, profile: str) -> Dict[str, Any]:
    if _tomllib is None:
        LOG.debug("TOML parser not available (tomllib/tomli); skipping TOML parsing for %s", path)
        return {}
    try:
        with open(path, "rb") as f:
            data = _tomllib.load(f)
    except Exception as e:
        LOG.debug("Failed to parse TOML %s: %s", path, e)
        return {}

    # TOML profiles could be tables with names matching profile
    # Allow top-level key-value (no tables) for a DEFAULT profile
    if profile in data and isinstance(data[profile], dict):
        section = data[profile]
        return {k.lower(): v for k, v in section.items()}
    # If profile is DEFAULT or not present, and top-level keys exist, return them
    if profile.upper() in ("DEFAULT", "OCI_DEFAULT") or profile == "DEFAULT":
        # top-level keys
        return {k.lower(): v for k, v in data.items()}
    # try lowercase profile
    if profile.lower() in data and isinstance(data[profile.lower()], dict):
        return {k.lower(): v for k, v in data[profile.lower()].items()}
    return {}


def load_profile_from_ini(path: str, profile: str) -> Dict[str, Any]:
    cp = configparser.ConfigParser()
    try:
        cp.read(path)
    except Exception as e:
        LOG.debug("Failed to read INI %s: %s", path, e)
        return {}
    if profile in cp:
        return {k.lower(): v for k, v in cp[profile].items()}
    # try DEFAULT
    if "DEFAULT" in cp:
        return {k.lower(): v for k, v in cp["DEFAULT"].items()}
    return {}


def find_and_load_profile(config_file_arg: Optional[str], profile: Optional[str]) -> Dict[str, Any]:
    """Locate a config file (if provided or in common locations) and return profile dict.

    Search order:
      1. If config_file_arg is provided, try to parse it (TOML or INI).
      2. ./config.toml
      3. ~/.oci/config (INI)

    Returns a dict of lowercase keys for the found profile (empty if nothing found).
    """
    candidates = []
    if config_file_arg:
        candidates.append(config_file_arg)
    repo_toml = os.path.join(os.getcwd(), "config.toml")
    if os.path.isfile(repo_toml):
        candidates.append(repo_toml)
    home_ini = os.path.expanduser("~/.oci/config")
    if os.path.isfile(home_ini):
        candidates.append(home_ini)

    for p in candidates:
        if not os.path.isfile(p):
            continue
        if is_ini_file(p):
            cfg = load_profile_from_ini(p, profile or "DEFAULT")
            if cfg:
                LOG.debug("Loaded profile %s from INI %s", profile, p)
                return cfg
        else:
            cfg = load_profile_from_toml(p, profile or "DEFAULT")
            if cfg:
                LOG.debug("Loaded profile %s from TOML %s", profile, p)
                return cfg
    return {}


def refresher_loop(interval_seconds: int, refresh_cmd: str, stop_event: threading.Event) -> None:
    # enforce a minimum interval to avoid thrashing (1 minute)
    min_seconds = 60
    if interval_seconds < min_seconds:
        LOG.warning("Requested interval %ds is too small; using %ds minimum.", interval_seconds, min_seconds)
        interval_seconds = min_seconds

    while not stop_event.is_set():
        next_run = datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)
        mins = int(interval_seconds // 60)
        LOG.info("Next refresh in %d minute(s) (at %s UTC)", mins, next_run.isoformat())
        if stop_event.wait(timeout=interval_seconds):
            break
        LOG.info("Refreshing session with: %s", refresh_cmd)
        rc = run_cmd_passthrough(refresh_cmd)
        if rc != 0:
            LOG.error("Refresh failed with rc=%s. Will retry after the interval.", rc)
        else:
            completed_at = datetime.now(timezone.utc)
            LOG.info("Refresh completed successfully at %s UTC", completed_at.isoformat())
            next_run = completed_at + timedelta(seconds=interval_seconds)
            LOG.info("Next refresh in %d minute(s) (at %s UTC)", mins, next_run.isoformat())


def main() -> None:
    p = argparse.ArgumentParser(
        description=(
            "Wrap `oci session authenticate` and refresh on a fixed interval. "
            "This wrapper does not parse or save CLI output; the OCI CLI writes session state itself."
        )
    )
    p.add_argument(
        "--auth-cmd",
        default="oci session authenticate",
        help="Command to obtain an initial session (default: 'oci session authenticate').",
    )
    p.add_argument(
        "--refresh-cmd",
        default="oci session refresh",
        help="Command to refresh the session (default: 'oci session refresh').",
    )
    # accept both --profile and --profile-name (OCI CLI uses --profile for many commands, authenticate uses --profile-name)
    p.add_argument(
        "--profile-name",
        dest="profile_name",
        default=None,
        help="Profile name to create/update in the OCI config (appended to auth as --profile-name, to refresh as --profile).",
    )
    p.add_argument(
        "--profile",
        dest="profile",
        default=None,
        help="Alias for --profile-name; accepts the OCI CLI style --profile option to select a profile section from a config file.",
    )
    p.add_argument(
        "--region",
        default=None,
        help="OCI region identifier (e.g., us-ashburn-1). Appended as --region if not already present.",
    )
    p.add_argument(
        "--config-file",
        default=None,
        help="Path to non-default OCI config file. Appended as --config-file if not already present (only if it's an INI-style file).",
    )
    p.add_argument(
        "--refresh-interval",
        default="45",
        help=(
            "Refresh interval (default: 45m). Accept minutes or hours: e.g., 45, 45m, 1h. "
            "Bare numbers are minutes. Max effective interval is 60 minutes."
        ),
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR).",
    )

    args = p.parse_args()

    setup_logging(args.log_level)

    # resolve profile name preference: CLI --profile (OCI style) overrides --profile-name
    profile_name = args.profile if args.profile is not None else args.profile_name

    try:
        interval_seconds = parse_refresh_interval_to_seconds(args.refresh_interval)
    except Exception as e:
        LOG.error(str(e))
        sys.exit(2)

    # attempt to load profile settings from config files (TOML or INI) for defaults
    profile_cfg = find_and_load_profile(args.config_file, profile_name or "DEFAULT")

    # determine effective region: use only CLI value. Do NOT read `region` from config.toml or any profile file;
    # leave region resolution to the wrapped OCI CLI/SDK (they will use ~/.oci/config or other defaults if not supplied).
    effective_region = args.region

    # determine whether to pass --config-file through to OCI CLI: only pass if args.config_file was provided and is INI
    config_file_to_pass = None
    if args.config_file:
        if is_ini_file(args.config_file):
            config_file_to_pass = args.config_file
        else:
            # If user explicitly provided a non-INI config file (e.g., TOML), we won't pass it to OCI CLI (it won't understand TOML)
            LOG.debug("Provided --config-file %s does not look like an INI OCI config; not passing it through to OCI CLI.", args.config_file)

    # Build effective commands by appending optional profile-name/region/config, mapping auth/refresh appropriately
    effective_auth_cmd = augment_auth_cmd(args.auth_cmd, profile_name, effective_region, config_file_to_pass)
    effective_refresh_cmd = augment_refresh_cmd(args.refresh_cmd, profile_name, effective_region, config_file_to_pass)

    # Initial authentication (once)
    LOG.info("Initial authentication with: %s", effective_auth_cmd)
    rc = run_cmd_passthrough(effective_auth_cmd)
    if rc != 0:
        LOG.error("Initial authentication failed with rc=%s", rc)
        sys.exit(rc)

    # Background refresher thread
    stop_event = threading.Event()

    def handle_signal(signum, _frame):
        LOG.info("Signal %s received; stopping.", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    th = threading.Thread(
        target=refresher_loop,
        args=(interval_seconds, effective_refresh_cmd, stop_event),
        daemon=True,
    )
    th.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()
    th.join(timeout=5)
    LOG.info("Exiting.")


if __name__ == "__main__":
    main()
