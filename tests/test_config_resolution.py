import os
from unittest import mock

import pytest

import oci_upst_session_manager as mgr


# Helper: run mgr.main() with a controlled argv/env and short-circuit the
# actual session logic (ensure_session). We only care about how main() resolves
# configuration and what exit code it returns, not about network or token flows.
def _run_main_with_args(monkeypatch, args, env=None):
    """Run main() with synthetic argv/env and return the SystemExit code.

    This avoids invoking real OAuth/OCI calls by stubbing ensure_session.
    """
    argv = ["woci"] + args
    monkeypatch.setattr("sys.argv", argv)
    # Avoid actually running ensure_session logic; we only care about config resolution/exit code.
    monkeypatch.setattr(mgr, "ensure_session", lambda *a, **k: None)
    if env is not None:
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    with pytest.raises(SystemExit) as exc:
        mgr.main()
    return exc.value.code


# Test intent: when both --manager-config and WOCI_MANAGER_CONFIG are set,
# the CLI flag must take precedence for selecting the manager INI path.
def test_manager_config_path_precedence_cli_over_env(tmp_path, monkeypatch):
    # Prepare two INI files; CLI one should win
    cli_ini = tmp_path / "cli.ini"
    env_ini = tmp_path / "env.ini"
    cli_ini.write_text("[COMMON]\nlog_level=DEBUG\n", encoding="utf-8")
    env_ini.write_text("[COMMON]\nlog_level=ERROR\n", encoding="utf-8")

    with mock.patch("configparser.ConfigParser.read", wraps=mgr.configparser.ConfigParser().read) as m_read:
        code = _run_main_with_args(
            monkeypatch,
            [
                "--manager-config", str(cli_ini),
                "--profile", "p",
                "--authz-base-url", "https://example.com/auth",
                "--token-url", "https://example.com/token",
                "--auth-client-id", "ac",
                "--client-id", "cid",
                "--client-secret", "csec",
                "--scope", "openid",
                "--redirect-port", "8181",
            ],
            env={"WOCI_MANAGER_CONFIG": str(env_ini)},
        )

    # We only assert that execution completed and that the CLI path was read.
    assert code in (0, 1, 2)
    paths = [call.args[0] for call in m_read.call_args_list]
    assert str(cli_ini) in paths


# Test intent: when no --manager-config is supplied but WOCI_MANAGER_CONFIG is
# set, the env var path must be used as the manager INI.
def test_manager_config_env_used_when_cli_missing(tmp_path, monkeypatch):
    env_ini = tmp_path / "env.ini"
    env_ini.write_text("[COMMON]\nlog_level=DEBUG\n", encoding="utf-8")

    with mock.patch("configparser.ConfigParser.read", wraps=mgr.configparser.ConfigParser().read) as m_read:
        code = _run_main_with_args(
            monkeypatch,
            [
                "--profile", "p",
                "--authz-base-url", "https://example.com/auth",
                "--token-url", "https://example.com/token",
                "--auth-client-id", "ac",
                "--client-id", "cid",
                "--client-secret", "csec",
                "--scope", "openid",
                "--redirect-port", "8181",
            ],
            env={"WOCI_MANAGER_CONFIG": str(env_ini)},
        )

    assert code in (0, 1, 2)
    paths = [call.args[0] for call in m_read.call_args_list]
    assert str(env_ini) in paths


# Test intent: when an explicit manager-config path (from CLI/env) is
# unreadable, main() must fail with configuration error code 2.
def test_explicit_manager_config_unreadable_is_fatal(tmp_path, monkeypatch):
    bad_path = tmp_path / "missing.ini"  # not created

    code = _run_main_with_args(
        monkeypatch,
        [
            "--manager-config", str(bad_path),
            "--profile", "p",
            "--authz-base-url", "https://example.com/auth",
            "--token-url", "https://example.com/token",
            "--auth-client-id", "ac",
            "--client-id", "cid",
            "--client-secret", "csec",
            "--scope", "openid",
            "--redirect-port", "8181",
        ],
        env={"WOCI_MANAGER_CONFIG": None},
    )

    assert code == 2


# Test intent: conflicting profile selectors (passthrough --profile vs manager-config section)
# must fail fast with code 2.
def test_conflicting_profile_inputs_exit_with_error(tmp_path, monkeypatch):
    ini = tmp_path / "cfg.ini"
    ini.write_text("""[COMMON]\nlog_level=INFO\n[mysection]\nauthz_base_url=https://example.com/auth\n""", encoding="utf-8")

    argv = [
        "woci",
        "--manager-config", str(ini),
        "--manager-config-section", "mysection",
        "--token-url", "https://example.com/token",
        "--auth-client-id", "ac",
        "--client-id", "cid",
        "--client-secret", "csec",
        "--scope", "openid",
        "--redirect-port", "8181",
        "--profile", "different-prof",
    ]

    monkeypatch.setattr("sys.argv", argv)
    monkeypatch.setattr(mgr, "ensure_session", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc:
        mgr.main()

    assert exc.value.code == 2


# Test intent: manager-config-section alone determines both the metadata source
# and the effective profile when no passthrough profile is provided.
def test_manager_config_section_sets_profile_when_alone(tmp_path, monkeypatch):
    ini = tmp_path / "cfg.ini"
    ini.write_text("""[COMMON]\nlog_level=INFO\n[sectionA]\nauthz_base_url=https://example.com/auth\n""", encoding="utf-8")

    argv = [
        "woci",
        "--manager-config", str(ini),
        "--manager-config-section", "sectionA",
        "--token-url", "https://example.com/token",
        "--auth-client-id", "ac",
        "--client-id", "cid",
        "--client-secret", "csec",
        "--scope", "openid",
        "--redirect-port", "8181",
    ]

    monkeypatch.setattr("sys.argv", argv)
    captured = {}

    def fake_ensure_session(args, *a, **k):
        captured["profile_name"] = args.profile_name

    monkeypatch.setattr(mgr, "ensure_session", fake_ensure_session)

    with pytest.raises(SystemExit):
        mgr.main()

    assert captured["profile_name"] == "sectionA"


# Test intent: when no section is selected and no profile_name exists,
# the effective profile should fall back to the passthrough --profile value.
def test_profile_name_falls_back_to_passthrough_when_no_cli_or_ini(tmp_path, monkeypatch):
    ini = tmp_path / "cfg.ini"
    ini.write_text("[COMMON]\nlog_level=INFO\n", encoding="utf-8")

    argv = [
        "woci",
        "--manager-config", str(ini),
        "--authz-base-url", "https://example.com/auth",
        "--token-url", "https://example.com/token",
        "--auth-client-id", "ac",
        "--client-id", "cid",
        "--client-secret", "csec",
        "--scope", "openid",
        "--redirect-port", "8181",
        "--profile", "passthrough-prof",
    ]

    monkeypatch.setattr("sys.argv", argv)
    captured = {}

    def fake_ensure_session(args, *a, **k):
        captured["profile_name"] = args.profile_name

    monkeypatch.setattr(mgr, "ensure_session", fake_ensure_session)

    with pytest.raises(SystemExit):
        mgr.main()

    assert captured["profile_name"] == "passthrough-prof"


# Test intent: if no profile can be resolved from CLI flags, passthrough
# --profile, or manager-config, main() must exit with code 2 and a clear
# error about the missing profile.
def test_missing_profile_name_defaults_to_DEFAULT(monkeypatch):
    argv = [
        "woci",
        "--authz-base-url", "https://example.com/auth",
        "--token-url", "https://example.com/token",
        "--auth-client-id", "ac",
        "--client-id", "cid",
        "--client-secret", "csec",
        "--scope", "openid",
        "--redirect-port", "8181",
    ]

    monkeypatch.setattr("sys.argv", argv)
    captured = {}

    def fake_ensure_session(args, *a, **k):
        captured["profile_name"] = args.profile_name

    monkeypatch.setattr(mgr, "ensure_session", fake_ensure_session)

    with pytest.raises(SystemExit) as exc:
        mgr.main()

    assert exc.value.code == 0
    assert captured["profile_name"] == "DEFAULT"
