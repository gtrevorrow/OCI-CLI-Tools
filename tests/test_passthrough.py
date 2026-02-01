from unittest import mock

from oci_upst_session_manager import run_cmd_passthrough


# Test intent: ensure run_cmd_passthrough injects an OCI prefix, a default
# --profile (when provided) and --auth security_token when they are missing.
def test_run_cmd_passthrough_injects_profile_and_auth():
    with mock.patch("subprocess.run") as m_run:
        m_run.return_value.returncode = 0

        rc = run_cmd_passthrough(["ce", "cluster", "list"], profile_name="myprof")

        assert rc == 0
        args, kwargs = m_run.call_args
        cmd = args[0]
        assert cmd[0] == "oci"
        assert "--profile" in cmd
        assert "myprof" in cmd
        # default auth should be security_token
        assert "--auth" in cmd
        idx = cmd.index("--auth")
        assert cmd[idx + 1] == "security_token"


# Test intent: verify that if the caller already supplies --profile and
# --auth flags, run_cmd_passthrough does not inject duplicates or override
# the chosen auth mechanism.
def test_run_cmd_passthrough_respects_existing_profile_and_auth():
    with mock.patch("subprocess.run") as m_run:
        m_run.return_value.returncode = 0

        rc = run_cmd_passthrough([
            "--profile", "cli-prof",
            "ce", "cluster", "list",
            "--auth", "api_key",
        ], profile_name="ignored-prof")

        assert rc == 0
        args, kwargs = m_run.call_args
        cmd = args[0]
        # Should not inject another --profile or override auth
        assert cmd.count("--profile") == 1
        assert cmd.count("--auth") == 1
        idx = cmd.index("--auth")
        assert cmd[idx + 1] == "api_key"
