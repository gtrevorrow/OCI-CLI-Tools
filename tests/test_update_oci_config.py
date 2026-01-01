import os
from pathlib import Path

import oci_upst_session_manager as mgr


# Test intent: when the target section exists, missing keys should be inserted
# inside that section (before the next section header), not at the end of the file.
def test_update_oci_config_inserts_within_existing_section(tmp_path: Path):
    cfg = tmp_path / "oci.cfg"
    cfg.write_text("""[foo]
region=us-ashburn-1
[bar]
region=us-phoenix-1
""", encoding="utf-8")

    mgr.update_oci_config(str(cfg), "foo", "us-ashburn-1", "/tmp/key.pem", "/tmp/token")

    lines = cfg.read_text(encoding="utf-8").splitlines()
    foo_idx = lines.index("[foo]")
    bar_idx = lines.index("[bar]")
    # Collect lines in the foo section (exclusive of next header)
    foo_section = lines[foo_idx + 1 : bar_idx]
    assert "key_file=/tmp/key.pem" in foo_section
    assert "security_token_file=/tmp/token" in foo_section
    # Ensure bar section remains intact and comes after inserted keys
    assert lines[bar_idx] == "[bar]"


# Test intent: when the target section does not exist, it should be created
# with key_file and security_token_file (region optional if None).
def test_update_oci_config_creates_section_when_missing(tmp_path: Path):
    cfg = tmp_path / "oci.cfg"
    cfg.write_text("""[common]
region=us-ashburn-1
""", encoding="utf-8")

    mgr.update_oci_config(str(cfg), "newprof", None, "/tmp/key.pem", "/tmp/token")

    content = cfg.read_text(encoding="utf-8").splitlines()
    assert "[newprof]" in content
    np_idx = content.index("[newprof]")
    newprof_section = content[np_idx + 1 :]
    assert "key_file=/tmp/key.pem" in newprof_section
    assert "security_token_file=/tmp/token" in newprof_section
    # region was None, so it should not be written
    assert not any(line.startswith("region=") for line in newprof_section)
