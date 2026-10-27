"""Tests for the dev.secrets check (SecretsScan).

The fixture represents a project tree the way FixtureContext understands it:
  * a directory ``D`` is an entry ``"D::<listdir>"`` whose value is its child names joined by "\\n";
  * a regular file ``F`` is an entry ``"F"`` whose value is the file's text;
  * the walk tells the two apart by calling ``list_dir`` on each child - a directory returns its listing,
    a file raises OSError (FileNotFoundError here) and is treated as a file.
Directories in the skip list (``.git``, ``node_modules``, ...) only need to appear in their parent's listing;
they are never descended into, so they need no ``::<listdir>`` entry. The presence of ``.git`` in a folder's
listing is what marks everything under it as "in a git repo" for the committed_env_file rule.
"""

import json

import pytest
from sentinel_agent.checks.common import secrets_scan as ss
from sentinel_agent.testing import FixtureContext, linux_host
from sentinel_core.checks import SkipCheck
from sentinel_core.models import Confidence, FindingKind, Severity

PROJECT = "/home/pi/proj"

# Distinctive, obviously-fake secret values. The tests assert none of these ever reach the output.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 base64 chars, the canonical AWS example value
SLACK = "xoxb-123456789012-abcdefABCDEF"
GITHUB = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
GOOGLE = "AIza" + "a" * 35
PW = "S3cr3t-Pa55word-99"
PRIVKEY_MARKER = "FAKEKEYMATERIAL1234567890"

ENV_REAL = f"AWS_ACCESS_KEY_ID={AWS_KEY}\nDB_PASSWORD={PW}\nSLACK_TOKEN={SLACK}\n"
ENV_EXAMPLE = "AWS_ACCESS_KEY_ID=your-key-here\nDB_PASSWORD=changeme\n"
ID_RSA = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{PRIVKEY_MARKER}b3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----\n"
SETTINGS = "DEBUG = True\nSECRET_KEY = 'changeme'\n"
NOTES_MD = f"Access via {GITHUB}\npassword = {PW}\n"
APP_JS = f'const googleKey = "{GOOGLE}";\n'
CONFIG_YAML = f"aws_secret_access_key: {AWS_SECRET}\n"

TREE = {
    f"{PROJECT}::<listdir>": ".git\n.env\n.env.example\nid_rsa\nsettings.py\nnotes.md\nsrc\nnode_modules",
    f"{PROJECT}/.env": ENV_REAL,
    f"{PROJECT}/.env.example": ENV_EXAMPLE,
    f"{PROJECT}/id_rsa": ID_RSA,
    f"{PROJECT}/settings.py": SETTINGS,
    f"{PROJECT}/notes.md": NOTES_MD,
    f"{PROJECT}/src::<listdir>": "app.js\nconfig.yaml",
    f"{PROJECT}/src/app.js": APP_JS,
    f"{PROJECT}/src/config.yaml": CONFIG_YAML,
}


def _run(files=None, project_paths=(PROJECT,)):
    ctx = FixtureContext(linux_host(), {"files": dict(files if files is not None else TREE)},
                         config={"project_paths": list(project_paths)})
    return ss.SecretsScan().run(ctx)


def _by_rule(out):
    return {f.rule_id.split(".")[-1] for f in out.findings}


def _matches(out):
    return out.evidence[0].content["matches"]


# --------------------------------------------------------------------------- sanity: crafted values match


def test_crafted_values_match_their_patterns():
    assert ss._AWS_ACCESS_KEY.search(AWS_KEY) and ss._AWS_SECRET_KEY.search(f"aws_secret_access_key: {AWS_SECRET}")
    assert ss._SLACK_TOKEN.search(SLACK) and ss._GITHUB_TOKEN.search(GITHUB) and ss._GOOGLE_API_KEY.search(GOOGLE)
    assert ss._BEGIN_PRIVATE_KEY.search("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert ss._BEGIN_PRIVATE_KEY.search("-----BEGIN PRIVATE KEY-----")  # empty variant keeps a single space


# --------------------------------------------------------------------------- the required cases


def test_private_key_flagged_high():
    out = _run()
    pk = [f for f in out.findings if f.rule_id == "dev.secrets.private_key"]
    assert len(pk) == 1
    f = pk[0]
    assert (f.severity, f.kind, f.confidence) == (Severity.HIGH, FindingKind.VERIFIED, Confidence.HIGH)
    assert f.subject_key == f"{PROJECT}:id_rsa:private_key:1"
    # the dedicated key-file rule fires as well, also HIGH
    cpk = [f for f in out.findings if f.rule_id == "dev.secrets.committed_private_key_file"]
    assert len(cpk) == 1 and cpk[0].severity is Severity.HIGH


def test_aws_access_key_flagged():
    out = _run()
    aws = [f for f in out.findings if f.rule_id == "dev.secrets.aws_access_key"]
    assert len(aws) == 1 and aws[0].severity is Severity.HIGH
    assert aws[0].subject_key == f"{PROJECT}:.env:aws_access_key:1"


def test_env_committed_but_example_is_not():
    out = _run()
    env_findings = [f for f in out.findings if f.rule_id == "dev.secrets.committed_env_file"]
    assert {f.subject_key for f in env_findings} == {f"{PROJECT}:.env:committed_env_file:0"}
    # the .env.example template is never flagged, by any rule
    assert not any(m["file"] == ".env.example" for m in _matches(out))
    # the KEY= line count is recorded as a number, not the values
    env_match = next(m for m in _matches(out) if m["rule"] == "committed_env_file")
    assert env_match["keys"] == 3


def test_placeholder_values_not_flagged():
    out = _run()
    generic = [m for m in _matches(out) if m["rule"] == "generic_secret_assignment"]
    generic_files = {m["file"] for m in generic}
    # changeme / your-key-here placeholders in .env.example and settings.py are excluded
    assert ".env.example" not in generic_files
    assert "settings.py" not in generic_files
    # settings.py still trips debug_enabled (DEBUG = True) and nothing else
    settings_rules = {m["rule"] for m in _matches(out) if m["file"] == "settings.py"}
    assert settings_rules == {"debug_enabled"}


def test_breadth_of_rules_and_recursion():
    out = _run()
    rules = _by_rule(out)
    # recursion into src/ reaches app.js and config.yaml
    assert {"aws_access_key", "slack_token", "github_token", "google_api_key", "aws_secret_key",
            "generic_secret_assignment", "committed_env_file", "debug_enabled", "private_key",
            "committed_private_key_file"} <= rules
    # .md files run only the high-confidence rules: the github token is caught, the password line is not
    md_rules = {m["rule"] for m in _matches(out) if m["file"] == "notes.md"}
    assert md_rules == {"github_token"}


def test_no_project_folders_skips():
    with pytest.raises(SkipCheck) as exc:
        ss.SecretsScan().run(FixtureContext(linux_host(), {}))
    assert str(exc.value) == ss.NO_PROJECTS
    with pytest.raises(SkipCheck):
        ss.SecretsScan().run(FixtureContext(linux_host(), {}, config={"project_paths": []}))


def test_unreadable_top_folder_skips_naming_it():
    files = {f"{PROJECT}::<listdir>": None}  # exists but cannot be listed
    with pytest.raises(SkipCheck, match=r"/home/pi/proj could not be read"):
        _run(files=files)


def test_unreadable_subdir_is_skipped_not_fatal():
    files = dict(TREE)
    files[f"{PROJECT}::<listdir>"] = ".env\nsecretdir"
    files[f"{PROJECT}/secretdir::<listdir>"] = None  # permission denied on a sub-folder
    out = _run(files=files)  # must not raise
    assert out.evidence[0].content["files_read"] >= 1


def test_secret_values_never_appear_in_output():
    out = _run()
    dumped = json.dumps(out.model_dump(mode="json"))
    for secret in (AWS_KEY, AWS_SECRET, SLACK, GITHUB, GOOGLE, PW, PRIVKEY_MARKER):
        assert secret not in dumped
