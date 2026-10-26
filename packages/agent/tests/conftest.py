import pytest


@pytest.fixture(autouse=True)
def _agent_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_AGENT_HOME", str(tmp_path / "agent-home"))
