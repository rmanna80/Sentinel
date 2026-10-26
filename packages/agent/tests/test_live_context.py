"""The live context's file access and the fixed tool locations (no Windows needed: OS calls are monkeypatched)."""

import pytest
from sentinel_agent import context, executables
from sentinel_agent.config import MemoryState
from sentinel_agent.context import LiveContext, Recorder
from sentinel_agent.safe_commands import SafeCommandRunner
from sentinel_agent.testing import FixtureContext, linux_host

# --------------------------------------------------------------------------- list_dir never turns an error into []


def _live(tmp_path, recorder=None):
    return LiveContext(linux_host(), SafeCommandRunner([]), MemoryState(), {"project_paths": [str(tmp_path)]},
                       lambda: False, recorder=recorder)


def test_live_list_dir_raises_instead_of_returning_empty(tmp_path, monkeypatch):
    (tmp_path / "empty").mkdir()
    (tmp_path / "file.txt").write_text("x")
    ctx = _live(tmp_path)
    assert ctx.list_dir(str(tmp_path / "empty")) == []
    with pytest.raises(FileNotFoundError):
        ctx.list_dir(str(tmp_path / "missing"))
    with pytest.raises(NotADirectoryError):
        ctx.list_dir(str(tmp_path / "file.txt"))

    recorder = Recorder()

    def denied(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(context.os, "listdir", denied)
    with pytest.raises(PermissionError):
        _live(tmp_path, recorder).list_dir(str(tmp_path / "empty"))
    # Recorded as unreadable, so a replayed fixture takes the same path.
    assert recorder.files == {str(tmp_path / "empty") + "::<listdir>": None}


def test_fixture_list_dir_and_read_text_mirror_the_live_errors():
    ctx = FixtureContext(linux_host(), {"files": {"/etc/a::<listdir>": "x\ny", "/etc/b::<listdir>": None,
                                                  "/etc/c": None}})
    assert ctx.list_dir("/etc/a") == ["x", "y"]
    with pytest.raises(FileNotFoundError):
        ctx.list_dir("/etc/missing")
    with pytest.raises(PermissionError):
        ctx.list_dir("/etc/b")
    with pytest.raises(PermissionError):
        ctx.read_text("/etc/c")
    assert ctx.path_exists("/etc/b") and ctx.path_exists("/etc/c")


# --------------------------------------------------------------------------- Windows folders come from the OS


@pytest.fixture
def fake_windows(tmp_path, monkeypatch):
    """A Windows layout under tmp_path, an attacker's copy of it, and environment variables pointing at the copy."""
    real, evil = tmp_path / "real", tmp_path / "attacker"
    folders = {
        "windows": real / "Windows",
        executables.FOLDERID_PROGRAM_FILES: real / "Program Files",
        executables.FOLDERID_PROGRAM_FILES_X86: real / "Program Files (x86)",
        executables.FOLDERID_PROGRAM_DATA: real / "ProgramData",
        executables.FOLDERID_STARTUP: real / "Users" / "Ryan" / "Start Menu" / "Programs" / "Startup",
    }
    for base in (real / "Windows", evil):
        for rel in ("System32/netsh.exe", "System32/WindowsPowerShell/v1.0/powershell.exe"):
            (base / rel).parent.mkdir(parents=True, exist_ok=True)
            (base / rel).write_text("")
    for base in (real / "Program Files", evil):
        (base / "Nmap").mkdir(parents=True, exist_ok=True)
        (base / "Nmap" / "nmap.exe").write_text("")
    for name in ("SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "APPDATA"):
        monkeypatch.setenv(name, str(evil))
    monkeypatch.setattr(executables.sys, "platform", "win32")
    monkeypatch.setattr(executables, "_system_windows_directory", lambda: str(folders["windows"]))
    monkeypatch.setattr(executables, "_known_folder_path", lambda folder_id: str(folders[folder_id]))
    return folders, evil


def test_tool_paths_ignore_overridden_environment(fake_windows):
    folders, evil = fake_windows
    assert executables.resolve("netsh") == str(folders["windows"] / "System32" / "netsh.exe")
    assert executables.resolve("powershell") == str(
        folders["windows"] / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    assert executables.resolve("nmap") == str(folders[executables.FOLDERID_PROGRAM_FILES] / "Nmap" / "nmap.exe")
    for name in ("netsh", "powershell", "nmap", "clamscan", "wevtutil"):
        assert not any(str(evil) in str(c) for c in executables._windows_candidates(name))


def test_tool_lookup_fails_closed_when_the_os_call_fails(fake_windows, monkeypatch):
    def fail():
        raise OSError("GetSystemWindowsDirectoryW failed")

    monkeypatch.setattr(executables, "_system_windows_directory", fail)
    with pytest.raises(executables.ExecutableNotFound):
        executables.resolve("netsh")  # never falls back to %SystemRoot%


def test_read_roots_ignore_overridden_environment(fake_windows):
    folders, evil = fake_windows
    roots = context._windows_read_roots()
    assert roots == [
        str(folders["windows"] / "System32" / "drivers" / "etc"),
        str(folders[executables.FOLDERID_PROGRAM_DATA] / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"),
        str(folders[executables.FOLDERID_STARTUP]),
    ]
    assert not any(str(evil) in r for r in roots)


def test_linux_resolution_does_not_touch_windows_apis(monkeypatch):
    def boom(*_args):
        raise AssertionError("Windows API called on Linux")

    monkeypatch.setattr(executables.sys, "platform", "linux")  # also meaningful when the suite runs on Windows
    monkeypatch.setattr(executables, "_system_windows_directory", boom)
    monkeypatch.setattr(executables, "_known_folder_path", boom)
    executables.is_available("ss")
    with pytest.raises(executables.ExecutableNotFound):
        executables.resolve("powershell")  # not an allowed Linux tool
