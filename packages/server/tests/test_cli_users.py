"""The local account commands: list-users and rename-user."""

from __future__ import annotations

from sentinel_server import cli

from .conftest import PASSWORD


def test_rename_user_keeps_password_and_audit_chain(browser, anon, capsys):
    assert cli.main(["list-users"]) == 0
    assert capsys.readouterr().out.strip() == "ryan"

    assert cli.main(["rename-user", "ryan", "ryan.manna"]) == 0
    assert "ryan.manna" in capsys.readouterr().out
    assert browser.get("/api/auth/state").json()["username"] == "ryan.manna"  # the open session survives

    browser.post("/api/auth/logout")
    assert anon.post("/api/auth/login", json={"username": "ryan", "password": PASSWORD}).status_code == 401
    assert anon.post("/api/auth/login", json={"username": "ryan.manna", "password": PASSWORD}).status_code == 200

    assert cli.main(["verify-audit"]) == 0  # the rename is appended to the chain, not rewritten into it
    assert cli.main(["list-users"]) == 0
    assert capsys.readouterr().out.strip().endswith("ryan.manna")


def test_rename_user_refuses_bad_input(browser, capsys):
    assert cli.main(["rename-user", "nobody", "someone"]) == 2
    assert cli.main(["rename-user", "ryan", "no"]) == 2  # too short
    assert cli.main(["rename-user", "ryan", "has space"]) == 2
    assert cli.main(["rename-user", "ryan", "ryan"]) == 0  # no-op
    capsys.readouterr()
    assert cli.main(["list-users"]) == 0
    assert capsys.readouterr().out.strip() == "ryan"


def test_list_users_before_setup(app, anon, capsys):
    assert cli.main(["list-users"]) == 0
    assert "No users yet" in capsys.readouterr().out
