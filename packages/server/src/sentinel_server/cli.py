"""Command-line entry point: ``sentinel-server``."""

from __future__ import annotations

import argparse
import getpass
import logging
import sys

from sqlalchemy import select

from .config import Mode, Settings, get_settings


def _settings(args: argparse.Namespace) -> Settings:
    settings = get_settings()
    overrides = {}
    if getattr(args, "mode", None):
        overrides["mode"] = Mode(args.mode)
    if getattr(args, "port", None):
        overrides["port"] = args.port
    if overrides:
        settings = settings.model_copy(update=overrides)
        get_settings.cache_clear()
        import os

        for k, v in overrides.items():
            os.environ[f"SENTINEL_{k.upper()}"] = str(v.value if hasattr(v, "value") else v)
    return settings


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = _settings(args)
    if settings.host not in ("127.0.0.1", "localhost", "::1"):
        print("Refusing to listen on a non-loopback address. Sentinel serves this machine only.", file=sys.stderr)
        return 2
    from .app import create_app

    app = create_app(settings)
    print(f"Sentinel {settings.mode.value} mode on http://127.0.0.1:{settings.port}  (data: {settings.data_dir})")
    uvicorn.run(app, host="127.0.0.1", port=settings.port, log_level="info", proxy_headers=False,
                server_header=False)
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    from .migrate import upgrade_to_head

    settings = _settings(args)
    settings.ensure_dirs()
    upgrade_to_head(settings.db_url)
    print("Database is up to date.")
    return 0


def cmd_reset_password(args: argparse.Namespace) -> int:
    from . import audit
    from .db import init_engine, session_scope
    from .models import User, UserSession
    from .security import hash_password, password_problems

    settings = _settings(args)
    init_engine(settings.db_url)
    password = getpass.getpass("New password: ")
    problems = password_problems(password, args.username)
    if problems:
        print(" ".join(problems), file=sys.stderr)
        return 2
    with session_scope() as db:
        user = db.execute(select(User).where(User.username == args.username)).scalar_one_or_none()
        if user is None:
            print("No such user", file=sys.stderr)
            return 2
        user.password_hash = hash_password(password)
        user.failed_logins = 0
        user.locked_until = None
        for s in db.execute(select(UserSession).where(UserSession.user_id == user.id)).scalars():
            db.delete(s)
        audit.record(db, "local-cli", "auth.password_reset", "user", user.id)
    print("Password reset; all sessions signed out.")
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    from . import audit
    from .db import init_engine, session_scope

    settings = _settings(args)
    init_engine(settings.db_url)
    with session_scope() as db:
        intact, bad = audit.verify_chain(db)
        seq, digest = audit.head(db)
    print("Audit chain intact." if intact else f"Audit chain broken at entry {bad}.")
    print(f"Latest entry: #{seq}  {digest}  (note this down to detect later truncation)")
    return 0 if intact else 1


def cmd_enrollment_code(args: argparse.Namespace) -> int:
    """Create a one-time enrollment code from this machine (for scripted setups and demo mode)."""
    from datetime import timedelta

    from . import audit
    from .db import init_engine, session_scope
    from .migrate import upgrade_to_head
    from .models import EnrollmentCode, now
    from .security import hash_token, new_enrollment_code, normalize_code

    settings = _settings(args)
    settings.ensure_dirs()
    upgrade_to_head(settings.db_url)
    init_engine(settings.db_url)
    code = new_enrollment_code()
    with session_scope() as db:
        db.add(EnrollmentCode(code_hash=hash_token(normalize_code(code)),
                              expires_at=now() + timedelta(minutes=settings.enrollment_code_minutes)))
        audit.record(db, "local-cli", "device.enrollment_code_created")
    print(code)
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    """Consistent online backup of the SQLite database (safe while the server runs)."""
    import sqlite3
    from pathlib import Path

    settings = _settings(args)
    if not settings.db_url.startswith("sqlite:///"):
        print("backup supports the default SQLite database only; use your database's own tools", file=sys.stderr)
        return 2
    src = Path(settings.db_url.removeprefix("sqlite:///"))
    out = Path(args.out).resolve()
    if out.exists():
        print(f"{out} already exists; choose a new file name", file=sys.stderr)
        return 2
    with sqlite3.connect(src) as source, sqlite3.connect(out) as target:
        source.backup(target)
    print(f"Backed up {src} to {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("alembic").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    p = argparse.ArgumentParser(prog="sentinel-server")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the API and dashboard on 127.0.0.1")
    s.add_argument("--port", type=int)
    s.add_argument("--mode", choices=[m.value for m in Mode if m is not Mode.TEST])
    sub.add_parser("migrate", help="create or upgrade the database")
    r = sub.add_parser("reset-password", help="reset a user's password from this machine")
    r.add_argument("username")
    sub.add_parser("verify-audit", help="check the audit log hash chain")
    e = sub.add_parser("create-enrollment-code", help="print a one-time agent enrollment code")
    e.add_argument("--port", type=int)
    e.add_argument("--mode", choices=[m.value for m in Mode if m is not Mode.TEST])
    b = sub.add_parser("backup", help="write a consistent copy of the database")
    b.add_argument("--out", required=True)
    args = p.parse_args(argv)
    return {"serve": cmd_serve, "migrate": cmd_migrate, "reset-password": cmd_reset_password,
            "verify-audit": cmd_verify_audit, "create-enrollment-code": cmd_enrollment_code,
            "backup": cmd_backup}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
