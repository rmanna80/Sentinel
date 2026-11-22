"""Command-line entry point: ``sentinel-server``."""

from __future__ import annotations

import argparse
import getpass
import logging
import re
import sys

from sqlalchemy import func, select

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


USERNAME_RULE = re.compile(r"^[A-Za-z0-9_.\-]{3,64}$")  # the same rule first-run setup applies


def cmd_list_users(args: argparse.Namespace) -> int:
    from .db import init_engine, session_scope
    from .models import User

    init_engine(_settings(args).db_url)
    with session_scope() as db:
        names = list(db.execute(select(User.username).order_by(User.id)).scalars())
    print("\n".join(names) if names else "No users yet; open the dashboard to run first-time setup.")
    return 0


def cmd_rename_user(args: argparse.Namespace) -> int:
    """Change a username from this machine. The password, sessions and stored data are untouched.

    Earlier audit entries keep the old name: the audit log is a sealed history of who did what under the
    name they had at the time, so it is appended to, never rewritten.
    """
    from . import audit
    from .db import init_engine, session_scope
    from .models import User

    if not USERNAME_RULE.match(args.new_username):
        print("A username is 3 to 64 characters: letters, digits, dot, dash or underscore.", file=sys.stderr)
        return 2
    init_engine(_settings(args).db_url)
    with session_scope() as db:
        user = db.execute(select(User).where(User.username == args.username)).scalar_one_or_none()
        if user is None:
            print("No such user (see `sentinel-server list-users`)", file=sys.stderr)
            return 2
        if args.new_username == args.username:
            print("That is already the username.")
            return 0
        clash = db.execute(select(User).where(func.lower(User.username) == args.new_username.lower(),
                                              User.id != user.id)).scalar_one_or_none()
        if clash is not None:
            print("That username is already taken", file=sys.stderr)
            return 2
        user.username = args.new_username
        audit.record(db, "local-cli", "auth.username_changed", "user", user.id,
                     {"from": args.username, "to": args.new_username})
    print(f"Username changed to {args.new_username}. The password is unchanged.")
    return 0


def cmd_eval_assistant(args: argparse.Namespace) -> int:
    """Ask the local model the evaluation questions and grade the answers against this database."""
    import json
    from dataclasses import replace

    from .db import init_engine, session_scope
    from .phases.assistant import OllamaUnavailable, ollama_config, ollama_models, run_conversation
    from .services.assistant_eval import CaseResult, build_cases, run_eval

    engine = init_engine(_settings(args).db_url)
    with session_scope() as db:
        cfg = ollama_config(db)
        cases = build_cases(db)
    if args.model:
        cfg = replace(cfg, model=args.model)
    if cfg.url_error or not cfg.model:
        print("Set the Ollama URL and model under Settings > Integrations first (the URL must be local).",
              file=sys.stderr)
        return 2
    try:
        installed = ollama_models(cfg)
    except OllamaUnavailable as exc:
        print(f"{exc}. Start Ollama and try again.", file=sys.stderr)
        return 2
    if cfg.model not in installed and f"{cfg.model}:latest" not in installed:
        print(f"The model '{cfg.model}' is not installed; run `ollama pull {cfg.model}`.", file=sys.stderr)
        return 2
    if args.only:
        cases = [c for c in cases if c.group == args.only or c.name.startswith(args.only)]
    cases = cases[: args.limit] if args.limit else cases

    def ask(question: str) -> tuple[str, int, list[str]]:
        result = run_conversation(engine, cfg, [], question)
        return result.answer, result.rounds, result.tools_used

    def show(result: CaseResult) -> None:
        mark = "pass" if result.passed else "FAIL"
        print(f"  [{mark}] {result.name:<34} {result.seconds:>6.1f}s" + ("" if result.passed else f"  {result.reason}"))

    print(f"Assistant evaluation: {len(cases)} questions for {cfg.model} at {cfg.url}\n")
    report = run_eval(engine, cfg.model, cases, ask, on_result=show)
    summary = report.as_dict()
    print(f"\n  passed {summary['passed']} of {summary['cases']} ({summary['pass_rate']:.0%})")
    for group, counts in summary["by_group"].items():
        print(f"    {group:<10} {counts['passed']}/{counts['total']}")
    print(f"  citations of records that do not exist: {summary['invalid_citations']}")
    print(f"  misstated severity or status: {summary['claim_mismatches']}")
    if summary["median_seconds"] is not None:
        print(f"  time per answer: median {summary['median_seconds']}s, slowest {summary['slowest_seconds']}s")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"\nWrote every question and answer to {args.json}")
    return 0 if summary["passed"] == summary["cases"] else 1


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
    n = sub.add_parser("rename-user", help="change a username from this machine")
    n.add_argument("username")
    n.add_argument("new_username")
    sub.add_parser("list-users", help="show the usernames that can sign in")
    a = sub.add_parser("eval-assistant", help="grade the local AI model against questions with known answers")
    a.add_argument("--model", help="evaluate this installed model instead of the configured one")
    a.add_argument("--only", help="run one group (facts, citations, scope, injection, explain) or name prefix")
    a.add_argument("--limit", type=int, help="ask only the first N questions")
    a.add_argument("--json", metavar="FILE", help="write every question, answer and verdict as JSON")
    sub.add_parser("verify-audit", help="check the audit log hash chain")
    e = sub.add_parser("create-enrollment-code", help="print a one-time agent enrollment code")
    e.add_argument("--port", type=int)
    e.add_argument("--mode", choices=[m.value for m in Mode if m is not Mode.TEST])
    b = sub.add_parser("backup", help="write a consistent copy of the database")
    b.add_argument("--out", required=True)
    args = p.parse_args(argv)
    return {"serve": cmd_serve, "migrate": cmd_migrate, "reset-password": cmd_reset_password,
            "rename-user": cmd_rename_user, "list-users": cmd_list_users,
            "eval-assistant": cmd_eval_assistant,
            "verify-audit": cmd_verify_audit, "create-enrollment-code": cmd_enrollment_code,
            "backup": cmd_backup}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
