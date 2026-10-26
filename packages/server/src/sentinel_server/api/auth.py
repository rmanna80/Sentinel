"""Setup, login, logout and password changes."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..config import Settings
from ..db import get_db
from ..deps import SESSION_COOKIE, AuthContext, client_ip, current_auth, settings_dep
from ..models import User, UserSession, now
from ..schemas import AuthState, ChangePasswordRequest, LoginRequest, SetupRequest
from ..security import (
    constant_time_equal,
    hash_password,
    hash_token,
    new_token,
    password_problems,
    rate_limiter,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

LOCKOUT_AFTER = 10
LOCKOUT_MINUTES = 15
_DUMMY_HASH = hash_password("timing-equalizer-not-a-real-password")


def _user_count(db: Session) -> int:
    return db.execute(select(func.count(User.id))).scalar_one()


def _start_session(db: Session, user: User, request: Request, response: Response, settings: Settings) -> str:
    token = new_token()
    csrf = new_token()
    t = now()
    db.add(UserSession(user_id=user.id, token_hash=hash_token(token), csrf_token=csrf, created_at=t, last_seen_at=t,
                       expires_at=t + timedelta(hours=settings.session_absolute_hours),
                       user_agent=(request.headers.get("user-agent") or "")[:300]))
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict", secure=request.url.scheme == "https",
        path="/", max_age=settings.session_absolute_hours * 3600,
    )
    return csrf


@router.get("/state", response_model=AuthState)
def auth_state(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> AuthState:
    needs_setup = _user_count(db) == 0
    token = request.cookies.get(SESSION_COOKIE)
    if token and not needs_setup:
        sess = db.execute(select(UserSession).where(UserSession.token_hash == hash_token(token))).scalar_one_or_none()
        t = now()
        if (sess and sess.expires_at > t
                and sess.last_seen_at + timedelta(minutes=settings.session_idle_minutes) > t and sess.user.is_active):
            return AuthState(needs_setup=False, signed_in=True, username=sess.user.username,
                             csrf_token=sess.csrf_token, mode=settings.mode.value)
    return AuthState(needs_setup=needs_setup, signed_in=False, mode=settings.mode.value)


@router.post("/setup", response_model=AuthState)
def setup(body: SetupRequest, request: Request, response: Response, db: Session = Depends(get_db),
          settings: Settings = Depends(settings_dep)) -> AuthState:
    if not rate_limiter.allow("setup", client_ip(request), settings.login_attempts_per_minute, 60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts; wait a minute")
    if _user_count(db) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup has already been completed")
    expected = getattr(request.app.state, "setup_token", None)
    if not expected or not constant_time_equal(body.setup_token.strip(), expected):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Setup token is wrong. It was printed when the server started.")
    problems = password_problems(body.password, body.username)
    if problems:
        raise HTTPException(422, " ".join(problems))
    user = User(username=body.username, password_hash=hash_password(body.password))
    db.add(user)
    db.flush()
    csrf = _start_session(db, user, request, response, settings)
    audit.record(db, f"user:{user.username}", "auth.setup", "user", user.id)
    db.commit()
    request.app.state.setup_token = None
    token_file = settings.data_dir / "setup-token.txt"
    token_file.unlink(missing_ok=True)
    return AuthState(needs_setup=False, signed_in=True, username=user.username, csrf_token=csrf, mode=settings.mode.value)


@router.post("/login", response_model=AuthState)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db),
          settings: Settings = Depends(settings_dep)) -> AuthState:
    ip = client_ip(request)
    if not rate_limiter.allow("login", ip, settings.login_attempts_per_minute, 60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many sign-in attempts; wait a minute")
    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    t = now()
    if user is None:
        verify_password(_DUMMY_HASH, body.password)  # same work either way: no user enumeration by timing
        audit.record(db, "anonymous", "auth.login_failed", "user", None, {"username": body.username[:64], "ip": ip})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong username or password")
    if user.locked_until and user.locked_until > t:
        raise HTTPException(status.HTTP_423_LOCKED, "Account temporarily locked after repeated failures")
    if not user.is_active or not verify_password(user.password_hash, body.password):
        user.failed_logins += 1
        if user.failed_logins >= LOCKOUT_AFTER:
            user.locked_until = t + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_logins = 0
        audit.record(db, "anonymous", "auth.login_failed", "user", user.id, {"ip": ip})
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong username or password")
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = t
    csrf = _start_session(db, user, request, response, settings)
    audit.record(db, f"user:{user.username}", "auth.login", "user", user.id, {"ip": ip})
    db.commit()
    return AuthState(needs_setup=False, signed_in=True, username=user.username, csrf_token=csrf, mode=settings.mode.value)


@router.post("/logout", status_code=204)
def logout(response: Response, auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Response:
    sess = db.get(UserSession, auth.session.id)
    if sess:
        db.delete(sess)
    audit.record(db, auth.actor, "auth.logout", "user", auth.user.id)
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.status_code = 204
    return response


@router.post("/change-password", status_code=204)
def change_password(body: ChangePasswordRequest, auth: AuthContext = Depends(current_auth),
                    db: Session = Depends(get_db)) -> Response:
    user = db.get(User, auth.user.id)
    assert user is not None
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Current password is wrong")
    problems = password_problems(body.new_password, user.username)
    if problems:
        raise HTTPException(422, " ".join(problems))
    user.password_hash = hash_password(body.new_password)
    # sign out every other session
    for s in db.execute(select(UserSession).where(UserSession.user_id == user.id,
                                                  UserSession.id != auth.session.id)).scalars():
        db.delete(s)
    audit.record(db, auth.actor, "auth.password_changed", "user", user.id)
    db.commit()
    return Response(status_code=204)
