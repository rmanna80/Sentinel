"""FastAPI dependencies: settings, database, users, CSRF and agent devices."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db import get_db
from .models import Device, User, UserSession, now
from .security import constant_time_equal, hash_token

SESSION_COOKIE = "sentinel_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class AuthContext:
    user: User
    session: UserSession

    @property
    def actor(self) -> str:
        return f"user:{self.user.username}"


def settings_dep() -> Settings:
    return get_settings()


def current_auth(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(settings_dep)) -> AuthContext:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
    sess = db.execute(select(UserSession).where(UserSession.token_hash == hash_token(token))).scalar_one_or_none()
    t = now()
    if sess is None or sess.expires_at <= t or sess.last_seen_at + timedelta(minutes=settings.session_idle_minutes) <= t:
        if sess is not None:
            db.delete(sess)
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
    if not sess.user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account disabled")
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not constant_time_equal(sent, sess.csrf_token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing or invalid CSRF token")
    if (t - sess.last_seen_at).total_seconds() > 60:
        sess.last_seen_at = t
        db.commit()
    return AuthContext(user=sess.user, session=sess)


def current_device(request: Request, db: Session = Depends(get_db)) -> Device:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Device token required")
    token = header.removeprefix("Bearer ").strip()
    device = db.execute(select(Device).where(Device.token_hash == hash_token(token))).scalar_one_or_none()
    if device is None or not device.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or revoked device token")
    return device


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
