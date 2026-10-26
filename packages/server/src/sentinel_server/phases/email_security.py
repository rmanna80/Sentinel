"""Phase 4: email breach exposure (Have I Been Pwned) and Pwned Passwords range lookups.

Only addresses the user confirms they own (or are authorized to assess) can be monitored. A live
breach check needs the HIBP integration enabled and an API key; without them the check is recorded
as ``unavailable`` with instructions instead of a guess. Recommendations are fixed text keyed on
HIBP data classes; no model writes them.
"""

from __future__ import annotations

import csv
import html
import io
import re
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import AuthContext, client_ip, current_auth
from ..integrations import hibp, http, pwned_passwords
from ..models import DomainCheck, EmailCheck, EmailIdentity, now
from ..security import rate_limiter
from ..services import secrets
from ..services.app_settings import integration_enabled
from ..services.notify import notify

router = APIRouter(prefix="/api/email", tags=["email"])

OWNERSHIP_TEXT = "I own this address or am authorized to assess it"
HIBP_SITE = "https://haveibeenpwned.com"
SUCCESS_STATUSES = ("found", "not_found")
PWNED_RANGE_LIMIT = 30  # requests per minute per client
TIER_NOTE = ("Breach lookups need an HIBP API key. The cheapest tier, Core 1, cost $4.39/month billed annually "
             "as of October 2026 and allows 10 requests per minute; Sentinel spaces lookups at least "
             f"{hibp.MIN_INTERVAL_SECONDS:g} seconds apart. Pwned Passwords is free and needs no key.")
PRIVACY_NOTE = ("A breach lookup sends the full email address to HIBP, because Core tiers have no k-anonymity "
                "search. A password check sends only the first 5 characters of the password's SHA-1 hash, which "
                "your browser computes: neither the password nor its full hash reaches Sentinel's server or HIBP.")
NOT_FOUND_CAVEAT = ("This address is not in any breach loaded into Have I Been Pwned. That does not prove it was "
                    "never exposed: many breaches are never made public or loaded into HIBP.")
DOMAIN_VERIFICATION_METHODS = [
    "Add a TXT record to the domain's DNS (HIBP domain search dashboard)",
    "Receive a verification email at a predefined address on the domain (for example security@ or webmaster@)",
    "Upload a verification file to the website's root",
    "Add a verification meta tag to the website's home page",
]

_EMAIL_RE = re.compile(
    r"^(?=.{3,254}$)(?P<local>[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*)"
    r"@(?P<domain>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9])$"
)
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")


# --------------------------------------------------------------------------- schemas


class IdentityCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    label: str | None = Field(default=None, max_length=128)
    ownership_confirmed: StrictBool = Field(default=False, description=OWNERSHIP_TEXT)  # JSON true only


class IdentityOut(BaseModel):
    id: int
    email: str
    masked_email: str
    label: str | None
    ownership_confirmed: bool
    created_at: datetime
    last_checked_at: datetime | None
    latest_status: str | None
    latest_checked_at: datetime | None
    breach_count: int | None  # from the latest successful check; null if never checked successfully


Priority = Literal["high", "medium", "low", "info"]


class Recommendation(BaseModel):
    id: str
    priority: Priority
    text: str
    data_classes: list[str] = Field(default_factory=list)
    breaches: list[str] = Field(default_factory=list)


class EmailCheckOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    identity_id: int
    checked_at: datetime
    status: str
    breach_count: int
    breaches: list[dict[str, Any]]
    source: str
    error: str | None
    counts: dict[str, int] = Field(default_factory=dict)


class EmailCheckResult(EmailCheckOut):
    explanation: str
    groups: dict[str, list[dict[str, Any]]]
    recommendations: list[Recommendation]
    new_breaches: list[str]
    retry_after: int | None = None
    payload_summary: str | None = None  # what left the machine; null when nothing was sent
    how_to_enable: list[str] | None = None
    manual_check_url: str | None = None
    attribution: str | None = None


class DomainCheckOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    domain: str
    checked_at: datetime
    status: str
    result: dict[str, Any]
    error: str | None


class DomainCheckResult(DomainCheckOut):
    explanation: str
    verification_methods: list[str] | None = None
    retry_after: int | None = None
    attribution: str | None = None


class PwnedSuffix(BaseModel):
    suffix: str
    count: int


class PwnedRange(BaseModel):
    suffixes: list[PwnedSuffix]


class EmailStatus(BaseModel):
    hibp_enabled: bool
    hibp_key_configured: bool
    pwned_passwords_enabled: bool
    tier_note: str
    privacy_note: str


# --------------------------------------------------------------------------- helpers


def normalize_email(raw: str) -> str:
    value = raw.strip().lower()
    m = _EMAIL_RE.match(value)
    if not m or len(m.group("local")) > 64:
        raise HTTPException(422, "Not a valid email address")
    return value


mask_email = hibp.mask_email


def _strip_html(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    plain = html.unescape(re.sub(r"<[^>]+>", "", text))
    return re.sub(r"\s+", " ", plain).strip()[:2000] or None


CLASS_LABELS = {
    "confirmed": "Confirmed breach",
    "unverified": "Unverified breach (HIBP could not confirm it came from the named site)",
    "malware": "Malware or stealer log (credentials captured from an infected device)",
    "spam_list": "Spam list (the address was on a spam list; this is not a security breach)",
    "fabricated": "Likely fabricated data (not a real breach)",
}
GROUP_ORDER = ("confirmed", "unverified", "malware", "spam_list", "fabricated")
EXPOSURE_CLASSES = {"confirmed", "unverified", "malware"}


def classify(b: dict[str, Any]) -> str:
    if b["is_spam_list"]:
        return "spam_list"
    if b["is_fabricated"]:
        return "fabricated"
    if b["is_malware"] or b["is_stealer_log"]:
        return "malware"
    if b["is_verified"]:
        return "confirmed"
    return "unverified"


def normalize_breach(raw: dict[str, Any]) -> dict[str, Any] | None:
    name = raw.get("Name") or raw.get("Title")
    if not isinstance(name, str) or not name:
        return None
    classes = [c for c in (raw.get("DataClasses") or []) if isinstance(c, str)]
    pwn = raw.get("PwnCount")
    b: dict[str, Any] = {
        "name": name,
        "title": raw.get("Title") if isinstance(raw.get("Title"), str) else name,
        "domain": raw.get("Domain") or None,
        "breach_date": raw.get("BreachDate"),
        "added_date": raw.get("AddedDate"),
        "modified_date": raw.get("ModifiedDate"),
        "pwn_count": pwn if isinstance(pwn, int) and not isinstance(pwn, bool) else None,
        "data_classes": classes,
        "description": _strip_html(raw.get("Description")),
        "is_verified": bool(raw.get("IsVerified")),
        "is_sensitive": bool(raw.get("IsSensitive")),
        "is_spam_list": bool(raw.get("IsSpamList")),
        "is_fabricated": bool(raw.get("IsFabricated")),
        "is_retired": bool(raw.get("IsRetired")),
        "is_malware": bool(raw.get("IsMalware")),
        "is_stealer_log": bool(raw.get("IsStealerLog")),
    }
    b["classification"] = classify(b)
    b["classification_label"] = CLASS_LABELS[b["classification"]]
    b["counts_as_breach"] = b["classification"] in EXPOSURE_CLASSES
    b["passwords_exposed"] = any("passwords" in c.lower() for c in classes)
    return b


def group_breaches(breaches: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {k: [] for k in GROUP_ORDER}
    for b in breaches:
        groups.setdefault(b.get("classification", "unverified"), []).append(b)
    return groups


def counts_for(breaches: list[dict[str, Any]]) -> dict[str, int]:
    out = {k: 0 for k in GROUP_ORDER}
    for b in breaches:
        out[b.get("classification", "unverified")] = out.get(b.get("classification", "unverified"), 0) + 1
    out["total_entries"] = len(breaches)
    out["breaches"] = sum(1 for b in breaches if b.get("counts_as_breach"))
    out["passwords_exposed"] = sum(1 for b in breaches if b.get("counts_as_breach") and b.get("passwords_exposed"))
    return out


# (id, priority, data-class keywords, text). Matching is a case-insensitive substring test, in this order.
DATA_CLASS_RULES: list[tuple[str, Priority, tuple[str, ...], str]] = [
    ("change_password", "high", ("passwords",),
     "Change the password for each affected account now, and change it everywhere else you used the same or a "
     "similar password. Attackers try leaked passwords on other sites (credential stuffing)."),
    ("enable_mfa", "high", ("passwords",),
     "Turn on multi-factor authentication for the affected accounts and for your email account, preferably with "
     "an authenticator app or a security key rather than SMS codes."),
    ("password_manager", "high", ("passwords",),
     "Use a password manager so every site gets a different, randomly generated password; one breach then "
     "exposes one account only."),
    ("password_hints", "high", ("password hints",),
     "Password hints often reveal the password itself. Treat that password as exposed and change it wherever "
     "it was used."),
    ("security_questions", "high", ("security questions",),
     "Change the security questions and answers on the affected accounts and anywhere you reused the same "
     "answers. Random answers stored in a password manager cannot be looked up or guessed."),
    ("auth_tokens", "high", ("auth tokens", "session tokens"),
     "Sign out of all sessions on the affected service and revoke any app passwords or API tokens it issued."),
    ("payment_data", "high", ("credit card", "bank account", "payment"),
     "Contact your bank or card issuer, ask whether the card should be replaced, and watch statements for "
     "transactions you do not recognise."),
    ("government_ids", "high", ("government issued", "social security", "passport", "national id", "tax"),
     "Identity documents or numbers were exposed: consider a credit freeze with the credit bureaus and watch for "
     "accounts or tax filings opened in your name."),
    ("phone_numbers", "medium", ("phone numbers",),
     "Your phone number is exposed, which helps SIM-swap attacks: ask your mobile carrier for a port-out or SIM "
     "lock PIN, avoid SMS as your only second factor, and be suspicious of calls or texts claiming to be your "
     "bank or carrier."),
    ("dates_of_birth", "medium", ("dates of birth",),
     "Date of birth is often used to verify identity. Do not rely on it as a secret, and consider a credit "
     "freeze if other identity details were exposed too."),
    ("physical_addresses", "medium", ("physical addresses",),
     "Expect phishing letters, delivery-scam texts and emails that quote your real address to seem genuine. "
     "Verify through the company's official website or phone number before acting."),
    ("private_messages", "medium", ("private messages", "chat logs", "email messages"),
     "Private messages from the service may now be public. Consider what they contained and whether anything "
     "in them (shared passwords, personal details) needs changing."),
    ("personal_details", "low", ("names", "employers", "job titles", "geographic locations", "genders", "ages"),
     "Personal details make targeted phishing more convincing. Be wary of messages that use them to build trust."),
    ("usernames", "low", ("usernames",),
     "Exposed usernames are paired with leaked passwords in credential-stuffing attacks; unique passwords per site "
     "make them useless."),
    ("email_phishing", "low", ("email addresses",),
     "Expect spam and phishing that mention the breached service. Do not follow links in unexpected emails; go "
     "to the site directly instead."),
    ("ip_addresses", "info", ("ip addresses",),
     "Exposed IP addresses mainly reveal approximate location at the time; usually no action is needed."),
]

GENERAL_HYGIENE: list[tuple[str, str]] = [
    ("hygiene_email_account",
     "Protect this email account above all others: it can reset every other password. Use a long unique password "
     "and multi-factor authentication on it."),
    ("hygiene_unique_passwords", "Use a unique password for every account, kept in a password manager."),
    ("hygiene_recovery", "Review the account's recovery phone number and backup email so they are current and yours."),
    ("hygiene_unused_accounts", "Close accounts you no longer use; they cannot leak data they do not hold."),
    ("hygiene_recheck", "Re-check this address periodically: new breaches are loaded into HIBP over time."),
]


def build_recommendations(breaches: list[dict[str, Any]]) -> list[Recommendation]:
    recs: list[Recommendation] = []
    active = [b for b in breaches if b.get("classification") != "fabricated"]
    for rid, priority, keywords, text in DATA_CLASS_RULES:
        matched_classes: list[str] = []
        matched_breaches: list[str] = []
        for b in active:
            hits = [c for c in b.get("data_classes", []) if any(k in c.lower() for k in keywords)]
            if hits:
                matched_breaches.append(b["name"])
                matched_classes.extend(c for c in hits if c not in matched_classes)
        if matched_breaches:
            recs.append(Recommendation(id=rid, priority=priority, text=text, data_classes=matched_classes,
                                       breaches=matched_breaches))
    by_class = group_breaches(breaches)
    if by_class["malware"]:
        recs.append(Recommendation(
            id="malware_cleanup", priority="high",
            text="This address appears in malware or stealer-log data, meaning credentials were captured from an "
                 "infected device. Scan the computers and phones you use with up-to-date security software, then "
                 "change passwords from a clean device and sign out of all sessions.",
            breaches=[b["name"] for b in by_class["malware"]]))
    if by_class["spam_list"]:
        recs.append(Recommendation(
            id="spam_list", priority="low",
            text="The address is on one or more spam lists. That is not a breach of an account, so no password change "
                 "is needed for it; expect more spam and phishing and use your mail provider's spam filtering.",
            breaches=[b["name"] for b in by_class["spam_list"]]))
    if by_class["unverified"]:
        recs.append(Recommendation(
            id="unverified_note", priority="info",
            text="Some breaches are unverified: HIBP could not confirm the data came from the named site. Treat the "
                 "exposed data as possibly real and follow the advice above anyway.",
            breaches=[b["name"] for b in by_class["unverified"]]))
    if by_class["fabricated"]:
        recs.append(Recommendation(
            id="fabricated_note", priority="info",
            text="Some entries are flagged as likely fabricated data, so they are not counted as breaches and no "
                 "specific action is suggested for them.",
            breaches=[b["name"] for b in by_class["fabricated"]]))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    recs.sort(key=lambda r: order[r.priority])  # stable: rule order kept within a priority
    recs.extend(Recommendation(id=rid, priority="info", text=text) for rid, text in GENERAL_HYGIENE)
    return recs


def _how_to_enable(enabled: bool, key: bool) -> list[str]:
    steps = []
    if not key:
        steps.append(f"Buy an API key at {HIBP_SITE}/API/Key (Core 1 is the cheapest tier) and store it under "
                     "Settings > Integrations as 'hibp_api_key'.")
    if not enabled:
        steps.append("Turn on the 'hibp' integration under Settings > Integrations.")
    return steps


def _latest_checks(db: Session, identity_id: int) -> tuple[EmailCheck | None, EmailCheck | None]:
    latest = db.execute(select(EmailCheck).where(EmailCheck.identity_id == identity_id)
                        .order_by(EmailCheck.checked_at.desc(), EmailCheck.id.desc()).limit(1)).scalar_one_or_none()
    ok = db.execute(select(EmailCheck).where(EmailCheck.identity_id == identity_id,
                                             EmailCheck.status.in_(SUCCESS_STATUSES))
                    .order_by(EmailCheck.checked_at.desc(), EmailCheck.id.desc()).limit(1)).scalar_one_or_none()
    return latest, ok


def _identity_out(db: Session, ident: EmailIdentity) -> IdentityOut:
    latest, ok = _latest_checks(db, ident.id)
    return IdentityOut(id=ident.id, email=ident.email, masked_email=mask_email(ident.email), label=ident.label,
                       ownership_confirmed=ident.ownership_confirmed, created_at=ident.created_at,
                       last_checked_at=ident.last_checked_at, latest_status=latest.status if latest else None,
                       latest_checked_at=latest.checked_at if latest else None,
                       breach_count=ok.breach_count if ok else None)


def _check_out(c: EmailCheck) -> dict[str, Any]:
    data = EmailCheckOut.model_validate(c).model_dump()
    data["counts"] = counts_for(c.breaches or [])
    return data


def _get_identity(db: Session, identity_id: int) -> EmailIdentity:
    ident = db.get(EmailIdentity, identity_id)
    if ident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such email identity")
    return ident


# --------------------------------------------------------------------------- identities


@router.get("/status", response_model=EmailStatus)
def email_status(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> EmailStatus:
    return EmailStatus(hibp_enabled=integration_enabled(db, "hibp"),
                       hibp_key_configured=secrets.has_secret("hibp_api_key"),
                       pwned_passwords_enabled=integration_enabled(db, "pwned_passwords"),
                       tier_note=TIER_NOTE, privacy_note=PRIVACY_NOTE)


@router.get("/identities", response_model=list[IdentityOut])
def list_identities(auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[IdentityOut]:
    rows = db.execute(select(EmailIdentity).order_by(EmailIdentity.created_at, EmailIdentity.id)).scalars()
    return [_identity_out(db, i) for i in rows]


@router.post("/identities", response_model=IdentityOut, status_code=201)
def add_identity(body: IdentityCreate, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> IdentityOut:
    if body.ownership_confirmed is not True:
        raise HTTPException(422, f"Confirm ownership first: '{OWNERSHIP_TEXT}'")
    email = normalize_email(body.email)
    if db.execute(select(EmailIdentity.id).where(EmailIdentity.email == email)).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "This address is already monitored")
    label = body.label.strip() if body.label and body.label.strip() else None
    ident = EmailIdentity(email=email, label=label, ownership_confirmed=True)
    db.add(ident)
    db.flush()
    audit.record(db, auth.actor, "email.identity_added", "email_identity", ident.id,
                 {"masked": mask_email(email), "ownership_confirmed": OWNERSHIP_TEXT})
    db.commit()
    return _identity_out(db, ident)


@router.delete("/identities/{identity_id}", status_code=204)
def delete_identity(identity_id: int, auth: AuthContext = Depends(current_auth),
                    db: Session = Depends(get_db)) -> Response:
    ident = _get_identity(db, identity_id)
    masked = mask_email(ident.email)
    for c in db.execute(select(EmailCheck).where(EmailCheck.identity_id == ident.id)).scalars():
        db.delete(c)
    db.delete(ident)
    audit.record(db, auth.actor, "email.identity_deleted", "email_identity", identity_id, {"masked": masked})
    db.commit()
    return Response(status_code=204)


# --------------------------------------------------------------------------- breach checks


def _notify_new(db: Session, ident: EmailIdentity, breaches: list[dict[str, Any]], new_names: list[str]) -> None:
    for b in breaches:
        if b["name"] not in new_names:
            continue
        severity = "high" if b.get("passwords_exposed") else "medium"
        who = ident.label or mask_email(ident.email)
        body = (f"{b['classification_label']}. Breach date: {b.get('breach_date') or 'unknown'}. "
                f"Exposed data: {', '.join(b.get('data_classes') or []) or 'not listed'}.")
        notify(db, severity=severity, kind="email_breach", title=f"{who} found in a new breach: {b['title']}",
               body=body, link=f"/email?identity={ident.id}", dedupe_key=f"breach:{ident.id}:{b['name']}")


@router.post("/identities/{identity_id}/check", response_model=EmailCheckResult)
def check_identity(identity_id: int, auth: AuthContext = Depends(current_auth),
                   db: Session = Depends(get_db)) -> EmailCheckResult:
    ident = _get_identity(db, identity_id)
    enabled = integration_enabled(db, "hibp")
    key = secrets.get_secret("hibp_api_key")
    if not enabled or not key:
        reasons = []
        if not enabled:
            reasons.append("the HIBP integration is turned off")
        if not key:
            reasons.append("no HIBP API key is stored")
        reason = "Live check unavailable: " + " and ".join(reasons) + "."
        return _record_unavailable(db, auth, ident, reason, _how_to_enable(enabled, bool(key)))

    _, previous_ok = _latest_checks(db, ident.id)
    result = hibp.breached_account(ident.email, key)
    if result.status == "unavailable":
        return _record_unavailable(db, auth, ident, f"Live check unavailable: {result.error}.",
                                   ["Allow outbound connections in the server settings."])

    breaches: list[dict[str, Any]] = []
    new_names: list[str] = []
    if result.status == "found":
        breaches = [b for b in (normalize_breach(r) for r in result.data) if b is not None]
        breaches.sort(key=lambda b: (str(b.get("breach_date") or ""), b["name"]), reverse=True)
        seen = {b.get("name") for b in (previous_ok.breaches if previous_ok else [])}
        # spam lists and fabricated data are listed, but never announced as new breaches
        new_names = [b["name"] for b in breaches if b["name"] not in seen and b["counts_as_breach"]]

    st = result.status if result.status in SUCCESS_STATUSES else "error"
    check = EmailCheck(identity_id=ident.id, status=st, source="hibp", breaches=breaches,
                       breach_count=sum(1 for b in breaches if b["counts_as_breach"]),
                       error=result.error if st == "error" else None)
    db.add(check)
    if st in SUCCESS_STATUSES:
        ident.last_checked_at = now()
    db.flush()
    if st == "found":
        _notify_new(db, ident, breaches, new_names)
    audit.record(db, auth.actor, "email.checked", "email_identity", ident.id,
                 {"masked": mask_email(ident.email), "status": st, "breach_count": check.breach_count,
                  "new_breaches": len(new_names)})
    db.commit()

    if st == "found":
        c = counts_for(breaches)
        explanation = (f"HIBP lists this address in {c['total_entries']} data set(s): {c['confirmed']} confirmed "
                       f"breach(es), {c['unverified']} unverified, {c['malware']} malware/stealer log, "
                       f"{c['spam_list']} spam list(s) and {c['fabricated']} likely fabricated.")
    elif st == "not_found":
        explanation = NOT_FOUND_CAVEAT
    else:
        explanation = f"The check did not complete: {result.error}."
    return EmailCheckResult(
        **_check_out(check), explanation=explanation, groups=group_breaches(breaches),
        recommendations=build_recommendations(breaches) if st in SUCCESS_STATUSES else [],
        new_breaches=new_names, retry_after=result.retry_after,
        payload_summary=hibp.ACCOUNT_PAYLOAD if result.sent else None,
        attribution=hibp.ATTRIBUTION if st in SUCCESS_STATUSES else None,
        manual_check_url=HIBP_SITE if st == "error" else None)


def _record_unavailable(db: Session, auth: AuthContext, ident: EmailIdentity, reason: str,
                        how_to_enable: list[str]) -> EmailCheckResult:
    check = EmailCheck(identity_id=ident.id, status="unavailable", source="hibp", breaches=[], breach_count=0,
                       error=reason)
    db.add(check)
    db.flush()
    audit.record(db, auth.actor, "email.checked", "email_identity", ident.id,
                 {"masked": mask_email(ident.email), "status": "unavailable"})
    db.commit()
    explanation = (f"{reason} Nothing was sent anywhere. To enable live checks: {' '.join(how_to_enable)} "
                   f"Meanwhile the owner of the address can check it manually at {HIBP_SITE}.")
    return EmailCheckResult(**_check_out(check), explanation=explanation, groups=group_breaches([]),
                            recommendations=[], new_breaches=[], how_to_enable=how_to_enable,
                            manual_check_url=HIBP_SITE)


@router.get("/identities/{identity_id}/history", response_model=list[EmailCheckOut])
def identity_history(identity_id: int, auth: AuthContext = Depends(current_auth),
                     db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    ident = _get_identity(db, identity_id)
    rows = db.execute(select(EmailCheck).where(EmailCheck.identity_id == ident.id)
                      .order_by(EmailCheck.checked_at.desc(), EmailCheck.id.desc())).scalars()
    return [_check_out(c) for c in rows]


_CSV_FIELDS = ["name", "title", "domain", "classification", "breach_date", "added_date", "pwn_count", "data_classes",
               "passwords_exposed", "is_verified", "is_spam_list", "is_fabricated", "is_malware", "is_stealer_log",
               "is_sensitive", "is_retired"]


def _csv_cell(value: Any) -> str:
    if isinstance(value, list):
        value = "; ".join(str(v) for v in value)
    text = "" if value is None else str(value)
    # Spreadsheet formula injection: breach titles come from a third party.
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@router.get("/identities/{identity_id}/report", response_model=None)
def identity_report(identity_id: int, format: Literal["json", "csv"] = Query("json"),
                    auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> Response | dict[str, Any]:
    ident = _get_identity(db, identity_id)
    latest, ok = _latest_checks(db, ident.id)
    breaches = ok.breaches if ok else []
    audit.record(db, auth.actor, "email.report_exported", "email_identity", ident.id, {"format": format})
    db.commit()
    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(_CSV_FIELDS)
        for b in breaches:
            writer.writerow([_csv_cell(b.get(f)) for f in _CSV_FIELDS])
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="email-exposure-{ident.id}.csv"'})
    history = db.execute(select(EmailCheck).where(EmailCheck.identity_id == ident.id)
                         .order_by(EmailCheck.checked_at.desc(), EmailCheck.id.desc())).scalars()
    return {
        "sentinel_email_report": 1,
        "generated_at": now().isoformat(),
        "identity": {"id": ident.id, "email": ident.email, "label": ident.label,
                     "ownership_confirmed": ident.ownership_confirmed},
        "latest_check": _check_out(latest) if latest else None,
        "latest_successful_check": _check_out(ok) if ok else None,
        "counts": counts_for(breaches),
        "breaches": breaches,
        "recommendations": [r.model_dump() for r in build_recommendations(breaches)] if ok else [],
        "history": [{"checked_at": c.checked_at.isoformat(), "status": c.status, "breach_count": c.breach_count,
                     "error": c.error} for c in history],
        "attribution": hibp.ATTRIBUTION,
        "limitations": NOT_FOUND_CAVEAT if ok is None or ok.status == "not_found" else
        "Only breaches loaded into Have I Been Pwned are listed; others may exist.",
    }


# --------------------------------------------------------------------------- domains


@router.post("/domains/{domain}/check", response_model=DomainCheckResult)
def check_domain(domain: str, auth: AuthContext = Depends(current_auth),
                 db: Session = Depends(get_db)) -> DomainCheckResult:
    d = domain.strip().rstrip(".").lower()
    if not _DOMAIN_RE.match(d):
        raise HTTPException(422, "Not a valid domain name")
    enabled = integration_enabled(db, "hibp")
    key = secrets.get_secret("hibp_api_key")
    result: hibp.HibpResult | None = None
    if enabled and key:
        result = hibp.breached_domain(d, key)
    if result is None or result.status == "unavailable":
        reason = result.error if result else "the HIBP integration is off or no API key is stored"
        row = DomainCheck(domain=d, status="unavailable", result={}, error=f"Live check unavailable: {reason}")
        explanation = (f"Live check unavailable: {reason}. Nothing was sent. "
                       + " ".join(_how_to_enable(enabled, bool(key))))
    elif result.status in ("found", "not_found"):
        aliases: dict[str, list[str]] = result.data or {}
        per_breach: dict[str, int] = {}
        for names in aliases.values():
            for n in names:
                per_breach[n] = per_breach.get(n, 0) + 1
        row = DomainCheck(domain=d, status=result.status, error=None,
                          result={"aliases": aliases, "alias_count": len(aliases),
                                  "breaches": dict(sorted(per_breach.items()))})
        explanation = (f"{len(aliases)} address(es) on {d} appear in {len(per_breach)} breach(es)."
                       if result.status == "found" else
                       f"No address on {d} appears in a breach loaded into HIBP. That does not prove none was exposed.")
    elif result.status == "not_verified":
        row = DomainCheck(domain=d, status="not_verified", result={}, error=result.error)
        explanation = (f"HIBP only searches domains you have proved you control. Add {d} in the HIBP domain search "
                       "dashboard with the same account as the API key and verify it, then try again.")
    else:
        row = DomainCheck(domain=d, status="error", result={}, error=result.error)
        explanation = f"The check did not complete: {result.error}."
    db.add(row)
    db.flush()
    audit.record(db, auth.actor, "email.domain_checked", "domain", d, {"status": row.status})
    db.commit()
    return DomainCheckResult(
        **DomainCheckOut.model_validate(row).model_dump(), explanation=explanation,
        verification_methods=DOMAIN_VERIFICATION_METHODS if row.status == "not_verified" else None,
        retry_after=result.retry_after if result else None,
        attribution=hibp.ATTRIBUTION if row.status in ("found", "not_found") else None)


@router.get("/domains", response_model=list[DomainCheckOut])
def domain_history(domain: str | None = None, limit: int = Query(100, ge=1, le=1000),
                   auth: AuthContext = Depends(current_auth), db: Session = Depends(get_db)) -> list[DomainCheck]:
    q = select(DomainCheck)
    if domain:
        q = q.where(DomainCheck.domain == domain.strip().rstrip(".").lower())
    return list(db.execute(q.order_by(DomainCheck.checked_at.desc(), DomainCheck.id.desc()).limit(limit)).scalars())


# --------------------------------------------------------------------------- Pwned Passwords


@router.get("/pwned-range/{prefix}", response_model=PwnedRange)
def pwned_range(prefix: str, request: Request, auth: AuthContext = Depends(current_auth),
                db: Session = Depends(get_db)) -> PwnedRange:
    """Relay a k-anonymity range lookup. The browser hashes the password and compares suffixes itself."""
    if not rate_limiter.allow("pwned_range", client_ip(request), PWNED_RANGE_LIMIT, 60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many password checks; wait a minute",
                            headers={"Retry-After": "60"})
    try:
        p = pwned_passwords.normalize_prefix(prefix)
    except pwned_passwords.InvalidPrefix as exc:
        raise HTTPException(422, "Send only the first 5 hexadecimal characters of the SHA-1 hash") from exc
    if not integration_enabled(db, "pwned_passwords"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "The Pwned Passwords integration is turned off")
    try:
        rows = pwned_passwords.range_query(p)
    except http.OutboundDisabled as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    except http.OutboundError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Pwned Passwords could not be reached") from exc
    audit.record(db, auth.actor, "email.password_checked", "pwned_passwords", None)  # never the prefix
    db.commit()
    return PwnedRange(suffixes=[PwnedSuffix(suffix=str(r["suffix"]), count=int(r["count"])) for r in rows])
