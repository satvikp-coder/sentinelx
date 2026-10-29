"""Independent verification. For each candidate, re-run a MINIMAL proof in a FRESH session (new
cookie jar, fresh persona login if any) using request logic and a decision rule written again
here - deliberately NOT by calling into `sentinelx.scanner.checks`. A finding is never confirmed
by the model; this module has no model import at all.

Outcomes: confirmed (reproduced, the consequence observed again), needs_validation (could not be
reproduced structurally, or the evidence is behavioural only), rejected (does not reproduce; the
control now behaves differently)."""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sentinelx.common_schemas import VulnClass
from sentinelx.policy.redaction import redact

from .context import ScanContext
from .models import Candidate, Verification

EXCERPT_LIMIT = 300
# intentionally re-declared here, independently of packages/scanner/checks/injection.py
_DB_ERROR_RE = re.compile(
    r"SQLSTATE|SQLite3?::|SQLITE_ERROR|no such column|no such table|unrecognized token|"
    r"syntax error(?: near| in)|PDOException|OperationalError|mysql_fetch|ORA-\d{5}|"
    r"org\.postgresql|You have an error in your SQL syntax", re.IGNORECASE)


def _excerpt(text: str) -> str:
    return str(redact(text[: EXCERPT_LIMIT * 4]).value)[:EXCERPT_LIMIT]


def _replace_query_param(path_and_query: str, name: str, value: str) -> str:
    parts = urlsplit(path_and_query)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit(("", "", parts.path, urlencode(pairs), ""))


def _v(state: str, detail: str, fresh_session: bool, *, event_ids: list[str] | None = None,
       excerpt: str = "") -> Verification:
    """`Verification` is a Pydantic model (keyword-only); this lets every verifier below build
    one with the same short, positional-looking call it would have with a plain dataclass."""
    return Verification(state=state, detail=detail, fresh_session=fresh_session,  # type: ignore[arg-type]
                        event_ids=event_ids or [], excerpt=excerpt)


def _verify_sql_injection(ctx: ScanContext, c: Candidate) -> Verification:
    proof = c.proof
    if "sample" in proof:
        persona = str(proof["persona"])
        session = ctx.ensure_persona(persona, fresh=True)  # a brand-new cookie jar / fresh login
        base_url = _replace_query_param(str(proof["sample"]), str(proof["param"]),
                                        str(proof["baseline"]))
        probe_url = _replace_query_param(str(proof["sample"]), str(proof["param"]),
                                         str(proof["baseline"]) + str(proof["probe_suffix"]))
        base = ctx.request_in(session, "GET", base_url)
        probe = ctx.request_in(session, "GET", probe_url)
    else:
        session = ctx.ensure_persona("anonymous", fresh=True)
        body_base = urlencode({str(proof["field"]): str(proof["baseline"])})
        body_probe = urlencode({str(proof["field"]): str(proof["baseline"]) + str(
            proof["probe_suffix"])})
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        base = ctx.request_in(session, "POST", str(proof["template"]), body=body_base,
                              headers=headers, reason="independent verification re-check",
                              account=ctx.personas_file.failed_login_username)
        probe = ctx.request_in(session, "POST", str(proof["template"]), body=body_probe,
                               headers=headers, reason="independent verification re-check",
                               account=ctx.personas_file.failed_login_username)
    if not (base.allowed and probe.allowed):
        return _v("needs_validation", "the re-check request was refused or failed",
                            fresh_session=True)
    if _DB_ERROR_RE.search(probe.text) and not _DB_ERROR_RE.search(base.text):
        return _v("confirmed", "the database-error signature reproduced", True,
                            event_ids=[e for e in [base.event_id, probe.event_id] if e],
                            excerpt=_excerpt(probe.text))
    return _v("rejected", "the database-error signature did not reproduce", True,
                        excerpt=_excerpt(probe.text))


def _verify_reflected_xss(ctx: ScanContext, c: Candidate) -> Verification:
    proof = c.proof
    if "sample" in proof:
        persona = str(proof["persona"])
        session = ctx.ensure_persona(persona, fresh=True)
        url = _replace_query_param(str(proof["sample"]), str(proof["param"]), str(proof["marker"]))
        probe = ctx.request_in(session, "GET", url)
    else:
        session = ctx.ensure_persona("anonymous", fresh=True)
        body = urlencode({str(proof["field"]): str(proof["marker"])})
        probe = ctx.request_in(session, "POST", str(proof["template"]), body=body,
                               headers={"Content-Type": "application/x-www-form-urlencoded"},
                               reason="independent verification re-check",
                               account=ctx.personas_file.failed_login_username)
    if not probe.allowed:
        return _v("needs_validation", "the re-check request was refused", True)
    marker = str(proof["marker"])
    if marker in probe.text:
        return _v("confirmed", "the marker reflected unencoded again", True,
                            event_ids=[e for e in [probe.event_id] if e],
                            excerpt=_excerpt(probe.text))
    return _v("rejected", "the marker was encoded (or absent) on re-check", True,
                        excerpt=_excerpt(probe.text))


def _content_slice(text: str) -> str:
    idx = text.lower().find("<h1>")
    body = text[idx:idx + 250] if idx != -1 else text
    return re.sub(r"\s+", " ", body).strip()


def _verify_bola(ctx: ScanContext, c: Candidate) -> Verification:
    url = str(c.proof["url"])
    b_session = ctx.ensure_persona("user_b", fresh=True)
    b_out = ctx.request_in(b_session, "GET", url)
    if not b_out.allowed or b_out.status != 200:
        return _v("needs_validation", "the victim's own re-fetch failed", True)
    b_slice = _content_slice(b_out.text)
    a_session = ctx.ensure_persona("user_a", fresh=True)
    a_out = ctx.request_in(a_session, "GET", url)
    if a_out.allowed and a_out.status == 200 and _content_slice(a_out.text) == b_slice:
        return _v("confirmed", "persona A still received persona B's content", True,
                            event_ids=[e for e in [b_out.event_id, a_out.event_id] if e],
                            excerpt=_excerpt(a_out.text))
    return _v("rejected", "persona A no longer receives persona B's content", True)


def _verify_path_still_exposed(ctx: ScanContext, c: Candidate, *, require_secret: bool
                               ) -> Verification:
    path = str(c.proof["path"])
    session = ctx.ensure_persona("anonymous", fresh=True)
    out = ctx.request_in(session, "GET", path)
    if not out.allowed:
        return _v("needs_validation", "the re-check request was refused", True)
    if out.status != 200:
        return _v("rejected", f"re-check returned HTTP {out.status}, not 200", True)
    if require_secret and redact(out.text).count == 0:
        return _v("rejected", "no secret-shaped value on re-check", True,
                            excerpt=_excerpt(out.text))
    return _v("confirmed", "the path is still reachable on re-check", True,
                        event_ids=[e for e in [out.event_id] if e], excerpt=_excerpt(out.text))


def _verify_static_secret(ctx: ScanContext, c: Candidate) -> Verification:
    """Static findings (already-crawled script text) have no live endpoint to re-request;
    re-derive the redaction independently from the stored excerpt instead."""
    if redact(c.excerpt).count == 0:
        return _v("needs_validation", "the stored excerpt no longer shows a "
                            "secret-shaped value (it may have been truncated)", fresh_session=True)
    return _v("confirmed", "a secret-shaped value is present in the static excerpt",
                        fresh_session=True, excerpt=_excerpt(c.excerpt))


def _verify_missing_auth(ctx: ScanContext, c: Candidate) -> Verification:
    return _verify_path_still_exposed(ctx, c, require_secret=False)


def _verify_sensitive_file(ctx: ScanContext, c: Candidate) -> Verification:
    if c.proof.get("static"):
        return _verify_static_secret(ctx, c)
    require = "secret_sha256_12" in c.proof
    return _verify_path_still_exposed(ctx, c, require_secret=require)


def _verify_debug_exposure(ctx: ScanContext, c: Candidate) -> Verification:
    return _verify_path_still_exposed(ctx, c, require_secret=False)


def _verify_rate_limit(ctx: ScanContext, c: Candidate) -> Verification:
    """Behavioural evidence can only ever reach `needs_validation` here, never `confirmed` - a
    fresh, SMALLER burst (never above the module's own hard cap) either repeats the pattern
    (needs_validation: still only behavioural) or shows throttling (rejected)."""
    from .checks.rate_limit import HARD_CAP

    username = ctx.personas_file.failed_login_username
    spec = ctx.personas_file.login
    cap = min(5, HARD_CAP)
    statuses: list[int] = []
    event_ids: list[str] = []
    session = ctx.ensure_persona("anonymous", fresh=True)
    for n in range(cap):
        if spec.encoding == "json":
            import json

            body = json.dumps({spec.username_field: username, spec.password_field: f"re-{n}"})
            headers = {"Content-Type": "application/json"}
        else:
            body = urlencode({spec.username_field: username, spec.password_field: f"re-{n}"})
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        out = ctx.request_in(session, "POST", spec.path, body=body, headers=headers,
                             reason="independent verification re-check (capped burst)",
                             account=username)
        if not out.allowed:
            break
        statuses.append(out.status or 0)
        if out.event_id:
            event_ids.append(out.event_id)
    if len(statuses) < 2:
        return _v("needs_validation", "the re-check burst was refused or too short",
                            True)
    if len({*statuses}) > 1 or any(s in {429, 423} for s in statuses):
        return _v("rejected", f"the fresh burst was throttled ({statuses})", True,
                            event_ids=event_ids)
    return _v("needs_validation",
                        f"the fresh, capped burst ({len(statuses)} attempts) again showed no "
                        "throttling; this remains behavioural evidence, not a structural proof",
                        True, event_ids=event_ids)


def _verify_cors(ctx: ScanContext, c: Candidate) -> Verification:
    from .checks.cors import PROBE_ORIGIN

    path = str(c.proof["path"])
    session = ctx.ensure_persona("anonymous", fresh=True)
    out = ctx.request_in(session, "GET", path, headers={"Origin": PROBE_ORIGIN})
    if not out.allowed:
        return _v("needs_validation", "the re-check request was refused", True)
    allow_origin = out.headers.get("access-control-allow-origin")
    allow_creds = out.headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == PROBE_ORIGIN and allow_creds == "true":
        return _v("confirmed", "the probe origin was reflected with credentials again",
                            True, event_ids=[e for e in [out.event_id] if e])
    return _v("rejected", "the probe origin was not reflected on re-check", True)


def _verify_headers_cookies(ctx: ScanContext, c: Candidate) -> Verification:
    if "missing_headers" in c.proof:
        session = ctx.ensure_persona("anonymous", fresh=True)
        out = ctx.request_in(session, "GET", str(c.proof["path"]))
        if not out.allowed:
            return _v("needs_validation", "the re-check request was refused", True)
        still_missing = [h for h in c.proof["missing_headers"] if h not in out.headers]
        if still_missing:
            return _v("confirmed", f"still missing: {still_missing}", True,
                                event_ids=[e for e in [out.event_id] if e])
        return _v("rejected", "the headers are present on re-check", True)
    persona = str(c.proof["persona"])
    session = ctx.ensure_persona(persona, fresh=True)
    hints = ("session", "sid", "phpsessid", "token", "auth")
    still: dict[str, list[str]] = {}
    for name, raw in session.raw_set_cookies.items():
        if not any(h in name.lower() for h in hints):
            continue
        low = raw.lower()
        missing = [f for f in ("httponly", "samesite") if f not in low]
        if missing:
            still[name] = missing
    if still:
        return _v("confirmed", f"cookie flags still missing: {still}", True)
    return _v("rejected", "the cookie flags are present on re-check", True)


_TRACE_RE = re.compile(
    r"Traceback \(most recent|Stack trace:|\bat\s+\S+\s+\([^)]*:\d+:\d+\)|\.js:\d+:\d+|"
    r"Fatal error:|Warning:.*on line \d+|node_modules[/\\]|/var/www/|/app/server\.js|"
    r'"stack"\s*:', re.IGNORECASE)


def _verify_verbose_errors(ctx: ScanContext, c: Candidate) -> Verification:
    proof = c.proof
    if "sample" in proof:
        session = ctx.ensure_persona(str(proof["persona"]), fresh=True)
        url = _replace_query_param(str(proof["sample"]), str(proof["param"]),
                                   str(proof["malformed_value"]))
        out = ctx.request_in(session, "GET", url)
    else:
        session = ctx.ensure_persona("anonymous", fresh=True)
        out = ctx.request_in(session, "POST", str(proof["path"]), body=str(proof[
            "malformed_body"]), headers={"Content-Type": "application/json"},
            reason="independent verification re-check",
            account=ctx.personas_file.failed_login_username)
    if not out.allowed:
        return _v("needs_validation", "the re-check request was refused", True)
    if _TRACE_RE.search(out.text):
        return _v("confirmed", "a stack trace or internal path reproduced", True,
                            event_ids=[e for e in [out.event_id] if e], excerpt=_excerpt(out.text))
    return _v("rejected", "no stack trace or internal path on re-check", True)


def _verify_upload(ctx: ScanContext, c: Candidate) -> Verification:
    """Re-checks only the PERSISTENT consequence (the file is still fetchable); it does not
    repeat the upload itself, so verification never doubles the artefacts left in the lab."""
    served_at = str(c.proof["served_at"])
    session = ctx.ensure_persona("anonymous", fresh=True)
    out = ctx.request_in(session, "GET", served_at)
    if not out.allowed:
        return _v("needs_validation", "the re-check request was refused", True)
    if out.status == 200:
        return _v("confirmed", "the uploaded file is still reachable without "
                            "authentication", True, event_ids=[e for e in [out.event_id] if e])
    return _v("rejected", f"re-check returned HTTP {out.status}, not 200", True)


_VERIFIERS: dict[VulnClass, Callable[[ScanContext, Candidate], Verification]] = {
    VulnClass.SQL_INJECTION: _verify_sql_injection,
    VulnClass.REFLECTED_XSS: _verify_reflected_xss,
    VulnClass.BROKEN_OBJECT_AUTHORIZATION: _verify_bola,
    VulnClass.MISSING_AUTHENTICATION: _verify_missing_auth,
    VulnClass.SENSITIVE_FILE_EXPOSURE: _verify_sensitive_file,
    VulnClass.DEBUG_EXPOSURE: _verify_debug_exposure,
    VulnClass.MISSING_RATE_LIMIT: _verify_rate_limit,
    VulnClass.PERMISSIVE_CORS: _verify_cors,
    VulnClass.SECURITY_HEADERS_AND_COOKIES: _verify_headers_cookies,
    VulnClass.WEAK_UPLOAD_VALIDATION: _verify_upload,
    VulnClass.VERBOSE_ERRORS: _verify_verbose_errors,
}


def verify_candidate(ctx: ScanContext, candidate: Candidate) -> Verification:
    fn = _VERIFIERS.get(candidate.vuln_class)
    if fn is None:
        return _v("needs_validation", f"no verifier for {candidate.vuln_class}", True)
    try:
        return fn(ctx, candidate)
    except Exception as exc:  # noqa: BLE001 - a verifier failure is honestly needs_validation
        return _v("needs_validation", f"verifier raised {type(exc).__name__}: {exc}",
                            True)
