"""Three checks that all read the GET-only, read-only `discover()` results:

- sensitive_file_exposure: backup/secret-shaped files an anonymous visitor can read, plus a
  static scan of crawled JavaScript/HTML for secret-shaped strings (hardcoded secrets).
- debug_exposure: debug/info/server-status pages an anonymous visitor can read.
- missing_authentication: admin/settings-style pages that return real content with no login.

None of these send a request beyond what `recon.discover()` / `recon.crawl()` already made
(or, for the admin paths, the same kind of plain GET)."""

from __future__ import annotations

import re

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate
from .base import CheckSpec, candidate_id, excerpt, looks_like_a_secret, severity_for

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.IGNORECASE)
_USER_IDENTIFIER_KEY_RE = re.compile(
    r'(?i)"(?:user_?id|username|email|account_?id)"\s*:')


def _looks_sensitive(ctx: ScanContext, body: str) -> bool:
    """A generic bar for confirming missing_authentication: the response must look like it
    carries something worth protecting (credentials/tokens/secrets, an email address, more than
    one user's identifiers in a JSON-shaped body, or - for a plain HTML listing - two or more of
    the scanner's OWN known persona usernames, which belong to different accounts), not just any
    page that happens to sit at a conventional admin/settings-shaped path. A page returning only
    site-wide, non-personal configuration (a theme name, a public announcement) is
    reachable-without-login by design, not a finding."""
    if looks_like_a_secret(body) or _EMAIL_RE.search(body):
        return True
    if len(_USER_IDENTIFIER_KEY_RE.findall(body)) >= 2:
        return True
    usernames = {p.credentials.username for p in ctx.personas_file.personas if p.credentials}
    hits = sum(1 for u in usernames if re.search(rf"\b{re.escape(u)}\b", body, re.IGNORECASE))
    return hits >= 2

FILE_SPEC = CheckSpec(
    id="sensitive_file_exposure", vuln_class=VulnClass.SENSITIVE_FILE_EXPOSURE,
    owasp_category="A05:2021 Security Misconfiguration",
    preconditions="a backup/env-shaped conventional path is reachable, or crawled JS/HTML "
                  "contains a secret-shaped string",
    safe_strategy="GET a conventional backup/secret path as an anonymous visitor, or read "
                  "already-crawled script text; only a hash and a short redacted excerpt are kept")
DEBUG_SPEC = CheckSpec(
    id="debug_exposure", vuln_class=VulnClass.DEBUG_EXPOSURE,
    owasp_category="A05:2021 Security Misconfiguration",
    preconditions="a debug/info/server-status conventional path is reachable",
    safe_strategy="GET a conventional debug/info path as an anonymous visitor")
AUTH_SPEC = CheckSpec(
    id="missing_authentication", vuln_class=VulnClass.MISSING_AUTHENTICATION,
    owasp_category="A01:2021 Broken Access Control",
    preconditions="an admin/settings-shaped conventional path returns content that looks "
                  "sensitive (a secret-shaped value, an email address, or more than one user's "
                  "identifiers) with no login",
    safe_strategy="GET an admin/settings path as an anonymous visitor; a redirect to login or a "
                  "denial is not flagged, and neither is a page with only non-personal, "
                  "site-wide content")
FILE_HINTS = (".env", ".git", ".bak", ".old", "backup", "config")
DEBUG_HINTS = ("debug", "info", "phpinfo", "server-status")


def _hits(ctx: ScanContext) -> list[tuple[str, dict[str, object]]]:
    return [(path, entry) for path, by_persona in ctx.discovery.items()
            if (entry := by_persona.get("anonymous")) and entry.get("real_hit")
            and entry.get("status") == 200]


def _candidate(spec: CheckSpec, path: str, entry: dict[str, object], secret_hash: str | None
              ) -> Candidate:
    body = str(entry.get("body", ""))
    proof: dict[str, object] = {"path": path}
    if secret_hash:
        proof["secret_sha256_12"] = secret_hash
    return Candidate(
        id=candidate_id(spec.id), check_id=spec.id, vuln_class=spec.vuln_class,
        severity=severity_for(spec.vuln_class), confidence="high", method="GET", endpoint=path,
        endpoints=[path], persona="anonymous",
        summary=(f"{path} is reachable without authentication and appears to contain a "
                 f"secret-shaped value." if secret_hash else
                 f"{path} is reachable without authentication."),
        evidence_event_ids=[e for e in [entry.get("event_id")] if isinstance(e, str)],
        excerpt=excerpt(body), proof=proof)


def applicable_sensitive_file_exposure(ctx: ScanContext) -> list[str]:
    return [p for p in ctx.paths.exposure_paths if any(h in p.lower() for h in FILE_HINTS)]


def applicable_debug_exposure(ctx: ScanContext) -> list[str]:
    return [p for p in ctx.paths.exposure_paths if any(h in p.lower() for h in DEBUG_HINTS)]


def applicable_missing_authentication(ctx: ScanContext) -> list[str]:
    return list(ctx.paths.admin_paths)


def run_sensitive_file_exposure(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []
    for path, entry in _hits(ctx):
        if not any(hint in path.lower() for hint in FILE_HINTS):
            continue
        body = str(entry.get("body", ""))
        secret_hash = None
        if looks_like_a_secret(body):
            import hashlib

            secret_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]
        out.append(_candidate(FILE_SPEC, path, entry, secret_hash))
    for url, body in ctx.scripts.items():
        if not looks_like_a_secret(body):
            continue
        import hashlib

        out.append(Candidate(
            id=candidate_id(FILE_SPEC.id), check_id=FILE_SPEC.id, vuln_class=FILE_SPEC.vuln_class,
            severity=severity_for(FILE_SPEC.vuln_class), confidence="high", method="GET",
            endpoint=url, endpoints=[url], persona="anonymous",
            summary="Crawled script/HTML text contains a secret-shaped value.",
            evidence_event_ids=[], excerpt=excerpt(body),
            proof={"path": url, "secret_sha256_12": hashlib.sha256(
                body.encode("utf-8")).hexdigest()[:12], "static": True}))
    return out


def run_debug_exposure(ctx: ScanContext) -> list[Candidate]:
    return [_candidate(DEBUG_SPEC, path, entry, None) for path, entry in _hits(ctx)
            if any(hint in path.lower() for hint in DEBUG_HINTS)]


def run_missing_authentication(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []
    for path, entry in _hits(ctx):
        if any(hint in path.lower() for hint in (*FILE_HINTS, *DEBUG_HINTS)):
            continue
        if path in ctx.paths.admin_paths and _looks_sensitive(ctx, str(entry.get("body", ""))):
            out.append(_candidate(AUTH_SPEC, path, entry, None))
    return out
