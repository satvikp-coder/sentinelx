"""Score a finished scan report against a lab's hand-authored PLANTED.json ground truth.

PLANTED.json is read ONLY here, after a scan has already produced its findings - never inside
`sentinelx.scanner`, which never sees the ground truth it is being measured against."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.common_schemas import PlantedManifest

from .metrics import rate

LABS_ROOT = Path(__file__).resolve().parents[2] / "labs"

# PLANTED vuln_class (hand-authored per lab, independent of the scanner) -> the scanner's public,
# OWASP-style VulnClass name. Documented here, not in the scanner, which must not read either
# file this maps between.
CLASS_MAP: dict[str, str] = {
    "SQL_INJECTION": "sql_injection",
    "XSS_REFLECTED": "reflected_xss",
    # known gap: our reflected_xss check tests same-request reflection only, not a stored
    # round-trip (set a value, then view it on a different page); see Limitations.
    "XSS_STORED": "reflected_xss",
    "BROKEN_OBJECT_AUTHORIZATION": "broken_object_authorization",
    "MISSING_AUTHENTICATION": "missing_authentication",
    "DEBUG_EXPOSURE": "debug_exposure",
    "HARDCODED_SECRET": "sensitive_file_exposure",
    "NO_RATE_LIMITING": "missing_rate_limit",
    "INSECURE_HEADERS_COOKIES": "security_headers_and_cookies",
    "PERMISSIVE_CORS": "permissive_cors",
    "VERBOSE_ERRORS": "verbose_errors",
    "WEAK_UPLOAD_VALIDATION": "weak_upload_validation",
}
_ID_SEGMENT = re.compile(r"/(?:\d+|:[A-Za-z_]+|\{[A-Za-z_]+\})(?=/|$)")

# A small, fixed set of vuln classes whose real-world root cause is typically one piece of
# global middleware/config, not a single endpoint (missing security headers, permissive CORS):
# a confirmed instance ANYWHERE in the app is evidence of the same planted weakness, even if the
# scanner happened to observe it at a different URL than PLANTED.json's one exemplar endpoint.
# A scoring-side judgment call (see docs/DECISIONS.md), not something PLANTED.json declares.
APPLICATION_WIDE_CLASSES: frozenset[str] = frozenset({
    "security_headers_and_cookies", "permissive_cors",
})


def normalize_endpoint(path: str) -> str:
    """Strip the query string and trailing slash, lower-case, and fold any id-shaped segment
    (numeric, Express `:id`, or our own `{id}`) to the same `{id}` placeholder."""
    bare = path.split("?", 1)[0].rstrip("/") or "/"
    return _ID_SEGMENT.sub("/{id}", bare.lower())


def load_planted(lab: str, labs_root: Path = LABS_ROOT) -> PlantedManifest:
    return PlantedManifest.model_validate_json(
        (labs_root / lab / "PLANTED.json").read_text(encoding="utf-8"))


@dataclass
class ScoreResult:
    lab: str
    manifest_lab: str
    matched: dict[str, str]  # planted weakness id -> finding (candidate) id
    planted_found: list[str]
    planted_missed: list[str]
    unmatched_confirmed: list[dict[str, Any]]  # for MANUAL review; never auto false positives
    needs_validation: int
    rejected: int
    per_class: dict[str, dict[str, Any]]
    overall: dict[str, Any]


def _endpoints_match(candidate: dict[str, Any], want_endpoint: str, want_method: str) -> bool:
    if want_method != "ANY" and candidate["method"] != want_method:
        return False
    return any(normalize_endpoint(e) == want_endpoint for e in candidate["endpoints"])


def _find_match(confirmed: list[dict[str, Any]], used: set[str], want_class: str,
                want_endpoint: str, want_method: str) -> dict[str, Any] | None:
    """A confirmed finding matching one planted weakness: by class + endpoint + method, except
    for APPLICATION_WIDE_CLASSES, which match by class alone (see the constant's docstring)."""
    if want_class in APPLICATION_WIDE_CLASSES:
        return next((f for f in confirmed if f["candidate"]["id"] not in used
                    and f["candidate"]["vuln_class"] == want_class), None)
    return next((f for f in confirmed if f["candidate"]["id"] not in used
                and f["candidate"]["vuln_class"] == want_class
                and _endpoints_match(f["candidate"], want_endpoint, want_method)), None)


def score(lab: str, findings: list[dict[str, Any]], labs_root: Path = LABS_ROOT) -> ScoreResult:
    """`findings` is `report["findings"]` from a scan report.json (list of serialized Finding)."""
    manifest = load_planted(lab, labs_root)
    confirmed = [f for f in findings if f["verification"]["state"] == "confirmed"]
    matched: dict[str, str] = {}
    used: set[str] = set()
    for w in manifest.weaknesses:
        want_class = CLASS_MAP[w.vuln_class]
        hit = _find_match(confirmed, used, want_class, normalize_endpoint(w.endpoint), w.method)
        if hit is not None:
            matched[w.id] = hit["candidate"]["id"]
            used.add(hit["candidate"]["id"])
    all_ids = sorted(w.id for w in manifest.weaknesses)
    planted_found = sorted(matched)
    planted_missed = sorted(set(all_ids) - set(matched))
    unmatched_confirmed = [
        {"finding_id": f["candidate"]["id"], "vuln_class": f["candidate"]["vuln_class"],
         "method": f["candidate"]["method"], "endpoint": f["candidate"]["endpoint"],
         "summary": f["candidate"]["summary"]}
        for f in confirmed if f["candidate"]["id"] not in used]
    per_class: dict[str, dict[str, Any]] = {}
    for cls in sorted({w.vuln_class for w in manifest.weaknesses}):
        ids = [w.id for w in manifest.weaknesses if w.vuln_class == cls]
        found = [i for i in ids if i in matched]
        per_class[cls] = rate(f"recall_{cls}", len(found), len(ids)).as_dict()
    overall = rate("recall_overall", len(planted_found), len(all_ids)).as_dict()
    return ScoreResult(
        lab=lab, manifest_lab=manifest.lab, matched=matched, planted_found=planted_found,
        planted_missed=planted_missed, unmatched_confirmed=unmatched_confirmed,
        needs_validation=sum(f["verification"]["state"] == "needs_validation" for f in findings),
        rejected=sum(f["verification"]["state"] == "rejected" for f in findings),
        per_class=per_class, overall=overall)


@dataclass
class CleanCopyResult:
    lab: str
    false_findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def false_findings_count(self) -> int:
        return len(self.false_findings)


def clean_copy_check(lab: str, findings_from_fixed_copy: list[dict[str, Any]],
                     labs_root: Path = LABS_ROOT) -> CleanCopyResult:
    """Which SPECIFIC planted weaknesses (same vuln_class, endpoint and method as a planted
    item - the same rule `score()` uses) still reproduce, CONFIRMED, on the hand-fixed reference
    copy. Should be 0; any hit is reported, not silently dropped.

    This matches each finding to a specific planted item, not merely to its class: a confirmed
    finding of the same class at an UNRELATED endpoint (e.g. a page that was always meant to be
    public) is not itself evidence that a fix failed, and is not counted here."""
    manifest = load_planted(lab, labs_root)
    confirmed = [f for f in findings_from_fixed_copy if f["verification"]["state"] == "confirmed"]
    false_findings: list[dict[str, Any]] = []
    for w in manifest.weaknesses:
        want_class = CLASS_MAP[w.vuln_class]
        hit = _find_match(confirmed, set(), want_class, normalize_endpoint(w.endpoint), w.method)
        if hit is not None:
            false_findings.append({"planted_id": w.id, "finding_id": hit["candidate"]["id"],
                                   "vuln_class": hit["candidate"]["vuln_class"],
                                   "method": hit["candidate"]["method"],
                                   "endpoint": hit["candidate"]["endpoint"],
                                   "summary": hit["candidate"]["summary"]})
    return CleanCopyResult(lab=lab, false_findings=false_findings)


def budget_usage(requests_used: int, request_budget: int) -> dict[str, Any]:
    return rate("requests_vs_budget", requests_used, request_budget).as_dict()
