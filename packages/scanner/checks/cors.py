"""permissive_cors: send a throwaway synthetic Origin and observe whether it is reflected back
with credentials allowed. The probe origin is never a real, resolvable domain and no request is
ever sent to it - it is only a header value on a request to the IN-SCOPE target."""

from __future__ import annotations

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate
from .base import CheckSpec, candidate_id, excerpt, severity_for

SPEC = CheckSpec(
    id="permissive_cors",
    vuln_class=VulnClass.PERMISSIVE_CORS,
    owasp_category="A05:2021 Security Misconfiguration",
    preconditions="the start page or a discovered API endpoint answers GET",
    safe_strategy="send a synthetic, non-resolving Origin header and read the CORS headers back",
)
PROBE_ORIGIN = "http://sentinelx-cors-probe.invalid"


def applicable(ctx: ScanContext) -> list[str]:
    return list(dict.fromkeys([ctx.personas_file.start_path,
                              *(h.path for h in ctx.paths.api_hints if h.path in
                                {t for _, t in ctx.inventory})]))


def run(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []
    for path in applicable(ctx):
        probe = ctx.get("anonymous", path, headers={"Origin": PROBE_ORIGIN})
        if not probe.allowed:
            continue
        allow_origin = probe.headers.get("access-control-allow-origin")
        allow_creds = probe.headers.get("access-control-allow-credentials", "").lower()
        if allow_origin == PROBE_ORIGIN and allow_creds == "true":
            out.append(Candidate(
                id=candidate_id(SPEC.id), check_id=SPEC.id, vuln_class=SPEC.vuln_class,
                severity=severity_for(SPEC.vuln_class), confidence="high", method="GET",
                endpoint=path, endpoints=[path], persona="anonymous",
                summary="The synthetic probe origin was reflected in Access-Control-Allow-Origin "
                        "together with Access-Control-Allow-Credentials: true.",
                evidence_event_ids=[e for e in [probe.event_id] if e],
                excerpt=excerpt(f"Access-Control-Allow-Origin: {allow_origin}"),
                proof={"path": path, "probe_origin": PROBE_ORIGIN}))
            break  # one confirmed instance is enough; the policy is site-wide in both labs
    return out
