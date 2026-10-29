"""weak_upload_validation (LAB only, declared state-changing): upload a harmless, inert text
file named with a double extension and a mismatched content type to a discovered file-upload
form, as persona A. Confirm only if it is accepted AND later reachable by an ordinary,
unauthenticated visitor. The uploaded file is left in place; cleanup is the lab reset, never a
delete through the app."""

from __future__ import annotations

import os
import re

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate
from .base import CheckSpec, candidate_id, excerpt, severity_for

SPEC = CheckSpec(
    id="weak_upload_validation", vuln_class=VulnClass.WEAK_UPLOAD_VALIDATION,
    owasp_category="A04:2021 Insecure Design",
    preconditions="a lab target with a file-upload form and a declared, state-changing profile",
    safe_strategy="upload one harmless inert text file (double extension, mismatched content "
                  "type) as a synthetic persona, then check whether an unauthenticated visitor "
                  "can later fetch it back")
FILENAME = "sentinelx_probe.txt.png"
CONTENT = (b"Sentinel X Site Guard: harmless, inert test file. No executable content. "
          b"This file is left in place; the lab reset removes it.\n")
CLAIMED_CONTENT_TYPE = "image/png"  # mismatched on purpose: the content above is plain text
LINK_RE = re.compile(r'(?:href|src)="([^"]*sentinelx_probe[^"]*)"', re.IGNORECASE)


def _multipart(file_field: str, filename: str, content: bytes, content_type: str
              ) -> tuple[bytes, str]:
    boundary = "----sentinelx" + os.urandom(12).hex()
    head = (f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
           f'filename="{filename}"\r\nContent-Type: {content_type}\r\n\r\n').encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + content + tail, f"multipart/form-data; boundary={boundary}"


def run(ctx: ScanContext) -> list[Candidate]:
    if not (ctx.profile.state_changing and ctx.target.lab):
        return []
    forms = [(template, form) for (method, template), ep in ctx.inventory.items()
             if method == "POST" for form in ep.forms if form.has_file]
    if not forms:
        return []
    account_persona = next((p for p in ctx.personas_file.personas if p.credentials), None)
    if account_persona is None or account_persona.credentials is None:
        return []
    persona, username = account_persona.name, account_persona.credentials.username
    out: list[Candidate] = []
    seen: set[str] = set()
    for template, form in forms:
        if template in seen:
            continue
        seen.add(template)
        file_field = form.fields[0] if form.fields else "file"
        body, content_type = _multipart(file_field, FILENAME, CONTENT, CLAIMED_CONTENT_TYPE)
        upload = ctx.call(persona, "POST", template, body=body,
                          headers={"Content-Type": content_type},
                          reason="inert test-file upload by a synthetic persona (lab only)",
                          account=username)
        if not upload.allowed or upload.status not in {200, 201}:
            continue
        candidate_link = next(iter(LINK_RE.findall(upload.text)), None)
        reachable = None
        if candidate_link:
            check = ctx.get("anonymous", candidate_link if candidate_link.startswith("/")
                           else "/" + candidate_link)
            if check.allowed and check.status == 200:
                reachable = candidate_link
        if reachable:
            out.append(Candidate(
                id=candidate_id(SPEC.id), check_id=SPEC.id, vuln_class=SPEC.vuln_class,
                severity=severity_for(SPEC.vuln_class), confidence="high", method="POST",
                endpoint=template, endpoints=[template], persona=persona,
                summary=f"An inert file with a double extension ({FILENAME}) and a mismatched "
                        f"content type was accepted at {template} and is now reachable by an "
                        f"unauthenticated visitor at {reachable}.",
                evidence_event_ids=[e for e in [upload.event_id] if e],
                excerpt=excerpt(upload.text),
                proof={"template": template, "filename": FILENAME, "served_at": reachable,
                      "persona": persona}))
    return out
