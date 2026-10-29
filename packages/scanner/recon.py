"""Recon: crawl as each persona (GET only, in scope), safe discovery of conventional paths, and a
structured endpoint inventory. All requests go through the ScanContext (-> GuardedClient)."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from .context import ScanContext
from .models import Endpoint, FormInfo, PathHint

SKIP_PATH = re.compile(r"logout|signout|delete|remove", re.IGNORECASE)
API_LITERAL = re.compile(r"""['"`](/(?:api|v\d)/[A-Za-z0-9_\-./]*)""")
ID_SEGMENT = re.compile(r"/\d+(?=/|$)")


def template_of(path: str) -> str:
    return ID_SEGMENT.sub("/{id}", path) or "/"


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script = True
        elif tag == "form":
            self._form = {"method": a.get("method", "get").upper(), "action": a.get("action", ""),
                          "fields": [], "file": False}
            self.forms.append(self._form)
        elif tag in {"input", "textarea", "select"} and self._form is not None and a.get("name"):
            self._form["fields"].append(a["name"])
            if a.get("type") == "file":
                self._form["file"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.inline_scripts.append(data)


def _record(ctx: ScanContext, persona: str, method: str, url: str, status: int,
            ctype: str, *, params: list[str] | None = None, forms: list[FormInfo] | None = None,
            cookies: list[str] | None = None) -> None:
    parts = urlsplit(url)
    tmpl = template_of(parts.path)
    ep = ctx.inventory.get((method, tmpl)) or Endpoint(method=method, template=tmpl)
    names = {k for k, _ in parse_qsl(parts.query, keep_blank_values=True)} | set(params or [])
    ep = ep.model_copy(update={
        "params": sorted(set(ep.params) | names),
        "forms": [*ep.forms, *[f for f in (forms or []) if f not in ep.forms]],
        "content_types": sorted(set(ep.content_types) | ({ctype} if ctype else set())),
        "statuses": {**ep.statuses, persona: status},
        "cookies": sorted(set(ep.cookies) | set(cookies or [])),
        "samples": {**ep.samples, persona: sorted(
            set(ep.samples.get(persona, [])) | {parts.path + (f"?{parts.query}" if parts.query
                                                              else "")})}})
    ctx.inventory[(method, tmpl)] = ep


def expand_collections(ctx: ScanContext, persona: str, path: str, body: str) -> None:
    """A JSON list of objects with ids implies member endpoints (`<path>/<id>`)."""
    try:
        doc = json.loads(body)
    except ValueError:
        return
    lists: list[Any] = [doc] if isinstance(doc, list) else [v for v in (
        doc.values() if isinstance(doc, dict) else []) if isinstance(v, list)]
    for items in lists:
        for item in items[:20]:
            if isinstance(item, dict) and isinstance(item.get("id"), int):
                member = f"{path.rstrip('/')}/{item['id']}"
                _record(ctx, persona, "GET", ctx.base_url + member, 200, "application/json")


def crawl(ctx: ScanContext, persona: str) -> int:
    """Breadth-first GET crawl from the start path as `persona`. Returns pages fetched."""
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(ctx.personas_file.start_path, 0)]
    fetched = 0
    while queue and fetched < ctx.profile.max_pages:
        path, depth = queue.pop(0)
        if path in seen or SKIP_PATH.search(urlsplit(path).path):
            continue
        seen.add(path)
        out = ctx.get(persona, path)
        fetched += 1
        if not out.allowed:
            continue
        ctype = out.headers.get("content-type", "").split(";")[0]
        cookie_names = [c.split("=", 1)[0] for c in out.set_cookies]
        parser = PageParser()
        forms: list[FormInfo] = []
        if "html" in ctype:
            parser.feed(out.text)
            for f in parser.forms:
                forms.append(FormInfo(method=f["method"], action=urlsplit(
                    urljoin(path, f["action"] or path)).path, fields=f["fields"],
                    has_file=f["file"]))
        _record(ctx, persona, "GET", ctx.base_url + path, out.status or 0, ctype,
                forms=forms, cookies=cookie_names)
        for f in forms:
            _record(ctx, persona, f.method, ctx.base_url + f.action, 0, "", params=f.fields,
                    forms=[f])
        if "json" in ctype:
            expand_collections(ctx, persona, urlsplit(path).path, out.text)
        literals: list[str] = []
        for src in parser.scripts:
            s_out = ctx.get(persona, urljoin(path, src))
            if s_out.allowed and s_out.status == 200:
                ctx.scripts[urljoin(path, src)] = s_out.text
                literals += API_LITERAL.findall(s_out.text)
        for code in parser.inline_scripts:
            literals += API_LITERAL.findall(code)
        for lit in dict.fromkeys(literals):
            if lit in seen:
                continue
            seen.add(lit)
            fetched += 1
            if fetched >= ctx.profile.max_pages:
                break
            lit_out = ctx.get(persona, lit)  # actually fetch it: a literal with no real
            if not lit_out.allowed:          # request behind it would give checks no sample
                continue
            lit_ctype = lit_out.headers.get("content-type", "").split(";")[0]
            _record(ctx, persona, "GET", ctx.base_url + lit, lit_out.status or 0, lit_ctype)
            if "json" in lit_ctype:
                expand_collections(ctx, persona, lit, lit_out.text)
        if depth < ctx.profile.max_depth:
            for href in parser.links:
                target = urljoin(path, href)
                parts = urlsplit(target)
                in_scope = not parts.netloc or parts.netloc == ctx.netloc
                if parts.scheme in {"", "http"} and in_scope:
                    queue.append((parts.path + (f"?{parts.query}" if parts.query else ""),
                                  depth + 1))
    return fetched


def discover(ctx: ScanContext, persona: str) -> None:
    """GET-only look at conventional paths as an ordinary visitor/user."""
    baseline = ctx.get(persona, "/sentinelx-nonexistent-9f3a1c")
    ctx.soft404 = (baseline.status, len(baseline.body)) if baseline.allowed else None
    for path in [*ctx.paths.exposure_paths, *ctx.paths.admin_paths]:
        out = ctx.get(persona, path)
        if out.allowed:
            ctype = out.headers.get("content-type", "").split(";")[0]
            hit = is_real_hit(ctx, out.status, len(out.body))
            ctx.discovery.setdefault(path, {})[persona] = {
                "status": out.status, "length": len(out.body), "content_type": ctype,
                "event_id": out.event_id, "real_hit": hit, "body": out.text[:2000]}
            if hit and out.status == 200:
                _record(ctx, persona, "GET", ctx.base_url + path, 200, ctype)
    probe_api_hints(ctx, persona)


def probe_api_hints(ctx: ScanContext, persona: str) -> None:
    """Seed the inventory with the conventional API endpoints from paths.yaml, AS `persona` -
    an authenticated persona gets a real, usable sample even where an anonymous visitor would
    just see a login-required response."""
    for hint in ctx.paths.api_hints:
        _hint(ctx, persona, hint)


def _hint(ctx: ScanContext, persona: str, hint: PathHint) -> None:
    url = hint.path + ("?" + "&".join(f"{p}=test" for p in hint.params) if hint.params else "")
    out = ctx.get(persona, url)
    if out.allowed:  # record it even on e.g. 401: other checks still need the parameter shape
        ctype = out.headers.get("content-type", "").split(";")[0]
        _record(ctx, persona, "GET", ctx.base_url + url, out.status or 0, ctype,
                params=hint.params)
        if out.status == 200 and "json" in ctype:
            expand_collections(ctx, persona, hint.path, out.text)


def is_real_hit(ctx: ScanContext, status: int | None, length: int) -> bool:
    """True if `status`/`length` differ from the lab's own 404-for-anything response (soft-404)."""
    if status != 200:
        return status is not None and 200 <= status < 300
    if ctx.soft404 is None:
        return True
    soft_status, soft_len = ctx.soft404
    return not (status == soft_status and abs(length - soft_len) < 16)
