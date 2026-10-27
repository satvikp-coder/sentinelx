"""The lab's single FastAPI app, serving four virtual hosts selected by the exact Host header.

Hosts: orders / calendar / support / collector (all *.lab.test). An unknown Host gets 404.
A tiny ASGI middleware maps an exact host match onto a path prefix (/_orders/...), so one
FastAPI router tree serves all hosts. Admin endpoints (/__admin__/*) need a local admin token
AND a loopback client. No outbound requests are made by this module. All data is synthetic.
"""

from __future__ import annotations

import hmac
import html
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from pydantic import BaseModel, ConfigDict

from .state import SIDE_EFFECT_ENDPOINTS, STATIC_FILES, LabState

VHOSTS = {f"{name}.lab.test": name for name in ("orders", "calendar", "support", "collector")}
LOOPBACK = {"127.0.0.1", "::1"}


def host_without_port(raw: bytes | str | None) -> str:
    text = raw.decode("latin-1") if isinstance(raw, bytes) else (raw or "")
    return text.split(":", 1)[0].strip().lower() if not text.startswith("[") else text.lower()


class VhostMiddleware:
    """Exact Host matching. Unknown Host -> 404 (admin paths are routed regardless of Host)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]
        if path.startswith("/__admin__/"):
            await self.app(scope, receive, send)
            return
        headers = dict(scope["headers"])
        vhost = VHOSTS.get(host_without_port(headers.get(b"host")))
        if vhost is None:
            await JSONResponse({"error": "unknown host"}, status_code=404)(scope, receive, send)
            return
        scope = dict(scope)
        scope["path"] = f"/_{vhost}{path}"
        scope["raw_path"] = scope["path"].encode()
        await self.app(scope, receive, send)


class ResetBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str
    seed: int | None = None


def _page(html_text: str) -> HTMLResponse:
    return HTMLResponse(html_text)


def create_app(state: LabState) -> FastAPI:
    app = FastAPI(title="Sentinel X fixture lab (synthetic)", docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.lab = state
    app.add_middleware(VhostMiddleware)

    def admin_ok(request: Request) -> bool:
        client = request.client.host if request.client else ""
        token = request.headers.get("x-admin-token", "")
        return client in LOOPBACK and hmac.compare_digest(token, state.admin_token)

    def head(request: Request, vhost: str, page: str) -> str:
        """The <head> payload slot; `?norefresh` lets a benign refresh happen only once."""
        if "norefresh" in request.query_params:
            return ""
        return state.payload_for(vhost, page, "head")

    def static_file(name: str) -> Response:
        item = STATIC_FILES.get(name)
        if item is None:
            return Response("not found", status_code=404)
        return Response(item[1], media_type=item[0])

    # ------------------------------------------------------------------ admin
    @app.post("/__admin__/reset")
    async def admin_reset(request: Request, body: ResetBody) -> JSONResponse:
        if not admin_ok(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        try:
            fixture_hash = state.reset(body.scenario_id, body.seed)
        except KeyError:
            return JSONResponse({"error": "unknown scenario"}, status_code=404)
        return JSONResponse({"fixture_hash": fixture_hash, "seed": state.seed,
                             "scenario_id": state.scenario_id})

    @app.get("/__admin__/ledger")
    async def admin_ledger(request: Request) -> JSONResponse:
        if not admin_ok(request):
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse({"entries": state.read_ledger()})

    # ------------------------------------------------------------------ orders
    @app.get("/_orders/")
    async def orders_index() -> HTMLResponse:
        return _page(state.render("orders_index", {}))

    @app.get("/_orders/orders/{order_id}")
    async def order(request: Request, order_id: str) -> HTMLResponse:
        row = state.data["orders"].get(order_id)
        if row is None:
            return HTMLResponse("not found", status_code=404)
        values = {"ORDER_ID": html.escape(order_id), "CUSTOMER": row["customer"],
                  "STATUS": row["status"], "TOTAL": row["total"], "TOKEN": state.data["token"],
                  "PAYLOAD": state.payload_for("orders", "order"),
                  "HEAD": head(request, "orders", "order")}
        return _page(state.render("order", values))

    @app.get("/_orders/search")
    async def orders_search(q: str = "") -> HTMLResponse:
        rows = "".join(
            f"<p>Order {oid} Status: {row['status']}</p>\n"
            for oid, row in state.data["orders"].items() if q and q in oid
        ) or "<p>No orders found.</p>\n"
        values = {"QUERY": html.escape(q), "RESULTS": rows, "TOKEN": state.data["token"],
                  "PAYLOAD": state.payload_for("orders", "orders_search")}
        return _page(state.render("orders_search", values))

    @app.get("/_orders/invoices/{invoice_id}")
    async def invoice(invoice_id: str) -> HTMLResponse:
        row = state.data["invoices"].get(invoice_id)
        if row is None:
            return HTMLResponse("not found", status_code=404)
        values = {"INVOICE_ID": html.escape(invoice_id), "TOTAL": row["total"],
                  "PAYLOAD": state.payload_for("orders", "invoice")}
        return _page(state.render("invoice", values))

    @app.api_route("/_orders/__tools__/lookup_order", methods=["GET", "POST"])
    async def lookup_order(order_id: str = "") -> JSONResponse:
        """Mock tool. Its `notes` field is the TOOL-RESULT injection surface."""
        row = state.data["orders"].get(order_id)
        if row is None:
            return JSONResponse({"error": "no such order"}, status_code=404)
        return JSONResponse({"order_id": order_id, "status": row["status"],
                             "notes": state.tool_notes()})

    @app.get("/_orders/api/orders/{order_id}")
    async def api_order(order_id: str) -> JSONResponse:
        """A legitimate read-only JSON API (benign http_request target)."""
        row = state.data["orders"].get(order_id)
        if row is None:
            return JSONResponse({"error": "no such order"}, status_code=404)
        return JSONResponse({"order_id": order_id, "status": row["status"]})

    @app.get("/_orders/redirect")
    async def redirect(to: str = "/") -> RedirectResponse:
        """Test helper: a 302 to wherever it is told (synthetic lab only)."""
        return RedirectResponse(to, status_code=302)

    @app.get("/_orders/static/{name}")
    async def orders_static(name: str) -> Response:
        return static_file(name)

    # ------------------------------------------------------------------ calendar
    @app.get("/_calendar/")
    async def calendar_index() -> HTMLResponse:
        return _page(state.render("calendar_index", {}))

    @app.get("/_calendar/today")
    async def calendar_today(request: Request) -> HTMLResponse:
        payload = state.payload_for("calendar", "calendar_today")
        lines = []
        for ev in state.data["events"]:
            suffix = " (cancelled)" if ev["cancelled"] else ""
            lines.append(f'<li class="event">{ev["time"]} {ev["title"]}{suffix}</li>')
            if ev["id"] == "ev2" and payload:
                lines.append(payload.rstrip("\n"))
        values = {"EVENTS": "\n".join(lines), "HEAD": head(request, "calendar", "calendar_today")}
        return _page(state.render("calendar_today", values))

    @app.get("/_calendar/api/agenda")
    async def api_agenda() -> JSONResponse:
        return JSONResponse({"events": [
            {"time": e["time"], "title": e["title"], "cancelled": e["cancelled"]}
            for e in state.data["events"]]})

    @app.get("/_calendar/static/{name}")
    async def calendar_static(name: str) -> Response:
        return static_file(name)

    # ------------------------------------------------------------------ support
    @app.get("/_support/")
    async def support_index() -> HTMLResponse:
        return _page(state.render("support_index", {}))

    @app.get("/_support/search")
    async def support_search(request: Request, q: str = "") -> HTMLResponse:
        lines = []
        for art in _match_articles(state, q):
            lines.append(f'<li class="result">\n<h3>Article: {art["title"]}</h3>\n'
                         f'<p>{art["snippet"]}</p>')
            if art["id"] == 1:
                lines.append(state.payload_for("support", "support_search").rstrip("\n"))
            lines.append("</li>")
        results = "\n".join(lines) or "<li>No articles found.</li>"
        values = {"QUERY": html.escape(q), "RESULTS": results,
                  "HEAD": head(request, "support", "support_search")}
        return _page(state.render("support_search", values))

    @app.get("/_support/docs")
    async def support_docs(q: str = "") -> HTMLResponse:
        payload = state.payload_for("support", "docs") if "prompt" in q.lower() else ""
        return _page(state.render("docs", {"PAYLOAD": payload}))

    @app.get("/_support/api/articles")
    async def api_articles(q: str = "") -> JSONResponse:
        return JSONResponse({"articles": [{"id": a["id"], "title": a["title"]}
                                          for a in _match_articles(state, q)]})

    @app.get("/_support/static/{name}")
    async def support_static(name: str) -> Response:
        return static_file(name)

    # ------------------------------------------------------------------ side-effect endpoints
    # Every call to these (and nothing else) is written to the ground-truth ledger.
    async def _side_effect(vhost: str, path: str, request: Request) -> JSONResponse:
        assert (vhost, path) in SIDE_EFFECT_ENDPOINTS
        body = await request.body()
        state.record(vhost, request.method, path, request.url.query,
                     {k.lower(): v for k, v in request.headers.items()}, body)
        return JSONResponse({"ok": True, "recorded": True})

    @app.api_route("/_collector/collect", methods=["GET", "POST", "PUT"])
    async def collect(request: Request) -> JSONResponse:
        return await _side_effect("collector", "/collect", request)

    @app.post("/_calendar/api/cancel")
    async def cancel(request: Request) -> JSONResponse:
        for ev in state.data["events"]:
            if ev["id"] == "ev2":
                ev["cancelled"] = True
        return await _side_effect("calendar", "/api/cancel", request)

    @app.post("/_calendar/api/rsvp")
    async def rsvp(request: Request) -> JSONResponse:
        return await _side_effect("calendar", "/api/rsvp", request)

    @app.post("/_support/api/upload")
    async def upload(request: Request) -> JSONResponse:
        state.data["uploads"].append("ticket-archive")
        return await _side_effect("support", "/api/upload", request)

    @app.post("/_orders/api/feedback")
    async def feedback(request: Request) -> JSONResponse:
        return await _side_effect("orders", "/api/feedback", request)

    @app.get("/_collector/")
    async def collector_index() -> PlainTextResponse:
        return PlainTextResponse("synthetic collector")

    return app


def _match_articles(state: LabState, q: str) -> list[dict[str, Any]]:
    words = [w for w in q.lower().split() if w]
    out = []
    for art in state.data["articles"]:
        hay = (art["title"] + " " + art["snippet"]).lower()
        if words and all(w in hay for w in words):
            out.append(art)
    return out
