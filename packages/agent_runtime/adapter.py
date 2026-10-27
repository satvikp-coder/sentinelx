"""Playwright (Chromium, headless, async) execution adapter behind the sandbox boundary.

Every browser request (navigations, subresources, form posts, each redirect hop) passes through
``context.route``. Two boundaries apply:

* SANDBOX (both arms): anything outside ``*.lab.test:<lab port>`` is aborted -> SANDBOX_BLOCKED.
* PAGE-EGRESS POLICY (protected arm only): the runner supplies ``page_policy``, a callable backed
  by ``sentinelx.policy.evaluate_page_request``; every request, including redirect hops, must
  pass the scenario's exact allowed-host rules or it is aborted -> EGRESS_BLOCKED.

Raw HTTP / mock-tool calls go through httpx to 127.0.0.1 only AFTER the same sandbox check. The
adapter never decides whether an ACTION may run; the runner calls it only after the arm's rules
say so.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter
from collections.abc import Callable
from types import TracebackType
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from sentinelx.common_schemas import ActionRequest, Decision

from .sandbox import SandboxBoundary
from .types import ActionOutcome

EventCallback = Callable[[str, dict[str, Any]], None]
# (url, resource_type, method, redirect source url | None) -> PolicyDecision-like object
PagePolicy = Callable[[str, str, str, str | None], Any]
MAX_TEXT = 20_000
MAX_HOPS = 5
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
# Defence in depth for Chromium itself: resolve *.lab.test to loopback, everything else NXDOMAIN.
RESOLVER_RULES = "MAP *.lab.test 127.0.0.1, MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
LAUNCH_ARGS = [
    f"--host-resolver-rules={RESOLVER_RULES}",
    "--disable-extensions", "--disable-sync", "--disable-background-networking",
    "--disable-component-update", "--disable-default-apps", "--no-first-run", "--no-pings",
    "--mute-audio",
]
_FIELD_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def clean_text(raw: str) -> str:
    lines = (" ".join(line.split()) for line in raw.splitlines())
    return "\n".join(line for line in lines if line)[:MAX_TEXT]


class BrowserAdapter:
    policy_abort_code = "aborted"  # how a policy-blocked request is cancelled in the browser

    def __init__(
        self,
        lab_port: int,
        on_event: EventCallback,
        page_policy: PagePolicy | None = None,
        op_timeout: float = 8.0,
        headless: bool = True,
    ) -> None:
        self.lab_port = lab_port
        self.sandbox = SandboxBoundary(lab_port)
        self._emit = on_event
        self._page_policy = page_policy  # None => unprotected arm: sandbox boundary only
        self.op_timeout = op_timeout
        self.headless = headless
        self._pw: Any = None
        self._pw_manager: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._http: httpx.AsyncClient | None = None
        self._blocked_count = 0
        self._egress_blocked = 0
        self._passed_by_type: Counter[str] = Counter()
        self._passed_by_host: Counter[str] = Counter()

    # ------------------------------------------------------------------ lifecycle
    async def __aenter__(self) -> BrowserAdapter:
        from playwright.async_api import async_playwright

        self._pw_manager = async_playwright()
        try:
            self._pw = await self._pw_manager.start()
            self._browser = await self._pw.chromium.launch(headless=self.headless,
                                                           args=LAUNCH_ARGS)
            self._context = await self._browser.new_context(
                accept_downloads=False, service_workers="block", permissions=[],
                java_script_enabled=True,
            )
            self._context.set_default_timeout(self.op_timeout * 1000)
            self._context.set_default_navigation_timeout(self.op_timeout * 1000)
            await self._context.route("**/*", self._route)
            try:  # WebSockets are not HTTP routes; close them all (see _route_ws)
                await self._context.route_web_socket("**/*", self._route_ws)
            except AttributeError:  # pragma: no cover - very old Playwright
                pass
            self._context.on("page", self._on_new_page)
            self._page = await self._context.new_page()
            self._http = httpx.AsyncClient(timeout=self.op_timeout, follow_redirects=False)
        except BaseException:
            await self.aclose()
            raise
        return self

    async def __aexit__(self, *exc: tuple[type[BaseException], BaseException, TracebackType] | Any
                        ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        for closer in (self._http, self._context, self._browser):
            if closer is None:
                continue
            try:
                await asyncio.wait_for(closer.aclose() if closer is self._http else closer.close(),
                                       10)
            except Exception:  # noqa: S110 - best-effort cleanup, never mask the real error
                pass
        # Stop the driver even if we were cancelled before start() returned (the manager owns
        # the Node driver process); otherwise a cancel during start-up leaks that process.
        stopper = self._pw.stop if self._pw is not None else getattr(self._pw_manager, "stop", None)
        if stopper is not None:
            try:
                await asyncio.wait_for(stopper(), 10)
            except Exception:  # noqa: S110
                pass
        self._http = self._context = self._browser = self._pw = self._page = None
        self._pw_manager = None

    @property
    def current_url(self) -> str | None:
        url = self._page.url if self._page is not None else None
        return url if url and url.startswith(("http://", "https://")) else None

    # ------------------------------------------------------------------ sandbox routing
    async def _route(self, route: Any, request: Any) -> None:
        """Fail closed: any error while serving a request aborts it (never continues it)."""
        try:
            await self._serve(route, request)
        except Exception:
            try:  # e.g. the page/context was closed mid-request during shutdown
                await route.abort("blockedbyclient")
            except Exception:  # noqa: S110 - already closed, nothing left to abort
                pass

    async def _serve(self, route: Any, request: Any) -> None:
        """Serve every browser request ourselves, hop by hop, with redirects OFF.

        Verified empirically: Playwright does NOT call a route handler for the target of a
        redirect (neither after continue_() nor after fulfilling a 3xx), so a browser-followed
        redirect would bypass the sandbox. We therefore follow redirects here, applying the
        sandbox check to every hop and, in the protected arm, check_redirect() as well.
        """
        url: str = request.url
        method: str = request.method
        body = request.post_data_buffer
        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in {"host", "content-length"}}
        source: str | None = None
        for hop in range(MAX_HOPS + 1):
            ok, reason = self.sandbox.check(url)
            if not ok:
                self._blocked_count += 1
                self._emit("SANDBOX_BLOCKED", {
                    "url": url[:300], "reason": reason, "resource_type": request.resource_type,
                    "channel": "browser", "hop": hop, "boundary": "sandbox"})
                await route.abort("blockedbyclient")
                return
            if self._page_policy is not None:
                decision = self._page_policy(url, request.resource_type, method, source)
                if decision.effective_action is not Decision.ALLOW:
                    self._egress_blocked += 1
                    self._emit("EGRESS_BLOCKED", {
                        "url": url[:300], "source_url": (source or "")[:300],
                        "resource_type": request.resource_type, "method": method,
                        "channel": self._channel(request, hop), "hop": hop,
                        "reason": decision.reason_code, "rule_ids": decision.rule_ids,
                        "policy_version": decision.policy_version,
                        "boundary": "page_egress_policy"})
                    # "aborted" cancels the load without replacing the current document with an
                    # error page, so a blocked page-initiated navigation does not wreck the task
                    await route.abort(self.policy_abort_code)
                    return
            self._passed_by_type[request.resource_type] += 1
            self._passed_by_host[urlsplit(url).hostname or "?"] += 1
            parts = urlsplit(url)
            target = f"http://127.0.0.1:{self.lab_port}{parts.path or '/'}"
            if parts.query:
                target += "?" + parts.query
            response = await route.fetch(
                url=target, method=method, headers={**headers, "host": parts.netloc},
                post_data=body, max_redirects=0,
            )
            location = response.headers.get("location")
            if response.status not in REDIRECT_STATUSES or not location:
                await route.fulfill(response=response)
                return
            nxt = urljoin(url, location)
            if response.status == 303 or (response.status in {301, 302} and method == "POST"):
                method, body = "GET", None
            source, url = url, nxt
        self._blocked_count += 1
        self._emit("SANDBOX_BLOCKED", {"url": url[:300], "reason": "TOO_MANY_REDIRECTS",
                                       "channel": "browser", "hop": MAX_HOPS,
                                       "boundary": "sandbox"})
        await route.abort("blockedbyclient")

    @staticmethod
    def _channel(request: Any, hop: int) -> str:
        if hop > 0:
            return "redirect_hop"
        if request.resource_type == "document":
            try:
                if request.frame.parent_frame is not None:
                    return "iframe"
            except Exception:  # noqa: S110 - frame already gone
                pass
            return "form_submission" if request.method == "POST" else "main_frame"
        return "subresource"

    async def _route_ws(self, ws: Any) -> None:
        """No WebSocket is ever connected in the lab; every attempt is recorded and closed."""
        url = ws.url
        http_url = ("http" + url[2:]) if url.startswith("ws") else url  # ws->http, wss->https
        ok, reason = self.sandbox.check(http_url)
        if not ok:
            self._blocked_count += 1
            self._emit("SANDBOX_BLOCKED", {"url": url[:300], "reason": reason,
                                           "resource_type": "websocket", "channel": "websocket",
                                           "boundary": "sandbox"})
        else:
            decision = (self._page_policy(http_url, "websocket", "GET", None)
                        if self._page_policy is not None else None)
            if decision is not None and decision.effective_action is not Decision.ALLOW:
                self._egress_blocked += 1
                self._emit("EGRESS_BLOCKED", {
                    "url": url[:300], "resource_type": "websocket", "method": "GET",
                    "channel": "websocket", "hop": 0, "reason": decision.reason_code,
                    "rule_ids": decision.rule_ids, "policy_version": decision.policy_version,
                    "boundary": "page_egress_policy"})
            else:
                self._blocked_count += 1
                self._emit("SANDBOX_BLOCKED", {
                    "url": url[:300], "reason": "WEBSOCKET_UNSUPPORTED_IN_LAB",
                    "resource_type": "websocket", "channel": "websocket", "boundary": "sandbox"})
        await ws.close(code=1008, reason="blocked")

    def egress_summary(self) -> dict[str, Any]:
        """Aggregate counts (one event per run, not one per request)."""
        return {"passed_by_resource_type": dict(self._passed_by_type),
                "passed_by_host": dict(self._passed_by_host),
                "egress_blocked": self._egress_blocked,
                "sandbox_blocked": self._blocked_count}

    def _on_new_page(self, page: Any) -> None:
        if self._page is None:  # the first page is ours (this fires inside new_page())
            return
        if page is not self._page:
            self._emit("POPUP_BLOCKED", {"url": (page.url or "")[:300]})
            asyncio.ensure_future(page.close())

    # ------------------------------------------------------------------ execution
    async def execute(self, request: ActionRequest) -> ActionOutcome:
        """Run one action with a hard timeout. Never raises; failures become an outcome."""
        before = self._blocked_count
        try:
            outcome = await asyncio.wait_for(self._dispatch(request), self.op_timeout + 2)
        except TimeoutError:
            outcome = ActionOutcome(False, error="TIMEOUT")
        except Exception as exc:
            outcome = ActionOutcome(False, error=f"{type(exc).__name__}: {str(exc)[:160]}")
        outcome.sandbox_blocked = outcome.sandbox_blocked or self._blocked_count > before
        if outcome.final_url is None:
            outcome.final_url = self.current_url
        return outcome

    async def _dispatch(self, request: ActionRequest) -> ActionOutcome:
        args = request.arguments
        tool = request.tool
        if tool == "navigate":
            return await self._navigate(str(args.get("url", "")))
        if tool == "read_page":
            return await self._read_page()
        if tool == "click":
            return await self._click(str(args.get("selector", "")))
        if tool == "submit_form":
            return await self._submit_form(str(args.get("selector", "")),
                                           str(args.get("field_name", "")),
                                           str(args.get("field_value", "")))
        if tool == "http_request":
            return await self._http_request(str(args.get("method", "GET")),
                                            str(args.get("url", "")), args.get("body"))
        if tool == "tool_call":
            return await self._tool_call(str(args.get("name", "")),
                                         str(args.get("order_id", "")))
        return ActionOutcome(False, error=f"UNKNOWN_TOOL:{tool[:40]}")

    async def _page_text(self) -> str:
        # textContent: includes hidden (display:none) text, as a DOM-reading agent would see it
        raw = await self._page.evaluate("() => document.body ? document.body.textContent : ''")
        return clean_text(raw or "")

    async def _navigate(self, url: str) -> ActionOutcome:
        # Pre-flight: file:, data:, javascript: and friends may never reach page.route at all.
        ok, reason = self.sandbox.check(url)
        if not ok:
            self._blocked_count += 1
            self._emit("SANDBOX_BLOCKED", {"url": url[:300], "reason": reason,
                                           "channel": "navigate_preflight"})
            return ActionOutcome(False, error=f"SANDBOX_BLOCKED:{reason}", sandbox_blocked=True)
        resp = None
        for attempt in range(2):
            try:
                # Wait only for the response to COMMIT, then (briefly) for DOMContentLoaded and for
                # the network to settle. A page-initiated navigation that policy aborts (meta
                # refresh, auto-submitted form) can leave goto()'s own lifecycle wait pending
                # until the timeout, although the document is already there.
                resp = await self._page.goto(url, wait_until="commit")
                try:
                    await self._page.wait_for_load_state("domcontentloaded", timeout=1500)
                except Exception:  # noqa: S110 - the document is committed; proceed
                    pass
                break
            except Exception as exc:
                # After an aborted navigation Chromium may still be committing its error page;
                # that surfaces as "interrupted by another navigation". Retry once, then give up.
                if attempt == 0 and "interrupted by another navigation" in str(exc):
                    await asyncio.sleep(0.3)
                    continue
                raise
        await self._settle()
        return ActionOutcome(True, status=resp.status if resp else None, final_url=self._page.url)

    async def _read_page(self) -> ActionOutcome:
        if self.current_url is None:
            return ActionOutcome(False, error="NO_PAGE_LOADED")
        return ActionOutcome(True, text=await self._page_text(), final_url=self._page.url)

    async def _click(self, selector: str) -> ActionOutcome:
        if not selector:
            return ActionOutcome(False, error="EMPTY_SELECTOR")
        await self._page.click(selector, timeout=3000)
        try:
            await self._page.wait_for_load_state("load", timeout=3000)
        except Exception:  # noqa: S110 - no navigation happened; fine
            pass
        await self._settle()
        return ActionOutcome(True, final_url=self._page.url)

    async def _settle(self) -> None:
        """Wait for the network to go quiet so page-initiated requests (images, fetch, meta
        refresh, form auto-submit) have happened before the next action (deterministic runs)."""
        try:
            await self._page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:  # noqa: S110 - best effort; a busy page just proceeds
            pass

    async def _submit_form(self, selector: str, field: str, value: str) -> ActionOutcome:
        if not selector or not _FIELD_NAME.match(field):
            return ActionOutcome(False, error="BAD_FORM_ARGUMENTS")
        form = self._page.locator(selector)
        await form.locator(f'[name="{field}"]').fill(value, timeout=3000)
        async with self._page.expect_navigation(wait_until="load", timeout=self.op_timeout * 1000):
            await form.locator("button[type=submit], input[type=submit]").first.click(timeout=3000)
        await self._settle()
        return ActionOutcome(True, final_url=self._page.url)

    # -- raw HTTP and mock tools: sandbox-checked, then sent to 127.0.0.1 with the lab Host ------
    async def _http_request(self, method: str, url: str, body: Any) -> ActionOutcome:
        method = method.upper()
        if method not in {"GET", "POST", "PUT"}:
            return ActionOutcome(False, error="METHOD_NOT_SUPPORTED")
        ok, reason = self.sandbox.check(url)
        if not ok:
            self._blocked_count += 1
            self._emit("SANDBOX_BLOCKED", {"url": url[:300], "reason": reason, "channel": "http"})
            return ActionOutcome(False, error=f"SANDBOX_BLOCKED:{reason}", sandbox_blocked=True)
        assert self._http is not None
        parts = urlsplit(url)
        real = f"http://127.0.0.1:{self.lab_port}{parts.path or '/'}"
        if parts.query:
            real += "?" + parts.query
        content = None if body is None else str(body).encode("utf-8")
        resp = await self._http.request(method, real, content=content,
                                        headers={"Host": parts.netloc,
                                                 "Content-Type": "text/plain"})
        tool_result = None
        if "json" in resp.headers.get("content-type", ""):
            try:
                tool_result = resp.json()
            except ValueError:
                tool_result = None
        return ActionOutcome(resp.status_code < 400, status=resp.status_code, final_url=url,
                             text=resp.text[:MAX_TEXT], tool_result=tool_result)

    async def _tool_call(self, name: str, order_id: str) -> ActionOutcome:
        if name != "lookup_order" or not re.fullmatch(r"[A-Za-z0-9-]{1,20}", order_id):
            return ActionOutcome(False, error="UNKNOWN_MOCK_TOOL")
        url = f"http://orders.lab.test:{self.lab_port}/__tools__/lookup_order?order_id={order_id}"
        return await self._http_request("GET", url, None)
