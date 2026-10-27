"""Playwright (Chromium, headless, async) execution adapter behind the sandbox boundary.

Every browser request (navigations, subresources, each redirect hop) passes through
``context.route``; the SandboxBoundary aborts anything outside ``*.lab.test:<lab port>`` in
BOTH arms. In the protected arm each redirect hop is additionally checked with
``sentinelx.policy.check_redirect``. Raw HTTP / mock-tool calls go through httpx to
127.0.0.1 only AFTER the same sandbox check. The adapter never decides whether an action
may run; the runner calls it only after the arm's rules say so.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from types import TracebackType
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from sentinelx.common_schemas import ActionRequest
from sentinelx.policy import check_redirect

from .sandbox import SandboxBoundary
from .types import ActionOutcome

EventCallback = Callable[[str, dict[str, Any]], None]
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
    def __init__(
        self,
        lab_port: int,
        on_event: EventCallback,
        redirect_allowed_hosts: list[str] | None = None,
        op_timeout: float = 8.0,
        headless: bool = True,
    ) -> None:
        self.lab_port = lab_port
        self.sandbox = SandboxBoundary(lab_port)
        self._emit = on_event
        self._redirect_hosts = redirect_allowed_hosts  # None => unprotected arm (no hop check)
        self.op_timeout = op_timeout
        self.headless = headless
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._http: httpx.AsyncClient | None = None
        self._blocked_count = 0

    # ------------------------------------------------------------------ lifecycle
    async def __aenter__(self) -> BrowserAdapter:
        from playwright.async_api import async_playwright

        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=self.headless,
                                                           args=LAUNCH_ARGS)
            self._context = await self._browser.new_context(
                accept_downloads=False, service_workers="block", permissions=[],
                java_script_enabled=True,
            )
            self._context.set_default_timeout(self.op_timeout * 1000)
            self._context.set_default_navigation_timeout(self.op_timeout * 1000)
            await self._context.route("**/*", self._route)
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
        if self._pw is not None:
            try:
                await asyncio.wait_for(self._pw.stop(), 10)
            except Exception:  # noqa: S110
                pass
        self._http = self._context = self._browser = self._pw = self._page = None

    @property
    def current_url(self) -> str | None:
        url = self._page.url if self._page is not None else None
        return url if url and url.startswith(("http://", "https://")) else None

    # ------------------------------------------------------------------ sandbox routing
    async def _route(self, route: Any, request: Any) -> None:
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
        for hop in range(MAX_HOPS + 1):
            ok, reason = self.sandbox.check(url)
            if not ok:
                self._blocked_count += 1
                self._emit("SANDBOX_BLOCKED", {
                    "url": url[:300], "reason": reason, "resource_type": request.resource_type,
                    "channel": "browser", "hop": hop})
                await route.abort("blockedbyclient")
                return
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
            # the sandbox is authoritative in both arms: an off-lab hop is reported as
            # SANDBOX_BLOCKED at the top of the next iteration, before any policy check
            if self._redirect_hosts is not None and self.sandbox.check(nxt)[0]:
                res = check_redirect(url, nxt, self._redirect_hosts)
                if not res.ok:
                    self._emit("REDIRECT_BLOCKED", {"source": url[:300], "target": nxt[:300],
                                                    "reason": res.reason_code, "hop": hop})
                    await route.abort("blockedbyclient")
                    return
            if response.status == 303 or (response.status in {301, 302} and method == "POST"):
                method, body = "GET", None
            url = nxt
        self._emit("REDIRECT_BLOCKED", {"source": url[:300], "target": "", "hop": MAX_HOPS,
                                        "reason": "TOO_MANY_REDIRECTS"})
        await route.abort("blockedbyclient")

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
                resp = await self._page.goto(url, wait_until="load")
                break
            except Exception as exc:
                # After an aborted navigation Chromium may still be committing its error page;
                # that surfaces as "interrupted by another navigation". Retry once, then give up.
                if attempt == 0 and "interrupted by another navigation" in str(exc):
                    await asyncio.sleep(0.3)
                    continue
                raise
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
        return ActionOutcome(True, final_url=self._page.url)

    async def _submit_form(self, selector: str, field: str, value: str) -> ActionOutcome:
        if not selector or not _FIELD_NAME.match(field):
            return ActionOutcome(False, error="BAD_FORM_ARGUMENTS")
        form = self._page.locator(selector)
        await form.locator(f'[name="{field}"]').fill(value, timeout=3000)
        async with self._page.expect_navigation(wait_until="load", timeout=self.op_timeout * 1000):
            await form.locator("button[type=submit], input[type=submit]").first.click(timeout=3000)
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
