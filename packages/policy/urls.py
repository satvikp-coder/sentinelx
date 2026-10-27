"""Strict URL normalisation and host matching. Pure string processing: NO DNS, NO network.

Everything ambiguous is rejected rather than "fixed up", because browsers and parsers disagree
about ambiguous URLs and attackers live in that gap. Host comparison is exact (lowercase ASCII,
punycode for IDN) against explicit allowlist entries ("host" or "host:port"); there is no
wildcard, suffix or substring matching. An entry without a port matches only the scheme's default
port. IP-literal hosts are accepted only in canonical text form AND only if listed verbatim.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_URL_LENGTH = 2048
OK = "OK"

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_LAST_LABEL = re.compile(r"^(?:0[xX][0-9a-fA-F]*|[0-9]+)$")


@dataclass(frozen=True)
class UrlCheck:
    ok: bool
    reason_code: str
    normalized_url: str | None = None
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    is_ip: bool = False
    is_idn: bool = False


def _bad(code: str) -> UrlCheck:
    return UrlCheck(False, code)


def _parse_ipv4_loose(host: str) -> int | None:
    """inet_aton-style parse (decimal / octal / hex, 1-4 parts). Only used to name the reason."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        try:
            if p.lower().startswith("0x"):
                nums.append(int(p[2:] or "0", 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                nums.append(int(p, 10))
        except ValueError:
            return None
    if any(n >= 256 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    return sum(n << (8 * (3 - i)) for i, n in enumerate(nums[:-1])) + nums[-1]


def normalize_url(
    raw: object,
    base: str | None = None,
    *,
    allow_about_blank: bool = False,
    trailing_dot: str = "reject",
) -> UrlCheck:
    """Validate and normalise ``raw`` (resolving against ``base`` if relative). No allowlist."""
    try:
        return _normalize(raw, base, allow_about_blank, trailing_dot, _depth=0)
    except Exception:  # fail closed on any parser surprise
        return _bad("URL_PARSE_ERROR")


def _normalize(
    raw: object, base: str | None, allow_about_blank: bool, trailing_dot: str, _depth: int
) -> UrlCheck:
    if not isinstance(raw, str):
        return _bad("URL_NOT_A_STRING")
    if not raw:
        return _bad("EMPTY_URL")
    if len(raw) > MAX_URL_LENGTH:
        return _bad("URL_TOO_LONG")
    if any(c.isspace() or ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in raw):
        return _bad("CONTROL_OR_WHITESPACE")
    if "\\" in raw:
        return _bad("BACKSLASH_IN_URL")

    m = _SCHEME_RE.match(raw)
    if m is None:  # relative reference
        if _depth > 0 or base is None:
            return _bad("RELATIVE_URL_WITHOUT_BASE")
        base_check = _normalize(base, None, False, trailing_dot, _depth=1)
        if not base_check.ok or base_check.normalized_url is None:
            return _bad("INVALID_BASE_URL")
        if raw.startswith("//"):
            # Never let urljoin interpret "//..." / "///...": browsers read these as a new
            # authority (so "///evil" means host evil), Python's urljoin does not.
            absolute = f"{base_check.scheme}:{raw}"
        else:
            absolute = urljoin(base_check.normalized_url, raw)
        return _normalize(absolute, None, allow_about_blank, trailing_dot, 1)

    scheme = m.group(1).lower()
    if scheme == "about":
        if allow_about_blank and raw.lower() == "about:blank":
            return UrlCheck(True, OK, "about:blank", None, None, "about")
        return _bad("SCHEME_NOT_ALLOWED")
    if scheme not in DEFAULT_PORTS:
        return _bad("SCHEME_NOT_ALLOWED")
    after = raw[m.end() :]
    if not after.startswith("//"):
        return _bad("MALFORMED_AUTHORITY")
    rest = after[2:]
    cut = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i != -1:
            cut = min(cut, i)
    authority, tail = rest[:cut], rest[cut:]
    if not authority:
        return _bad("EMPTY_HOST")
    if "@" in authority:
        return _bad("USERINFO_IN_URL")
    if "%" in authority:
        return _bad("ENCODED_AUTHORITY")

    # --- split host / port ourselves, then cross-check with the stdlib parser
    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            return _bad("MALFORMED_AUTHORITY")
        host_raw, after_host, bracketed = authority[1:close], authority[close + 1 :], True
        if after_host and not after_host.startswith(":"):
            return _bad("MALFORMED_AUTHORITY")
        port_str = after_host[1:] if after_host else None
    else:
        if authority.count(":") > 1:
            return _bad("MALFORMED_AUTHORITY")
        host_raw, sep, port_text = authority.partition(":")
        port_str, bracketed = (port_text if sep else None), False

    port: int | None = None
    if port_str:
        if not (port_str.isascii() and port_str.isdigit()):
            return _bad("INVALID_PORT")
        port = int(port_str)
        if not 1 <= port <= 65535:
            return _bad("INVALID_PORT")
    effective_port = port if port is not None else DEFAULT_PORTS[scheme]

    try:
        parts = urlsplit(raw)
        std_host, std_port = parts.hostname, parts.port
    except ValueError:
        return _bad("URL_PARSE_ERROR")
    if (std_host or "") != host_raw.lower() or (std_port or None) != port:
        return _bad("PARSER_DISAGREEMENT")

    host = host_raw.lower()
    is_ip = is_idn = False
    if bracketed:
        if "%" in host:
            return _bad("INVALID_IP_HOST")
        try:
            ip6 = ipaddress.IPv6Address(host)
        except ValueError:
            return _bad("INVALID_IP_HOST")
        if str(ip6) != host or ip6.ipv4_mapped is not None or "." in host:
            return _bad("NONCANONICAL_IP")
        is_ip = True
        netloc_host = f"[{host}]"
    else:
        if host.endswith("."):
            if trailing_dot != "normalize":
                return _bad("TRAILING_DOT")
            host = host[:-1]
            if not host or host.endswith("."):
                return _bad("INVALID_HOST")
        if not host:
            return _bad("EMPTY_HOST")
        if not host.isascii():
            try:
                ascii_host = host.encode("idna").decode("ascii")
            except UnicodeError:
                return _bad("INVALID_HOST")
            if "xn--" not in ascii_host:
                return _bad("IDN_NORMALIZES_TO_ASCII")
            host, is_idn = ascii_host, True
        labels = host.split(".")
        if _NUMERIC_LAST_LABEL.match(labels[-1]):
            try:
                ipaddress.IPv4Address(host)
            except ValueError:
                loose = _parse_ipv4_loose(host)
                return _bad("NONCANONICAL_IP" if loose is not None else "INVALID_IP_HOST")
            is_ip = True
        elif len(host) > 253 or not all(_LABEL_RE.match(lb) for lb in labels):
            return _bad("INVALID_HOST")
        netloc_host = host

    path_query = tail.split("#", 1)[0]
    if not path_query.startswith("/"):
        path_query = "/" + path_query
    netloc = netloc_host + ("" if effective_port == DEFAULT_PORTS[scheme] else f":{effective_port}")
    return UrlCheck(
        True, OK, f"{scheme}://{netloc}{path_query}", host, effective_port, scheme, is_ip, is_idn
    )


# ------------------------------------------------------------------ allowlist matching
def parse_host_entry(entry: object) -> tuple[str, int | None] | None:
    """Parse "host" or "host:port". Invalid entries return None (they never match)."""
    if not isinstance(entry, str) or not entry or entry != entry.strip():
        return None
    e = entry.lower()
    if any(c in e for c in "*/@%\\?# ") or e.endswith("."):
        return None
    try:
        if e.startswith("["):
            close = e.find("]")
            if close == -1:
                return None
            host = str(ipaddress.IPv6Address(e[1:close]))
            rest = e[close + 1 :]
            if rest and not rest.startswith(":"):
                return None
            port_text = rest[1:] if rest else ""
        else:
            if e.count(":") > 1:
                return None
            host, _, port_text = e.partition(":")
            if not host or not host.isascii():
                return None
            if _NUMERIC_LAST_LABEL.match(host.split(".")[-1]):
                host = str(ipaddress.IPv4Address(host))
                if host != e.partition(":")[0]:
                    return None
        if not port_text:
            return host, None
        if not (port_text.isascii() and port_text.isdigit()) or not 1 <= int(port_text) <= 65535:
            return None
        return host, int(port_text)
    except ValueError:
        return None


def host_matches(
    entries: Iterable[object], host: str | None, port: int | None, scheme: str | None,
    *, any_port: bool = False,
) -> bool:
    """Exact host match; an entry without a port matches only the scheme's default port."""
    if host is None or port is None or scheme not in DEFAULT_PORTS:
        return False
    for entry in entries:
        parsed = parse_host_entry(entry)
        if parsed is None:
            continue
        eh, ep = parsed
        if eh != host:
            continue
        if any_port or (ep if ep is not None else DEFAULT_PORTS[scheme]) == port:
            return True
    return False


def check_url(
    raw: object,
    allowed_hosts: Iterable[object],
    base: str | None = None,
    *,
    allow_about_blank: bool = False,
    trailing_dot: str = "reject",
) -> UrlCheck:
    """normalize_url + exact allowlist membership. ``ok`` means: safe to treat as in-scope."""
    allowed = list(allowed_hosts)
    res = normalize_url(raw, base, allow_about_blank=allow_about_blank, trailing_dot=trailing_dot)
    if not res.ok or res.scheme == "about":
        return res
    if host_matches(allowed, res.host, res.port, res.scheme):
        return res
    if res.is_ip:
        code = "IP_LITERAL_NOT_ALLOWED"
    elif res.is_idn:
        code = "IDN_HOST_NOT_ALLOWED"
    elif host_matches(allowed, res.host, res.port, res.scheme, any_port=True):
        code = "PORT_NOT_ALLOWED"
    else:
        code = "HOST_NOT_ALLOWED"
    return UrlCheck(False, code, res.normalized_url, res.host, res.port, res.scheme,
                    res.is_ip, res.is_idn)


def check_redirect(
    source_url: str,
    target_url: object,
    allowed_hosts: Iterable[object],
    *,
    allow_about_blank: bool = False,
    trailing_dot: str = "reject",
) -> UrlCheck:
    """Apply the same rules to one redirect hop (``target_url`` may be relative to the source)."""
    return check_url(
        target_url, allowed_hosts, base=source_url,
        allow_about_blank=allow_about_blank, trailing_dot=trailing_dot,
    )
