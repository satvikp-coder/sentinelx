"""Persona sessions: each has its OWN cookie jar / token. Credentials are for LAB targets only."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from sentinelx.common_schemas import TargetAuthorization

from .http import GuardedClient, Outcome
from .models import LoginSpec, Persona


class PersonaCredentialError(PermissionError):
    """Persona credentials were requested for a target that is not a lab target."""


@dataclass
class PersonaSession:
    persona: Persona
    cookies: dict[str, str] = field(default_factory=dict)
    token: str | None = None
    logged_in: bool = False

    @property
    def name(self) -> str:
        return self.persona.name

    def headers(self) -> dict[str, str]:
        h: dict[str, str] = {}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def absorb(self, out: Outcome) -> None:
        for raw in out.set_cookies:
            pair = raw.split(";", 1)[0]
            name, _, value = pair.partition("=")
            if not name.strip():
                continue
            low = raw.lower()
            if value == "" or "max-age=0" in low or "expires=thu, 01 jan 1970" in low:
                self.cookies.pop(name.strip(), None)
            else:
                self.cookies[name.strip()] = value


def new_session(target: TargetAuthorization, persona: Persona) -> PersonaSession:
    """A fresh, empty session (new cookie jar). Credentials only ever exist on lab targets."""
    if persona.credentials is not None and not target.lab:
        raise PersonaCredentialError(
            f"persona {persona.name!r} has credentials but target "
            f"{target.target_id!r} is not a lab")
    return PersonaSession(persona)


def request_as(client: GuardedClient, session: PersonaSession, method: str, url: str,
               **kwargs: Any) -> Outcome:
    headers = {**session.headers(), **kwargs.pop("headers", {})}
    out = client.request(method, url, headers=headers, **kwargs)
    if out.allowed:
        session.absorb(out)
    return out


def login(client: GuardedClient, base_url: str, session: PersonaSession, spec: LoginSpec) -> bool:
    """Log a persona in (a declared, reasoned POST with a synthetic account). Anonymous: no-op."""
    creds = session.persona.credentials
    if creds is None:
        return True
    body: dict[str, str] = {spec.username_field: creds.username,
                            spec.password_field: creds.password}
    kwargs: dict[str, Any] = {
        "reason": "persona login with a synthetic account", "account": creds.username,
        "follow_redirects": False}
    if spec.encoding == "json":
        kwargs["body"] = json.dumps(body)
        kwargs["headers"] = {"Content-Type": "application/json"}
    else:
        from urllib.parse import urlencode

        kwargs["body"] = urlencode(body)
        kwargs["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
    out = request_as(client, session, "POST", base_url + spec.path, **kwargs)
    if not out.allowed:
        return False
    if spec.token_key:
        try:
            session.token = str(json.loads(out.text)[spec.token_key])
        except (ValueError, KeyError, TypeError):
            return False
    session.logged_in = out.status in {200, 201, 302, 303} and (
        bool(session.cookies) or session.token is not None)
    return session.logged_in
