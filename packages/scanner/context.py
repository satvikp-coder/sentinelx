"""ScanContext: the single object a check or recon function touches. It owns the GuardedClient,
one PersonaSession per persona (each its own cookie jar), the profile/paths, and the growing
endpoint inventory and discovery results. Every network call goes through `ctx.get` / `ctx.call`,
which delegate to `session.request_as` -> `GuardedClient.request` - there is no other path out."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sentinelx.common_schemas import TargetAuthorization

from .authz import ScanProfile as AuthzScanProfile
from .http import GuardedClient, Outcome
from .models import Endpoint, PathLists, PersonaFile, SiteScanProfile, load_paths, load_personas
from .session import PersonaSession, login, new_session, request_as


def authz_profile_for(site: SiteScanProfile, personas: PersonaFile) -> AuthzScanProfile:
    """The `GuardedClient`'s own (unrelated) `ScanProfile`: which methods/accounts the gate lets
    through. Built from the scan-plan profile and the persona file, never from a model."""
    methods = tuple(sorted({s.method for s in site.declared_steps})) if site.state_changing else ()
    accounts = tuple(dict.fromkeys(
        [p.credentials.username for p in personas.personas if p.credentials is not None]
        + [personas.failed_login_username]))
    return AuthzScanProfile(name=site.name, state_changing_methods=methods,
                            synthetic_accounts=accounts)


@dataclass
class ScanContext:
    target: TargetAuthorization
    client: GuardedClient
    profile: SiteScanProfile
    paths: PathLists
    personas_file: PersonaFile
    sessions: dict[str, PersonaSession] = field(default_factory=dict)
    inventory: dict[tuple[str, str], Endpoint] = field(default_factory=dict)
    discovery: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    scripts: dict[str, str] = field(default_factory=dict)
    soft404: tuple[int, int] | None = None
    login_failures: dict[str, int] = field(default_factory=dict)  # counted, never uncapped

    @property
    def base_url(self) -> str:
        return self.target.base_url

    @property
    def netloc(self) -> str:
        return urlsplit(self.base_url).netloc

    def session_for(self, persona: str) -> PersonaSession:
        if persona not in self.sessions:
            raise KeyError(f"persona {persona!r} has no open session (call ensure_persona first)")
        return self.sessions[persona]

    def ensure_persona(self, persona: str, *, fresh: bool = False) -> PersonaSession:
        """Return the persona's session, creating (and logging in) it if needed.

        `fresh=True` always makes a brand-new session (new cookie jar / no token): used by the
        independent verifier, which must never reuse a detection-time session. A cached session
        is reused even if it has no credentials (an anonymous visitor still keeps its cookies
        across requests)."""
        if not fresh and persona in self.sessions:
            return self.sessions[persona]
        p = self.personas_file.get(persona)
        session = new_session(self.target, p)
        if p.credentials is not None:
            login(self.client, self.base_url, session, self.personas_file.login)
        if not fresh:
            self.sessions[persona] = session
        return session

    def get(self, persona: str, path: str, **kwargs: Any) -> Outcome:
        session = self.ensure_persona(persona)
        return request_as(self.client, session, "GET", self.base_url + path, **kwargs)

    def call(self, persona: str, method: str, path: str, *, fresh: bool = False,
             **kwargs: Any) -> Outcome:
        session = self.ensure_persona(persona, fresh=fresh)
        return request_as(self.client, session, method, self.base_url + path, **kwargs)

    def count_login_failure(self, username: str) -> int:
        self.login_failures[username] = self.login_failures.get(username, 0) + 1
        return self.login_failures[username]


def build_context(target: TargetAuthorization, client: GuardedClient, profile: SiteScanProfile,
                  labs_root: Path, lab_name: str) -> ScanContext:
    return ScanContext(target=target, client=client, profile=profile, paths=load_paths(),
                       personas_file=load_personas(labs_root / lab_name / "personas.json"))
