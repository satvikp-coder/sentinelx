"""Scanner data models (strict). Personas, profile, inventory, candidates, verifications."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from sentinelx.common_schemas import Severity, VulnClass

CONFIG_DIR = Path(__file__).resolve().parents[2] / "configs" / "scan"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------ personas
class Credentials(_Strict):
    username: str
    password: str


class Persona(_Strict):
    name: str
    role: str
    credentials: Credentials | None = None


class LoginSpec(_Strict):
    method: Literal["POST"]
    path: str
    encoding: Literal["form", "json"]
    username_field: str
    password_field: str
    token_key: str | None = None  # JSON key holding a bearer token (else a session cookie)


class PersonaFile(_Strict):
    """Synthetic accounts for a LAB target (committed, labelled synthetic)."""

    synthetic: Literal[True]
    note: str
    start_path: str
    login: LoginSpec
    failed_login_username: str
    personas: list[Persona]

    def get(self, name: str) -> Persona:
        return next(p for p in self.personas if p.name == name)


def load_personas(path: Path) -> PersonaFile:
    return PersonaFile.model_validate_json(Path(path).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ profile
class DeclaredStep(_Strict):
    method: str
    purpose: str


class SiteScanProfile(_Strict):
    """configs/scan/*.yaml. Versioned; the hash is recorded in the evidence."""

    profile_version: str
    name: str
    checks: list[str]
    request_budget: Annotated[int, Field(ge=1)] = 500
    requests_per_second: Annotated[float, Field(gt=0)] = 25.0
    burst: Annotated[int, Field(ge=1)] = 25
    max_depth: Annotated[int, Field(ge=0, le=6)] = 3
    max_pages: Annotated[int, Field(ge=1, le=200)] = 40
    login_burst: Annotated[int, Field(ge=1, le=15)] = 15  # hard ceiling: 15 failed logins
    state_changing: bool = False
    declared_steps: list[DeclaredStep] = []
    personas: list[str]

    @property
    def sha256(self) -> str:
        doc = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(doc.encode("utf-8")).hexdigest()


def load_profile(path: Path | None = None) -> SiteScanProfile:
    p = Path(path) if path else CONFIG_DIR / "lab_default.yaml"
    return SiteScanProfile.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")))


class PathHint(_Strict):
    path: str
    params: list[str] = []


class PathLists(_Strict):
    version: str
    exposure_paths: list[str]
    admin_paths: list[str]
    api_hints: list[PathHint]


def load_paths(path: Path | None = None) -> PathLists:
    p = Path(path) if path else CONFIG_DIR / "paths.yaml"
    return PathLists.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")))


# ------------------------------------------------------------------ inventory
class FormInfo(_Strict):
    method: str
    action: str
    fields: list[str]
    has_file: bool = False


class Endpoint(_Strict):
    method: str
    template: str  # path with numeric segments as {id}
    params: list[str] = []
    forms: list[FormInfo] = []
    content_types: list[str] = []
    statuses: dict[str, int] = {}  # persona -> last status
    auth_required: bool | None = None
    cookies: list[str] = []
    samples: dict[str, list[str]] = {}  # persona -> concrete path+query seen in that session

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, self.template)


# ------------------------------------------------------------------ findings
class Candidate(_Strict):
    id: str
    check_id: str
    vuln_class: VulnClass
    severity: Severity
    confidence: Literal["low", "medium", "high"]
    method: str
    endpoint: str  # normalized path template
    endpoints: list[str]  # every endpoint the finding applies to (templates)
    param: str | None = None
    persona: str
    summary: str
    evidence_event_ids: list[str]
    excerpt: str  # redacted, truncated
    proof: dict[str, Any] = {}  # what the INDEPENDENT verifier needs (no secrets)
    behavioral: bool = False  # evidence is behavioural only (e.g. no throttling observed)


class Verification(_Strict):
    state: Literal["confirmed", "needs_validation", "rejected"]
    detail: str
    fresh_session: bool
    event_ids: list[str] = []
    excerpt: str = ""


class Finding(_Strict):
    candidate: Candidate
    verification: Verification
    explanation: str | None = None  # MODEL-GENERATED, never part of verification
    explanation_label: str | None = None
