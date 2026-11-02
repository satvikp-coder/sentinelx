"""
Configuration for external scanner QA harness.

All settings are disabled by default. Enabling external scanner support
requires explicit configuration and human approval.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScannerConfig:
    """Configuration for a single external scanner."""

    name: str
    enabled: bool = False
    target_url: str | None = None  # must be lab-only (127.0.0.1, localhost, *.lab.test)
    api_key: str | None = None
    pinned_version: str | None = None
    license: str = "unknown"
    request_budget: int = 100
    time_budget_seconds: int = 300
    dry_run: bool = True  # always dry-run unless explicitly disabled
    kill_switch: bool = True  # kill switch always active


@dataclass(frozen=True)
class ExternalScannerConfig:
    """Top-level configuration for the external scanner QA harness."""

    enabled: bool = False
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)
    require_human_approval: bool = True
    local_lab_only: bool = True
    separate_evidence_storage: bool = True
    independent_verification_required: bool = True

    @classmethod
    def disabled_defaults(cls) -> ExternalScannerConfig:
        """Return a fully disabled configuration (the default)."""
        return cls(
            enabled=False,
            scanners={
                "strix": ScannerConfig(name="strix", enabled=False, dry_run=True),
                "pentagi": ScannerConfig(name="pentagi", enabled=False, dry_run=True),
            },
            require_human_approval=True,
            local_lab_only=True,
            separate_evidence_storage=True,
            independent_verification_required=True,
        )


def is_local_lab_url(url: str | None) -> bool:
    """Check if a URL is a local lab URL (127.0.0.1, localhost, *.lab.test)."""
    if not url:
        return False
    return (
        url.startswith("http://127.0.0.1")
        or url.startswith("http://localhost")
        or ".lab.test" in url
    )


def validate_config(config: ExternalScannerConfig) -> list[str]:
    """Validate configuration. Returns list of error messages (empty if valid)."""
    errors: list[str] = []
    if config.enabled and not config.require_human_approval:
        errors.append("external scanner enablement requires human approval")
    if config.enabled and not config.local_lab_only:
        errors.append("external scanner requires local-lab-only targeting")
    for name, scanner in config.scanners.items():
        if scanner.enabled:
            if not is_local_lab_url(scanner.target_url):
                errors.append(f"scanner {name}: target_url must be local lab URL")
            if scanner.dry_run is False:
                errors.append(f"scanner {name}: dry_run must be True unless explicitly overridden")
    return errors
