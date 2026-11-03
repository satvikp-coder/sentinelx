"""Authorization checks for external scanner operations.

External scanner operations require explicit authorization. No scanner
may run without authorization, local-lab-only targeting, and dry-run mode.
"""

from __future__ import annotations

from .config import ExternalScannerConfig, is_local_lab_url


class AuthorizationError(PermissionError):
    """Raised when an external scanner operation is not authorized."""


def check_authorization(
    config: ExternalScannerConfig,
    scanner_name: str,
    operation: str = "scan",
) -> None:
    """Verify that the requested scanner operation is authorized.

    Raises AuthorizationError if any check fails.
    """
    if not config.enabled:
        raise AuthorizationError(
            "external scanner harness is disabled; enable it explicitly in config"
        )
    if config.require_human_approval:
        raise AuthorizationError(
            f"external scanner operation '{operation}' requires human approval "
            "(require_human_approval must be explicitly disabled)"
        )
    scanner = config.scanners.get(scanner_name)
    if scanner is None:
        raise AuthorizationError(f"unknown scanner: {scanner_name}")
    if not scanner.enabled:
        raise AuthorizationError(f"scanner {scanner_name} is not enabled")
    if scanner.target_url and not is_local_lab_url(scanner.target_url):
        raise AuthorizationError(
            f"scanner {scanner_name}: target_url must be a local lab URL, "
            f"got {scanner.target_url}"
        )
    if not scanner.dry_run:
        raise AuthorizationError(
            f"scanner {scanner_name}: dry_run must be True for unattended operation"
        )


def is_authorized(
    config: ExternalScannerConfig,
    scanner_name: str,
    operation: str = "scan",
) -> bool:
    """Return True if the operation is authorized, False otherwise."""
    try:
        check_authorization(config, scanner_name, operation)
        return True
    except AuthorizationError:
        return False
