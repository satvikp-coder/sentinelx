"""The fixed check catalog. Each entry is one plugin: an id, a `VulnClass`, an OWASP category, its
preconditions, its safe strategy, and a `run(ctx) -> list[Candidate]` function. A model may only
pick a subset of these ids (`sentinelx.scanner.model_assist`); it can never add a request, a URL,
a header or a payload - every request in every check is written by this module's own code."""

from __future__ import annotations

from . import (
    authz_object,
    authz_post,
    cors,
    errors,
    exposure,
    headers_cookies,
    injection,
    rate_limit,
    stored_xss,
    upload,
)
from .base import Check, CheckSpec

CATALOG: dict[str, Check] = {
    headers_cookies.SPEC.id: Check(headers_cookies.SPEC, headers_cookies.run,
                                   headers_cookies.applicable),
    exposure.FILE_SPEC.id: Check(exposure.FILE_SPEC, exposure.run_sensitive_file_exposure,
                                 exposure.applicable_sensitive_file_exposure),
    exposure.DEBUG_SPEC.id: Check(exposure.DEBUG_SPEC, exposure.run_debug_exposure,
                                  exposure.applicable_debug_exposure),
    exposure.AUTH_SPEC.id: Check(exposure.AUTH_SPEC, exposure.run_missing_authentication,
                                 exposure.applicable_missing_authentication),
    cors.SPEC.id: Check(cors.SPEC, cors.run, cors.applicable),
    errors.SPEC.id: Check(errors.SPEC, errors.run, errors.applicable),
    injection.SQL_SPEC.id: Check(injection.SQL_SPEC, injection.run_sql_injection,
                                 injection.applicable_sql_injection),
    injection.XSS_SPEC.id: Check(injection.XSS_SPEC, injection.run_reflected_xss,
                                 injection.applicable_reflected_xss),
    authz_object.SPEC.id: Check(authz_object.SPEC, authz_object.run,
                                authz_object.applicable),
    authz_post.SPEC.id: Check(authz_post.SPEC, authz_post.run, authz_post.applicable),
    rate_limit.SPEC.id: Check(rate_limit.SPEC, rate_limit.run, rate_limit.applicable),
    stored_xss.SPEC.id: Check(stored_xss.SPEC, stored_xss.run, stored_xss.applicable),
    upload.SPEC.id: Check(upload.SPEC, upload.run, upload.applicable),
}

__all__ = ["CATALOG", "Check", "CheckSpec"]
