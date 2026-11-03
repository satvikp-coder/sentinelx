# Sentinel X — Final Feature Matrix

**Date:** 2026-11-04
**Branch:** work/ds
**Legend:** PASS = implemented + verified locally · PARTIAL = implemented, some
paths unverified · FAIL = broken · BLOCKED = external dependency · NOT RUN =
no execution evidence

## Core security platform

| Feature | Entry point | Status | Notes |
|---------|-------------|--------|-------|
| Policy gateway | `POST /api/v1/policy/decide`, `POST /guard/decide` | PASS | deterministic `evaluate()`; no shortcut; counters + evidence |
| Session lifecycle | `POST /api/v1/sessions`, runs | PASS | PENDING→RUNNING→terminal; scenario snapshots deep-copied |
| Approval workflow (actions) | `POST /api/v1/approvals` | PASS | scoped by session + action digest |
| Evidence store | SQLite hash chain | PASS | verify_chain; redaction before hashing |
| SSE stream | `GET /api/v1/events/stream` | PASS | signed HttpOnly cookie + bearer; integer seq cursor |
| Redaction | all evidence/SSE/API echoes | PASS | includes shield rule echoes and proxy logs |
| Rate limits / step caps | gateway | PASS | per-session under lock |

## Site Guard — scanning

| Feature | Entry point | Status | Notes |
|---------|-------------|--------|-------|
| Target registration | `POST /api/v1/targets` | PASS | loopback / `*.lab.test` only; registration ≠ ownership |
| Scan execution | `POST /api/v1/scans` | PASS | real `run_scan()`; background thread; guarded transport |
| Scan status | `GET /api/v1/scans/{id}` | PASS | PENDING/RUNNING/COMPLETED/FAILED/CANCELLED |
| Per-scan findings | `GET /api/v1/scans/{id}/findings` | PASS | filtered by scan; 404 unknown |
| Global findings | `GET /api/v1/findings` | PASS | explicit serialization; native session IDs mapped |
| Cancellation | `POST /api/v1/scans/{id}/cancel` | PASS | CANCELLED preserved across worker return/error; actual counts |
| Budget alignment | scan responses | PASS | reports the scanner profile budget (500) |

## Site Guard — shield

| Feature | Entry point | Status | Notes |
|---------|-------------|--------|-------|
| Rule proposal | `POST /api/v1/shield/rules` | PASS | RuleCompiler validation; real proposal evidence |
| Rule listing | `GET /api/v1/shield/rules` | PASS | strict schema; pagination; TTL mirroring |
| Approval (scoped) | `POST /api/v1/approvals` (tool=shield_rule) | PASS | canonical `shield_rule:{rule_id}:{digest}` subject |
| Activation | `POST /api/v1/shield/rules/{id}/approve` | VERIFIED_LOCAL | gate -> install -> persist; rollback on failure; 24h approval age; latest-record wins |
| Real proxy enforcement | standalone `uvicorn` + API | VERIFIED_LOCAL | subprocess E2E: 403 block, upstream never reached, benign passthrough |
| Cross-process coordination | `SHIELD_RUNTIME_DB` | VERIFIED_LOCAL | verified ACTIVE rows only; tampered rows never enforced |
| Manual expiry | `POST /api/v1/shield/rules/{id}/expire` | PASS | stops local + shared enforcement; reports it |
| Manual removal | `DELETE /api/v1/shield/rules/{id}` | PASS | stops local + shared enforcement; idempotent |
| Natural TTL | read-time filter + expire_overdue | PASS | enforcement stops; API list mirrors EXPIRED |
| Kill switch | proxy config | PASS | blocks new activation; traffic passes per contract |
| Browser UI for shield | apps/web/src | NOT RUN | Playwright not installed |

## Agent Guard

| Feature | Status | Notes |
|---------|--------|-------|
| Python SDK + wrapped runtime tests | PASS | SDK tests + wrapped-tool runtime checks |
| Scripted lab scenarios / verifier | PASS | independent verifier from ledger |
| Live model benchmark | BLOCKED | no credentials; scripted results labeled SIMULATED |

## Quality / release

| Check | Status |
|-------|--------|
| Project Ruff | PASS |
| Full fast pytest | PASS (recorded in SHIELD_RECOVERY_TEST_MATRIX) |
| Docker/PHP labs | BLOCKED (daemon not running; skipped loudly) |
| Browser E2E | NOT RUN (Playwright not installed) |
| Hosted CI | NOT RUN (push not authorized) |
| Fresh install / packaging | PARTIAL (CI install step added; remote confirmation required) |
| LICENSE / public visibility | HUMAN ACTION |
| Independent Codex review of Shield recovery | REQUIRED |

> Shield activation is NOT production-certified: loopback-only demo scope,
> browser/Docker/hosted validation absent, and independent review pending.
