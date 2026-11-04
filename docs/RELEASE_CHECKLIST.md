# Sentinel X — Release Checklist

## Pre-Release

- [ ] All code committed locally on `work/ds` branch
- [ ] Reviewed main pushed normally, with remote SHA verified
- [ ] `git status` clean
- [ ] `git diff --check` passes
- [ ] `ruff check .` passes
- [ ] `pytest -m "not slow"` passes
- [ ] TypeScript SDK compiles (`tsc --noEmit`: 0 errors)
- [ ] React dashboard builds (`npm run build` succeeds)
- [ ] `scripts/final_run.py --dry-run` works
- [ ] Secret history scan reviewed (no real credentials exposed)
- [ ] No forbidden paths modified (packages/policy/**, configs/policy/**, packages/scanner/authz.py, packages/scanner/http.py, labs/**/PLANTED.json, any *_reference folder, .env, opencode.json, immutable evaluation manifests)

## Documentation

- [ ] README.md "Planned vs implemented" table is accurate
- [ ] SECURITY.md is current
- [ ] NOTICE.md is current
- [ ] docs/HACKATHON_SCOPE.md is current
- [ ] docs/RULES_COMPLIANCE.md items reviewed
- [ ] docs/THIRD_PARTY_INVENTORY.md is current
- [ ] docs/LEGACY_CODE_AUDIT.md is current
- [ ] docs/DEMO_SCRIPT.md is complete
- [ ] docs/SUBMISSION_DRAFT.md is complete
- [ ] docs/DEMO_CHECKLIST.md is complete
- [ ] docs/RELEASE_CHECKLIST.md is complete

## Tasks 22-33

| Task | Status | Result File | Commit |
|---|---|---|---|
| 22 Shield intent accuracy | VERIFIED_LOCAL | tasks/22.result.md | 6532b91 |
| 23 Scanner stored-XSS + POST auth | VERIFIED_LOCAL | tasks/23.result.md | 63aebff |
| 24 Agent test CLI | VERIFIED_LOCAL | tasks/24.result.md | 0ea4096 (+fix 24f22b7) |
| 25 30-case model eval harness | VERIFIED_LOCAL (offline only) | tasks/25.result.md | c914788 |
| 26 Model-written explanations | VERIFIED_LOCAL | tasks/26.result.md | 3275d06 |
| 27 FastAPI backend + events | VERIFIED_LOCAL | tasks/27.result.md | 125d29a |
| 28 TypeScript SDK | VERIFIED_LOCAL (compiled) | tasks/28.result.md | b3d4f95 |
| 29 React dashboard | VERIFIED_LOCAL (built) | tasks/29.result.md | 3dcd430 |
| 30 External scanner QA | VERIFIED_LOCAL (fixture tests) | tasks/30.result.md | d8e680a |
| 31 Final-run orchestrator | VERIFIED_LOCAL (dry-run) | tasks/31.result.md | d9c2ad4 |
| 32 Security hardening | VERIFIED_LOCAL | tasks/32.result.md | e985488 |
| 33 Demo & submission | VERIFIED_LOCAL (docs) | tasks/33.result.md | pending |

## Human-Only Tasks (Not Automated)

- [ ] Real model run with provider credentials (NEEDS_LIVE_VALIDATION)
- [ ] Credentials rotation (if applicable)
- [ ] Organizer rule confirmation
- [ ] License choice (repo owner decision — NOT made)
- [ ] CI verification (workflow exists; require actual green run for the integrated SHA)
- [ ] Making repository public (NOT done — kept private)
- [ ] Video recording (3-minute demo)
- [ ] Video publishing
- [ ] Hackathon submission on Cerebral Valley (Nov 4, 9 PM ET)

## NOT Done (Intentional)

- [ ] Repository NOT pushed to GitHub
- [ ] Repository NOT made public
- [ ] LICENSE NOT chosen
- [ ] No live model calls made
- [ ] No public targets scanned
- [ ] No hackathon submission made automatically
