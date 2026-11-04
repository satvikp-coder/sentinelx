# Meta model evidence: submission disposition

Reviewed against release `d855c4ece913775306295a8fec54254e7c2181d1`.
No provider call was made during this review. No real credential file was read.
Model identifiers below are the identifiers recorded by the integration, not an
independent attestation of the provider's serving infrastructure or current catalog.

## What the existing artifacts actually support

| Artifact | Classification | Observed evidence | Limits |
|---|---|---|---|
| `evaluations/runs/model-subset-1/evidence.db` (local ignored artifact) and tracked `evaluations/example_report_model/report.json`, `evaluations/model-subset-1.log` | Recorded evidence of previous LIVE NVIDIA invocation | `meta/muse-glimmer-30b`; 76 MODEL_CALL events: 72 OK, 4 MODEL_UNAVAILABLE; 72 successful events have request IDs; 36,939 input and 11,216 output tokens recorded. Hash chains verified OK for all 20 model-call sessions. | 10 cases × 2 arms = 20 runs, 16 valid, 4 invalid; not the full 30-case live benchmark. No new execution; no provider billing/console corroboration obtained. |
| `evaluations/runs/model-generated-1/evidence.db`, tracked `evaluations/model-generated-1.log` | Recorded previous LIVE subset with generated cases | Same NVIDIA model identifier; 22 call events: 21 OK, 1 MODEL_UNAVAILABLE; 8 model-call session chains OK. | Separate 4-case subset, not an additive extension proving 30-case coverage. |
| `evaluations/runs/model-main-1/evidence.db` and `docs/DECISIONS.md` | ABORTED historical LIVE run | 25 OK call events over 6 model-call sessions; chains OK. | Full run was aborted for latency. Exclude it from completed benchmark claims. |
| `evaluations/example_investigation/evidence_copy.db` (local ignored artifact), tracked `evaluations/example_investigation/investigations.json` | Recorded evidence of model-assisted investigation | 82 call events: 78 OK, 4 unavailable; 20 chains OK. | This copies the subset database and adds investigation calls. Do not add its counts to the original subset; that would double-count. Claims include independent verification failures/needs_validation, not automatic VERIFIED. |
| `evaluations/model_usage.sqlite` (local ignored artifact), `docs/DECISIONS.md` | Historical Baseten usage record; weaker provenance | `meta-models/muse-spark-open-1026`, one usage row: 165 input, 168 output tokens; **estimated** USD 0.00092025. | No corresponding MODEL_CALL event in this database. A usage row plus a written account is not equivalent to an independently authenticated provider receipt. |
| `evaluations/example_fix_report/report.json` | Recorded model-profile attribution | `baseten_spark_open`, no fallback recorded; generated 2026-10-29. Includes accepted and rejected patch outcomes. | The report's spend field is not a provider invoice. Reject explanations are model descriptions, not proof of a fix. |
| `evaluations/example_model_assisted_scan/report.json` | Recorded model-assisted scan provenance | NVIDIA, `meta/muse-glimmer-30b`, LIVE label. | Historical artifact, not a fresh scan/model call in this release review. |
| `evaluations/example_report/report.json` | SIMULATED scripted evaluation | 30 cases in each of two arms; no model provider. | Never present it as a live Meta-model benchmark. |
| `evaluations/example_report_evcs/report.json` | SIMULATED containment evaluation | Explicit scripted planner label. | A branch replay is not a new live-model experiment. |
| `fixtures/recorded_model/` | Cassette mechanism implemented; no distributable replies present | Only `.gitkeep` currently present. | Do not promise offline replay of historical model responses from this directory. |
| Final CI live smoke test | NOT RUN | Live test skipped for missing configured model credentials. | All other passing CI checks do not establish fresh model usage. |

The read-only review queried existing databases and ran the real evidence-chain
verifier. Counts above describe stored records, not newly observed provider
requests. Hash chains detect certain changes; someone with complete database
write access can recompute a chain. This is not cryptographic provider attestation.
Local ignored evidence databases will not appear in a fresh Git clone. Judges can
inspect tracked summaries; owner must separately approve any sanitized artifact
export. Do not upload raw databases or prompts without a privacy review.

## Submission wording

“Meta open-weight model integrations use an OpenAI-compatible server-side adapter.
Historical traces record NVIDIA `meta/muse-glimmer-30b` planning/investigation and
a small Baseten `meta-models/muse-spark-open-1026` usage record. The present demo is
offline/synthetic and makes no model calls. We have not completed the full 30-case
live comparison or established a model-performance improvement.”

The owner must confirm that the accepted event rules recognize these provider/model
combinations and that the historical use satisfies the event's substantive model
requirement. A model mentioned in configuration is not evidence it was invoked.

## Optional supervised one-call smoke test — NOT AUTHORIZED OR EXECUTED HERE

Existing evidence is useful, but one owner-supervised call could establish fresh
provenance if organizers require it. This is not a benchmark. Do not run a whole
evaluation to obtain one screenshot. First verify provider access and current
pricing in the owner's dashboard, existing spend/reserve and a maximum authorized
spend. The checked-in historical price is USD 1.25/M input + USD 4.25/M output;
2,000 input + 128 output tokens would estimate **USD 0.003044**, not a bill or
guaranteed upper bound. The current pricing page could not be read without
JavaScript during this review. NVIDIA pricing is unknown, not proven free.

Only after explicit owner approval, use an external empty directory and the
existing interpreter. Save the following as `owner_meta_smoke.py` there, then run
`C:\Users\satvi\Desktop\sentinelx-ds\.venv\Scripts\python.exe owner_meta_smoke.py`.
The script deliberately refuses until the owner provides the approval phrase.
It uses a hidden prompt for the provider credential and does not read `.env`.
No credentials, model response text or raw exception text are printed or saved.
Use an HTTPS-verified provider endpoint only; do not change authorization policy.

```python
import getpass
import json
from pydantic import BaseModel, ConfigDict, SecretStr
from sentinelx.model_clients import ModelClient
from sentinelx.model_clients.config import ModelConfig

if input('Type OWNER APPROVES ONE PAID CALL after confirming current price/spend: ') != 'OWNER APPROVES ONE PAID CALL':
    raise SystemExit('Not approved; no call made')
class Reply(BaseModel):
    model_config = ConfigDict(extra='forbid')
    answer: str
cfg = ModelConfig(
    provider='baseten', base_url='https://inference.baseten.co/v1',
    model='meta-models/muse-spark-open-1026',
    api_key=SecretStr(getpass.getpass('Provider credential (hidden): ')),
    max_tokens=128, max_retries=0, not_found_retries=0,
    run_call_cap=1, experiment_call_ceiling=1,
    connect_timeout_s=10, read_timeout_s=30,
)
client = ModelClient(cfg)
client.begin_run(cap=1)  # prevents validation-repair exchange from making another request
try:
    result = client.complete('owner_supervised_smoke', [
        {'role':'system','content':'Return only JSON with one string field answer.'},
        {'role':'user','content':'Set answer to pong.'},
    ], Reply)
    print(json.dumps({
        'status':result.status.value, 'provider':result.provider,
        'model':result.model, 'mode':result.mode.value,
        'http_calls':result.http_calls, 'tokens_in':result.tokens_in,
        'tokens_out':result.tokens_out, 'request_id_present':bool(result.request_id),
        'schema_valid':result.parsed is not None, 'latency_ms':result.latency_ms,
    }))
finally:
    client.close()
```

One request with 128 completion tokens may legitimately return INVALID_OUTPUT
because of reasoning/token limits. Do not silently raise budgets or rerun. Record
failure honestly and seek a new decision. This manual smoke path does not enforce
the application's cumulative USD ledger by itself: owner must check remaining
budget first, retain the provider receipt and enter any incurred spend. The
application's configured budget remains hard 70 / warning 50 / reserve 30 USD.
