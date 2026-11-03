# @sentinelx/sdk — TypeScript Agent Guard SDK

The Sentinel X TypeScript Agent Guard SDK wraps agent tool calls with policy
enforcement. Every tool call is checked by the local Sentinel X sidecar API
(`/api/v1/guard/decide`) BEFORE the tool runs.

**Critical invariant:** a blocked action must NEVER execute the wrapped tool
(fail-closed in enforce mode).

## Install

```bash
# From the sdk/typescript directory
npm install

# Build
npm run build

# Local install (for consuming projects)
npm pack
# then in your project:
npm install ../sdk/typescript/sentinelx-sdk-0.1.0.tgz
```

Or consume directly via `npm link`:

```bash
cd sdk/typescript && npm link
cd my-app && npm link @sentinelx/sdk
```

## Quickstart

```typescript
import { Guard, GuardBlockedError } from "@sentinelx/sdk";

const guard = new Guard({
  baseUrl: "http://127.0.0.1:8080",  // local Sentinel X sidecar API
  token: "sentinelx-demo-local-only", // demo token
  mode: "enforce",                    // "monitor" or "enforce"
  timeoutMs: 5000,
});

// 1. check() - evaluate an action without executing it
const decision = await guard.check({
  sessionId: "sess-123",
  action: { tool: "navigate", arguments: { url: "http://127.0.0.1:8080/" } },
});
console.log(decision.decision); // "ALLOW" | "BLOCK" | "CONFIRM"

// 2. tool() wrapper - enforce before every call
const safeFetch = guard.tool("fetch_page", async (url: string) => {
  const resp = await fetch(url);
  return resp.text();
});

// In enforce mode, this throws GuardBlockedError before fetch_page runs:
try {
  await safeFetch("http://evil.com/");
} catch (e) {
  if (e instanceof GuardBlockedError) {
    console.log("Blocked:", e.reasonCode);
  }
}

// 3. checkAndDecide() - explicit allowed/blocked/confirm-required outcome
const outcome = await guard.checkAndDecide({
  sessionId: "sess-123",
  action: { tool: "send_data", arguments: { to: "http://evil.com/" } },
});
if (outcome.kind === "blocked") {
  // tool never runs
  console.log("Blocked:", outcome.decision.reasonCode);
}
```

## Modes

| Mode | Behavior |
|------|----------|
| `monitor` | Decision is recorded, tool always executes |
| `enforce` | ALLOW → runs; BLOCK → throws (tool never runs); CONFIRM → asks approver |

## Decisions

| Decision | Meaning |
|----------|---------|
| `ALLOW` | Action permitted; tool executes |
| `BLOCK` | Action refused; tool never executes |
| `CONFIRM` | Human approval required before execution |

## Security properties

- **Fail-closed:** sidecar unavailability → tool never executes (enforce mode)
- **Local-only:** sidecar base URL must be `http://127.0.0.1` or `http://localhost`
- **No shell:** no shell execution; all communication is via fetch()
- **Timeout:** configurable request timeout (default 5s)
- **Validated responses:** sidecar responses are strictly validated before use

## Types

The SDK exports strict TypeScript types: `GuardConfig`, `GuardAction`,
`GuardDecisionResult`, `GuardMode`, `GuardDecision`, `GuardOutcome`,
`ValidatedDecision`, `GuardCheckOptions`.

All types use nominal branding where appropriate to prevent accidental mixing
of session IDs, tool names, and other string values.
