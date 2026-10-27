# Security and Responsible-Use Policy

- **Scan only systems you own or are authorized to test.** Sentinel X is for localhost labs and sites you own.
- **Ownership verification is enforced in code** (ownership token); targets that are not verified-owned are refused. (Planned: not yet implemented.)
- Scans are non-destructive by default. Monitor-only mode is the default; nothing is auto-applied; the shield never edits code; a kill switch always exists.
- **Data stays local.** Evidence and scan results are stored locally in SQLite.
- **Telemetry is off by default.**
- **Secrets are redacted before any model call** and before storage.
- Lab services bind to 127.0.0.1 and use synthetic data only.

## Reporting a vulnerability in Sentinel X
Open a private security advisory on the GitHub repository (contact: the repository owner). Do not include real credentials or third-party data in reports.
