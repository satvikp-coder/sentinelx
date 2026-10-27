# Limitations (what the MVP does NOT do)

- No production deployments.
- No scanning of sites the user does not own or is not authorized to test.
- No guarantee of finding every vulnerability.
- Shield rules are temporary and are not fixes; the shield never edits code.
- Generated patches are not verified fixes until independently verified and human-approved.
- Hosted trial endpoint rate limits apply; model calls can fail (explicit MODEL_UNAVAILABLE).
- Lab only: synthetic data, localhost services, no outbound internet from the lab.
- At setup time nothing is implemented; see STATUS.md.
