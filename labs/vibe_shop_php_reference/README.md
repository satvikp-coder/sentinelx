# Vibe Shop - REFERENCE (hand-fixed) copy

Ground truth for later verification only: every weakness in `../vibe_shop_php/PLANTED.json` is fixed here with
the correct, minimal change. Port **18082** (`127.0.0.1` only). **No code under `packages/` may import,
read or open anything in this folder** (a test enforces it). Start it with
`python scripts/lab_up.py vibe_shop_php_reference`.
