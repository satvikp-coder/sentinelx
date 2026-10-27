# Vibe Shop (PHP 8.5 + SQLite, Docker) - DELIBERATELY VULNERABLE

A small shop written the way a rushed, AI-generated app often is: no framework, mixed HTML and
PHP, minimal validation. It exists only as a Site Guard **test target**. Synthetic data only
(users `alice`, `bob`, `admin`; 12 products; 3 orders), seeded deterministically from a fixed seed.

**Never expose this app beyond 127.0.0.1.** It contains planted weaknesses on purpose; the hand-authored
ground truth is in [`PLANTED.json`](PLANTED.json). The hand-fixed copy is `../vibe_shop_php_reference`
(ground truth for later verification; no scanner/fixer code may read it).

## Start / stop / reset
```
python scripts/lab_up.py vibe_shop_php        # build, start, health-check, prove 127.0.0.1-only
python scripts/lab_reset.py vibe_shop_php     # back to the seeded state, prints the state hash
python scripts/lab_down.py vibe_shop_php
```
or by hand: `docker compose up -d --build` in this folder (port `SHOP_PORT`, default **18080**, published
as `127.0.0.1:18080:80` only). The SQLite file and uploads live in `./data` (git-ignored).

Base image is pinned to `php:8.5.12-apache` (see docs/DECISIONS.md). Features: sign up / log in
(sessions), product list + search, product detail, cart, order creation, "my orders" and order detail,
profile with avatar upload, admin page, contact form, debug page, small JSON API, `/health.php`.

`python labs/vibe_shop_php/benign_traffic.py` exercises every legitimate feature (run it after a reset).
