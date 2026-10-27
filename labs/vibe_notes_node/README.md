# Vibe Notes (Node + Express + SQLite) - DELIBERATELY VULNERABLE

A notes/todo API with a tiny HTML front end, written the way a rushed, AI-generated Express app often
is. A Site Guard **test target** only. Synthetic data (users `carol`, `dave`, `admin`; 6 notes),
deterministic seed. Uses Node's built-in `node:sqlite` (Node 22.5+; tested on Node 24), so there is no
native compilation on Windows; the only dependency is `express` (pinned; it carries known advisories
that are NOT part of the scored ground truth).

**Listens on 127.0.0.1 only.** Planted weaknesses are in [`PLANTED.json`](PLANTED.json); the hand-fixed
copy is `../vibe_notes_node_reference` (no scanner/fixer code may read it).

## Start / stop / reset
```
python scripts/lab_up.py vibe_notes_node      # npm install (first time), start, health-check, loopback proof
python scripts/lab_reset.py vibe_notes_node   # back to the seeded state, prints the state hash
python scripts/lab_down.py vibe_notes_node
```
by hand: `npm install` then `npm start` here (`NOTES_PORT`, default **18081**). Optional Docker:
`docker compose up -d --build` (published as `127.0.0.1:18081` only).

Features: sign up, log in (bearer token or `sid` cookie), notes CRUD by id, share link, public profile
page, search, site settings, `/debug`, `/health`. `python labs/vibe_notes_node/benign_traffic.py`
exercises every legitimate feature (run it after a reset).
