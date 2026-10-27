"""Benign traffic for Vibe Notes (Node): every legitimate feature, synthetic users only.

Usage: python labs/vibe_notes_node/benign_traffic.py [--base-url http://127.0.0.1:18081]
Run it against a freshly reset lab (scripts/lab_reset.py); it signs up one new synthetic user and
changes one site setting as the synthetic admin. Works unchanged against the vulnerable lab and
its reference copy.
"""

import argparse
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benign_common import Report, check  # noqa: E402


def login(rep: Report, c: httpx.Client, who: str, password: str, feature: str) -> str:
    r = check(rep, c, feature, "POST", "/api/login", 200, '"ok":true',
              json={"username": who, "password": password})
    return str(r.json()["token"])


def run(base_url: str = "http://127.0.0.1:18081", lab: str = "vibe_notes_node") -> Report:
    rep = Report(lab, base_url)
    with httpx.Client(base_url=base_url, timeout=15) as c:
        check(rep, c, "front page", "GET", "/", 200, "Vibe Notes")
        check(rep, c, "health", "GET", "/health", 200, "ok")
        check(rep, c, "sign up", "POST", "/api/signup", 201, "account created",
              json={"username": "erin", "password": "erinpass"})
        token = login(rep, c, "carol", "carolpass", "log in")
        auth = {"Authorization": f"Bearer {token}"}
        check(rep, c, "list notes", "GET", "/api/notes", 200, "Garden plan", headers=auth)
        made = check(rep, c, "create note", "POST", "/api/notes", 201, "Reading list",
                     json={"title": "Reading list", "body": "three books"}, headers=auth)
        nid = made.json()["id"]
        check(rep, c, "view own note", "GET", "/api/notes/1", 200, "Garden plan", headers=auth)
        check(rep, c, "update note", "PUT", f"/api/notes/{nid}", 200, '"ok":true',
              json={"title": "Reading list", "body": "four books"}, headers=auth)
        check(rep, c, "search notes", "GET", "/api/search?q=plan", 200, "Garden plan",
              headers=auth)
        shared = check(rep, c, "share note", "POST", f"/api/notes/{nid}/share", 200, "/s/",
                       headers=auth)
        check(rep, c, "open share link", "GET", shared.json()["share_url"], 200, "Reading list")
        check(rep, c, "set profile bio", "PUT", "/api/profile", 200, '"ok":true',
              json={"bio": "Carol likes tea."}, headers=auth)
        check(rep, c, "public profile", "GET", "/u/carol", 200, "Carol likes tea.")
        check(rep, c, "read settings", "GET", "/api/settings", 200, "Welcome to Vibe Notes")
        atoken = login(rep, c, "admin", "labadmin_FAKE_pass_2026", "admin log in")
        admin = {"Authorization": f"Bearer {atoken}"}
        check(rep, c, "change a setting (admin)", "POST", "/api/settings", 200, '"ok":true',
              json={"theme": "dark"}, headers=admin)
        check(rep, c, "settings reflect change", "GET", "/api/settings", 200, '"theme":"dark"')
        check(rep, c, "debug route (admin)", "GET", "/debug", 200, "node", headers=admin)
        check(rep, c, "delete own note", "DELETE", f"/api/notes/{nid}", 200, '"ok":true',
              headers=auth)
    return rep


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:18081")
    args = ap.parse_args()
    rep = run(args.base_url)
    print(rep.to_json())
    print(f"features {rep.features}, requests {rep.requests}, passed {rep.passed}",
          file=sys.stderr)
    return 0 if rep.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
