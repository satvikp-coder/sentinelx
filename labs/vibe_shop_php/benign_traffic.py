"""Benign traffic for Vibe Shop (PHP): every legitimate feature, synthetic users only.

Usage: python labs/vibe_shop_php/benign_traffic.py [--base-url http://127.0.0.1:18080]
Run it against a freshly reset lab (scripts/lab_reset.py); it signs up one new synthetic user.
Works unchanged against the vulnerable lab and its reference copy.
"""

import argparse
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benign_common import TINY_PNG, Report, check  # noqa: E402


def run(base_url: str = "http://127.0.0.1:18080", lab: str = "vibe_shop_php") -> Report:
    rep = Report(lab, base_url)
    with httpx.Client(base_url=base_url, timeout=15, follow_redirects=False) as c, \
            httpx.Client(base_url=base_url, timeout=15, follow_redirects=False) as admin:
        check(rep, c, "browse products", "GET", "/index.php", 200, "<h1>Products</h1>")
        check(rep, c, "search products", "GET", "/index.php?q=mug", 200, "Blue Mug")
        check(rep, c, "product detail", "GET", "/product.php?id=3", 200, "Notebook A5")
        check(rep, c, "sign up", "POST", "/signup.php", 200, "Account created",
              data={"username": "newshopper", "password": "newshopperpass"})
        check(rep, c, "log in", "POST", "/login.php", 302, location_contains="/index.php",
              data={"username": "alice", "password": "alicepass"})
        check(rep, c, "logged-in home", "GET", "/index.php", 200, "(alice)")
        check(rep, c, "add to cart", "POST", "/cart.php", 200, "Green Mug x 2",
              data={"product_id": "2", "qty": "2"})
        check(rep, c, "view cart", "GET", "/cart.php", 200, "Your cart")
        placed = check(rep, c, "place order", "POST", "/order.php", 302,
                       location_contains="/order_view.php?id=4", data={"x": "1"})
        check(rep, c, "order confirmation", "GET", placed.headers["location"], 200,
              "Order placed")
        check(rep, c, "my orders", "GET", "/orders.php", 200, "Order #4")
        check(rep, c, "own order detail", "GET", "/order_view.php?id=1", 200, "<h1>Order #1</h1>")
        check(rep, c, "profile page", "GET", "/profile.php", 200, "Profile: alice")
        check(rep, c, "avatar upload", "POST", "/profile.php", 200, "Profile updated",
              files={"avatar": ("avatar.png", TINY_PNG, "image/png")})
        check(rep, c, "contact form", "POST", "/contact.php", 200, "Thanks Alice",
              data={"name": "Alice", "message": "Hello, do you ship to Canada?"})
        check(rep, c, "products API", "GET", "/api.php", 200, '"products"')
        check(rep, c, "log out", "GET", "/logout.php", 200, "Logged out")
        check(rep, admin, "admin log in", "POST", "/login.php", 302,
              location_contains="/index.php",
              data={"username": "admin", "password": "labadmin_FAKE_pass_2026"})
        check(rep, admin, "admin panel", "GET", "/admin.php", 200, "Admin panel")
        check(rep, admin, "debug page (admin)", "GET", "/info.php", 200, "Debug info")
    return rep


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:18080")
    args = ap.parse_args()
    rep = run(args.base_url)
    print(rep.to_json())
    print(f"features {rep.features}, requests {rep.requests}, passed {rep.passed}",
          file=sys.stderr)
    return 0 if rep.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
