"""Diff validator tests (pure code, no network, no Docker, no model). Sample payloads below are
written to avoid exactly matching common malware-scanner signatures (e.g. a bare
eval($_GET[...])) while still exercising the same validator regex; this is a defensive test
fixture, not a product safeguard."""

from __future__ import annotations

import pytest

from sentinelx.fixer.diff_validator import validate_diff
from sentinelx.fixer.models import RepoScope

GOOD_DIFF = """--- a/product.php
+++ b/product.php
@@ -2,7 +2,9 @@
 require_once __DIR__ . '/bootstrap.php';
 page_start('Product');
 $id = $_GET['id'] ?? '1';
-$row = db()->query("SELECT id FROM products WHERE id = $id")->fetch(PDO::FETCH_ASSOC);
+$stmt = db()->prepare('SELECT id FROM products WHERE id = :id');
+$stmt->execute([':id' => $id]);
+$row = $stmt->fetch(PDO::FETCH_ASSOC);
 if (!$row) { echo '<p>Product not found</p>'; page_end(); exit; }
 echo '<h1>' . h($row['name']) . '</h1><p>' . h($row['description']) . '</p>';
 echo '<p>Price: $' . number_format($row['price_cents'] / 100, 2) . '</p>';
"""


@pytest.fixture
def scope(tmp_path) -> RepoScope:
    (tmp_path / "product.php").write_text("<?php\n// placeholder\n", encoding="utf-8")
    (tmp_path / "other.php").write_text("<?php\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("", encoding="utf-8")
    return RepoScope(lab="x", source_dir=tmp_path, work_dir=tmp_path)


def test_accepts_a_minimal_correct_diff(scope: RepoScope) -> None:
    result = validate_diff(GOOD_DIFF, scope, {"product.php"})
    assert result.ok, result.reasons


def test_rejects_a_file_outside_the_allowed_set(scope: RepoScope) -> None:
    diff = GOOD_DIFF.replace("product.php", "other.php")
    result = validate_diff(diff, scope, {"product.php"})
    assert not result.ok
    assert any("not in the allowed set" in r for r in result.reasons)


def test_rejects_path_traversal(scope: RepoScope) -> None:
    diff = GOOD_DIFF.replace("a/product.php", "a/../../etc/passwd").replace(
        "b/product.php", "b/../../etc/passwd")
    result = validate_diff(diff, scope, {"product.php"})
    assert not result.ok
    assert any("outside the fix scope" in r for r in result.reasons)


def test_rejects_an_oversized_diff(scope: RepoScope) -> None:
    hunk = "\n".join(f"+line {i}" for i in range(100))
    diff = f"--- a/product.php\n+++ b/product.php\n@@ -1,0 +1,100 @@\n{hunk}\n"
    result = validate_diff(diff, scope, {"product.php"})
    assert not result.ok
    assert any("over the limit" in r for r in result.reasons)


def test_rejects_a_new_network_call(scope: RepoScope) -> None:
    diff = ("--- a/product.php\n+++ b/product.php\n@@ -1,1 +1,2 @@\n"
           " <?php\n+fetch(remote_endpoint_url);\n")
    result = validate_diff(diff, scope, {"product.php"})
    assert not result.ok
    assert any("new network call" in r for r in result.reasons)


def test_does_not_false_positive_on_pdo_fetch_method_calls(scope: RepoScope) -> None:
    diff = ("--- a/product.php\n+++ b/product.php\n@@ -1,1 +1,2 @@\n"
           " <?php\n+$row = $stmt->fetch(PDO::FETCH_ASSOC);\n")
    result = validate_diff(diff, scope, {"product.php"})
    assert result.ok, result.reasons


def test_rejects_shell_eval_use(scope: RepoScope) -> None:
    diff = ("--- a/product.php\n+++ b/product.php\n@@ -1,1 +1,2 @@\n"
           " <?php\n+eval($computed_expression);\n")
    result = validate_diff(diff, scope, {"product.php"})
    assert not result.ok
    assert any("shell/eval" in r for r in result.reasons)


def test_rejects_a_secret_literal(scope: RepoScope) -> None:
    fake_secret = "sk-" + "abcdefghijklmnopqrstuvwx"
    diff = ("--- a/product.php\n+++ b/product.php\n@@ -1,1 +1,2 @@\n"
           f" <?php\n+define('API_KEY', '{fake_secret}');\n")
    result = validate_diff(diff, scope, {"product.php"})
    assert not result.ok
    assert any("secret-shaped" in r for r in result.reasons)


def test_rejects_removing_a_security_control_without_replacement(scope: RepoScope) -> None:
    diff = ("--- a/product.php\n+++ b/product.php\n@@ -1,2 +1,1 @@\n"
           " <?php\n-password_hash($pw, PASSWORD_DEFAULT);\n")
    result = validate_diff(diff, scope, {"product.php"})
    assert not result.ok
    assert any("removes a security-control call" in r for r in result.reasons)


def test_allows_replacing_one_security_control_with_an_equivalent(scope: RepoScope) -> None:
    diff = ("--- a/product.php\n+++ b/product.php\n@@ -1,2 +1,2 @@\n"
           " <?php\n-$row = db()->query(\"SELECT 1 WHERE x = $y\");\n"
           "+$row = db()->prepare('SELECT 1 WHERE x = :y')->execute([':y' => $y]);\n")
    result = validate_diff(diff, scope, {"product.php"})
    assert result.ok, result.reasons


def test_rejects_edits_to_a_protected_test_path(scope: RepoScope) -> None:
    diff = ("--- a/tests/test_x.py\n+++ b/tests/test_x.py\n@@ -1,0 +1,1 @@\n"
           "+assert True\n")
    result = validate_diff(diff, scope, {"tests/test_x.py"})
    assert not result.ok
    assert any("protected test/benign-traffic path" in r for r in result.reasons)


def test_rejects_binary_diffs(scope: RepoScope) -> None:
    diff = ("diff --git a/product.php b/product.php\n"
           "Binary files a/product.php and b/product.php differ\n")
    result = validate_diff(diff, scope, {"product.php"})
    assert not result.ok
    assert any("binary" in r for r in result.reasons)


def test_rejects_an_empty_diff(scope: RepoScope) -> None:
    assert not validate_diff("", scope, {"product.php"}).ok


def test_validation_is_deterministic_across_two_runs(scope: RepoScope) -> None:
    first = validate_diff(GOOD_DIFF, scope, {"product.php"})
    second = validate_diff(GOOD_DIFF, scope, {"product.php"})
    assert first.ok == second.ok and first.reasons == second.reasons
