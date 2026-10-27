<?php
require_once __DIR__ . '/bootstrap.php';
require_login();
$cart = $_SESSION['cart'] ?? [];
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$cart) { header('Location: /cart.php'); exit; }
$pdo = db();
$total = 0;
foreach ($cart as $pid => $qty) {
    $st = $pdo->prepare('SELECT price_cents FROM products WHERE id = ?');
    $st->execute([$pid]);
    $total += (int)$st->fetchColumn() * $qty;
}
$pdo->prepare('INSERT INTO orders (user_id, total_cents, status, created_at) VALUES (?,?,?,?)')
    ->execute([current_user()['id'], $total, 'paid', '2026-10-27 10:00:00']);
$oid = $pdo->lastInsertId();
foreach ($cart as $pid => $qty) {
    $pdo->prepare('INSERT INTO order_items (order_id, product_id, qty) VALUES (?,?,?)')->execute([$oid, $pid, $qty]);
}
$_SESSION['cart'] = [];
header('Location: /order_view.php?id=' . $oid . '&placed=1');
