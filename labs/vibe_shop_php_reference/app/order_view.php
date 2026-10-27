<?php
require_once __DIR__ . '/bootstrap.php';
require_login();
$st = db()->prepare('SELECT id, user_id, total_cents, status, created_at FROM orders WHERE id = ?');
$st->execute([$_GET['id'] ?? 0]);
$o = $st->fetch(PDO::FETCH_ASSOC);
if (!$o || (int)$o['user_id'] !== (int)current_user()['id']) { http_response_code(404); page_start('Order'); echo '<p>Order not found</p>'; page_end(); exit; }
page_start('Order');
if (!empty($_GET['placed'])) echo '<p>Order placed. Thank you!</p>';
echo '<h1>Order #' . (int)$o['id'] . '</h1><p>Status: ' . h($o['status']) . '</p><p>Total: $' . number_format($o['total_cents'] / 100, 2) . '</p>';
$items = db()->prepare('SELECT p.name, i.qty FROM order_items i JOIN products p ON p.id = i.product_id WHERE i.order_id = ?');
$items->execute([$o['id']]);
echo '<ul>';
foreach ($items->fetchAll(PDO::FETCH_ASSOC) as $it) echo '<li>' . h($it['name']) . ' x ' . (int)$it['qty'] . '</li>';
echo '</ul>';
page_end();
