<?php
require_once __DIR__ . '/bootstrap.php';
require_login();
page_start('My orders');
$st = db()->prepare('SELECT id, total_cents, status FROM orders WHERE user_id = ? ORDER BY id');
$st->execute([current_user()['id']]);
echo '<h1>My orders</h1><ul>';
foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $o) {
    echo '<li><a href="/order_view.php?id=' . (int)$o['id'] . '">Order #' . (int)$o['id'] . '</a> - $' . number_format($o['total_cents'] / 100, 2) . ' (' . h($o['status']) . ')</li>';
}
echo '</ul>';
page_end();
