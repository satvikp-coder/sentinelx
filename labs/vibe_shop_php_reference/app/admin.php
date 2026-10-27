<?php
require_once __DIR__ . '/bootstrap.php';
$me = current_user();
if (!$me || !$me['is_admin']) { http_response_code(403); echo 'Forbidden'; exit; }
page_start('Admin');
echo '<h1>Admin panel</h1><h2>Users</h2><ul>';
foreach (db()->query('SELECT id, username, is_admin FROM users ORDER BY id')->fetchAll(PDO::FETCH_ASSOC) as $r) {
    echo '<li>#' . (int)$r['id'] . ' ' . h($r['username']) . ($r['is_admin'] ? ' (admin)' : '') . '</li>';
}
echo '</ul><h2>Orders</h2><ul>';
foreach (db()->query('SELECT id, user_id, total_cents FROM orders ORDER BY id')->fetchAll(PDO::FETCH_ASSOC) as $r) {
    echo '<li>Order #' . (int)$r['id'] . ' user ' . (int)$r['user_id'] . ' $' . number_format($r['total_cents'] / 100, 2) . '</li>';
}
echo '</ul>';
page_end();
