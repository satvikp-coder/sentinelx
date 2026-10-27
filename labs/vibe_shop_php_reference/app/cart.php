<?php
require_once __DIR__ . '/bootstrap.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pid = (int)($_POST['product_id'] ?? 0);
    $qty = max(1, (int)($_POST['qty'] ?? 1));
    $_SESSION['cart'][$pid] = ($_SESSION['cart'][$pid] ?? 0) + $qty;
}
page_start('Cart');
echo '<h1>Your cart</h1>';
$cart = $_SESSION['cart'] ?? [];
if (!$cart) echo '<p>Your cart is empty</p>';
else {
    echo '<ul>';
    foreach ($cart as $pid => $qty) {
        $st = db()->prepare('SELECT name FROM products WHERE id = ?');
        $st->execute([$pid]);
        $p = $st->fetch(PDO::FETCH_ASSOC);
        echo '<li>' . h($p['name'] ?? '?') . ' x ' . (int)$qty . '</li>';
    }
    echo '</ul><form method="post" action="/order.php"><button>Place order</button></form>';
}
page_end();
