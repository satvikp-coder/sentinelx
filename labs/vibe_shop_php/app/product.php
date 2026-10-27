<?php
require_once __DIR__ . '/bootstrap.php';
page_start('Product');
$id = $_GET['id'] ?? '1';
$row = db()->query("SELECT id, name, description, price_cents FROM products WHERE id = $id")->fetch(PDO::FETCH_ASSOC);
if (!$row) { echo '<p>Product not found</p>'; page_end(); exit; }
echo '<h1>' . h($row['name']) . '</h1><p>' . h($row['description']) . '</p>';
echo '<p>Price: $' . number_format($row['price_cents'] / 100, 2) . '</p>';
echo '<form method="post" action="/cart.php"><input type="hidden" name="product_id" value="' . (int)$row['id'] . '">';
echo 'Qty <input name="qty" value="1" size="2"><button>Add to cart</button></form>';
page_end();
