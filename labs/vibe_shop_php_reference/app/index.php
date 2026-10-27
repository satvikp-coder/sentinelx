<?php
require_once __DIR__ . '/bootstrap.php';
page_start('Products');
$q = $_GET['q'] ?? '';
$st = db()->prepare('SELECT id, name, price_cents FROM products WHERE name LIKE ? ORDER BY id');
$st->execute(['%' . $q . '%']);
$rows = $st->fetchAll(PDO::FETCH_ASSOC);
echo '<h1>Products</h1>';
echo '<form method="get" action="/index.php"><input name="q" value="' . h($q) . '"><button>Search</button></form>';
echo '<p>Showing ' . count($rows) . ' products</p><ul>';
foreach ($rows as $r) {
    echo '<li><a href="/product.php?id=' . (int)$r['id'] . '">' . h($r['name']) . '</a> - $' . number_format($r['price_cents'] / 100, 2) . '</li>';
}
echo '</ul>';
page_end();
