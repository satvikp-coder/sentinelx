<?php
require_once __DIR__ . '/bootstrap.php';
$allowed = ['http://127.0.0.1:18082', 'http://localhost:18082'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed, true)) {
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
}
header('Content-Type: application/json');
$rows = db()->query('SELECT id, name, price_cents FROM products ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
echo json_encode(['products' => $rows]);
