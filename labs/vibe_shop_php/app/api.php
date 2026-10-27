<?php
require_once __DIR__ . '/bootstrap.php';
$origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
header('Access-Control-Allow-Origin: ' . $origin);
header('Access-Control-Allow-Credentials: true');
header('Content-Type: application/json');
$rows = db()->query('SELECT id, name, price_cents FROM products ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
echo json_encode(['products' => $rows]);
