<?php
// database helper: opens the SQLite file and seeds it deterministically on first use
function db() {
    static $pdo = null;
    if ($pdo) return $pdo;
    $fresh = !file_exists(DB_PATH);
    $pdo = new PDO('sqlite:' . DB_PATH);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA journal_mode=DELETE');
    if ($fresh) seed($pdo);
    return $pdo;
}

function seed($pdo) {
    $pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, pass_hash TEXT, is_admin INTEGER, avatar TEXT, created_at TEXT)');
    $pdo->exec('CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT, price_cents INTEGER)');
    $pdo->exec('CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER, total_cents INTEGER, status TEXT, created_at TEXT)');
    $pdo->exec('CREATE TABLE order_items (id INTEGER PRIMARY KEY, order_id INTEGER, product_id INTEGER, qty INTEGER)');
    $pdo->exec('CREATE TABLE messages (id INTEGER PRIMARY KEY, name TEXT, body TEXT, created_at TEXT)');
    $pdo->exec('CREATE TABLE login_attempts (id INTEGER PRIMARY KEY, username TEXT, ip TEXT, at INTEGER)');
    $when = '2026-10-27 09:00:00';
    $users = [['alice', 'alicepass', 0], ['bob', 'bobpass', 0], ['admin', ADMIN_PASSWORD, 1]];
    foreach ($users as $i => $u) {
        $st = $pdo->prepare('INSERT INTO users (id, username, pass_hash, is_admin, avatar, created_at) VALUES (?,?,?,?,?,?)');
        $st->execute([$i + 1, $u[0], password_hash($u[1], PASSWORD_DEFAULT), $u[2], '', $when]);
    }
    $names = ['Blue Mug', 'Green Mug', 'Notebook A5', 'Notebook A4', 'Desk Lamp', 'USB Cable', 'Sticker Pack',
              'Tote Bag', 'Water Bottle', 'Pen Set', 'Phone Stand', 'Mouse Pad'];
    $x = SEED;
    foreach ($names as $i => $n) {
        $x = ($x * 1103515245 + 12345) % 2147483648;
        $price = 500 + ($x % 4500);
        $st = $pdo->prepare('INSERT INTO products (id, name, description, price_cents) VALUES (?,?,?,?)');
        $st->execute([$i + 1, $n, "A very nice $n for everyday use.", $price]);
    }
    $orders = [[1, 1, 2, 1], [2, 1, 3, 2], [3, 2, 5, 1]];
    foreach ($orders as $o) {
        $total = 0;
        $p = $pdo->query('SELECT price_cents FROM products WHERE id = ' . (int)$o[2])->fetch(PDO::FETCH_ASSOC);
        $total = $p['price_cents'] * $o[3];
        $pdo->prepare('INSERT INTO orders (id, user_id, total_cents, status, created_at) VALUES (?,?,?,?,?)')
            ->execute([$o[0], $o[1], $total, 'paid', $when]);
        $pdo->prepare('INSERT INTO order_items (order_id, product_id, qty) VALUES (?,?,?)')
            ->execute([$o[0], $o[2], $o[3]]);
    }
}
