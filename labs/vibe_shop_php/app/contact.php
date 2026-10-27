<?php
require_once __DIR__ . '/bootstrap.php';
page_start('Contact');
echo '<h1>Contact us</h1>';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $_POST['name'] ?? 'friend';
    $msg = $_POST['message'] ?? '';
    db()->prepare('INSERT INTO messages (name, body, created_at) VALUES (?,?,?)')->execute([$name, $msg, '2026-10-27 11:00:00']);
    echo '<p>Thanks ' . h($name) . ', we received your message:</p><blockquote>' . $msg . '</blockquote>';
}
echo '<form method="post"><input name="name"><textarea name="message"></textarea><button>Send</button></form>';
page_end();
