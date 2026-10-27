<?php
require_once __DIR__ . '/bootstrap.php';
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $st = db()->prepare('SELECT id, username, pass_hash FROM users WHERE username = ?');
    $st->execute([$_POST['username'] ?? '']);
    $u = $st->fetch(PDO::FETCH_ASSOC);
    if ($u && password_verify($_POST['password'] ?? '', $u['pass_hash'])) {
        $_SESSION['uid'] = $u['id'];
        header('Location: /index.php');
        exit;
    }
    $msg = 'Invalid credentials';
}
page_start('Login');
echo '<h1>Login</h1>';
if ($msg) echo '<p>' . h($msg) . '</p>';
echo '<form method="post"><input name="username"><input name="password" type="password"><button>Log in</button></form>';
page_end();
