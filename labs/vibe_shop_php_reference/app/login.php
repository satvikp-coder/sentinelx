<?php
require_once __DIR__ . '/bootstrap.php';
$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $who = (string)($_POST['username'] ?? '');
    $recent = db()->prepare('SELECT COUNT(*) FROM login_attempts WHERE username = ? AND at > ?');
    $recent->execute([$who, time() - 60]);
    if ((int)$recent->fetchColumn() >= 5) {
        http_response_code(429);
        header('Retry-After: 60');
        echo 'Too many attempts, try again later';
        exit;
    }
    $st = db()->prepare('SELECT id, username, pass_hash FROM users WHERE username = ?');
    $st->execute([$_POST['username'] ?? '']);
    $u = $st->fetch(PDO::FETCH_ASSOC);
    if ($u && password_verify($_POST['password'] ?? '', $u['pass_hash'])) {
        $_SESSION['uid'] = $u['id'];
        header('Location: /index.php');
        exit;
    }
    db()->prepare('INSERT INTO login_attempts (username, ip, at) VALUES (?,?,?)')
        ->execute([$who, $_SERVER['REMOTE_ADDR'] ?? '', time()]);
    $msg = 'Invalid credentials';
}
page_start('Login');
echo '<h1>Login</h1>';
if ($msg) echo '<p>' . h($msg) . '</p>';
echo '<form method="post"><input name="username"><input name="password" type="password"><button>Log in</button></form>';
page_end();
