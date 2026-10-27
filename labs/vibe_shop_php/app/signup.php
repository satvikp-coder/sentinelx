<?php
require_once __DIR__ . '/bootstrap.php';
page_start('Sign up');
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = trim($_POST['username'] ?? '');
    $p = $_POST['password'] ?? '';
    if ($u === '' || $p === '') { echo '<p>Username and password are required</p>'; }
    else {
        try {
            db()->prepare('INSERT INTO users (username, pass_hash, is_admin, avatar, created_at) VALUES (?,?,0,?,?)')
                ->execute([$u, password_hash($p, PASSWORD_DEFAULT), '', '2026-10-27 09:30:00']);
            echo '<p>Account created. <a href="/login.php">Log in</a></p>';
        } catch (PDOException $e) { echo '<p>That username is taken</p>'; }
    }
}
echo '<h1>Sign up</h1><form method="post"><input name="username"><input name="password" type="password"><button>Create account</button></form>';
page_end();
