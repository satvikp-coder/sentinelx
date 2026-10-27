<?php
// shared setup for every page
error_reporting(E_ALL);
ini_set('display_errors', '0');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'httponly' => false, 'secure' => false]);
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES); }

function current_user() {
    if (empty($_SESSION['uid'])) return null;
    $st = db()->prepare('SELECT id, username, is_admin FROM users WHERE id = ?');
    $st->execute([$_SESSION['uid']]);
    return $st->fetch(PDO::FETCH_ASSOC) ?: null;
}

function require_login() {
    if (!current_user()) { header('Location: /login.php'); exit; }
}

function page_start($title) {
    $u = current_user();
    echo '<!doctype html><html><head><meta charset="utf-8"><title>' . h($title) . ' - ' . APP_NAME . '</title></head><body>';
    echo '<nav><a href="/index.php">Shop</a> | <a href="/cart.php">Cart</a> | <a href="/contact.php">Contact</a>';
    if ($u) echo ' | <a href="/orders.php">My orders</a> | <a href="/profile.php">Profile</a> | <a href="/logout.php">Logout</a> (' . h($u['username']) . ')';
    else echo ' | <a href="/login.php">Login</a> | <a href="/signup.php">Sign up</a>';
    echo '</nav><hr>';
}

function page_end() { echo '</body></html>'; }
