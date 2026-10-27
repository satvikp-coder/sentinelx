<?php
require_once __DIR__ . '/bootstrap.php';
require_login();
$u = current_user();
$note = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
    $kinds = ['image/png' => 'png', 'image/jpeg' => 'jpg', 'image/gif' => 'gif'];
    $tmp = $_FILES['avatar']['tmp_name'] ?? '';
    $mime = (is_uploaded_file($tmp) && $_FILES['avatar']['size'] <= 1048576) ? (new finfo(FILEINFO_MIME_TYPE))->file($tmp) : '';
    if (isset($kinds[$mime])) {
        $name = bin2hex(random_bytes(8)) . '.' . $kinds[$mime];
        move_uploaded_file($tmp, __DIR__ . '/uploads/' . $name);
        db()->prepare('UPDATE users SET avatar = ? WHERE id = ?')->execute([$name, $u['id']]);
        $note = 'Profile updated';
    } else {
        $note = 'Only image files are allowed';
    }
}
page_start('Profile');
echo '<h1>Profile: ' . h($u['username']) . '</h1>';
if ($note) echo '<p>' . h($note) . '</p>';
$st = db()->prepare('SELECT avatar FROM users WHERE id = ?');
$st->execute([$u['id']]);
$av = $st->fetchColumn();
if ($av) echo '<p>Avatar: <a href="/uploads/' . h($av) . '">' . h($av) . '</a></p>';
echo '<form method="post" enctype="multipart/form-data"><input type="file" name="avatar"><button>Upload avatar</button></form>';
page_end();
