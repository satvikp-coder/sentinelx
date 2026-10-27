<?php
require_once __DIR__ . '/bootstrap.php';
require_login();
$u = current_user();
$note = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
    $name = $_FILES['avatar']['name'];
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])) {
        move_uploaded_file($_FILES['avatar']['tmp_name'], __DIR__ . '/uploads/' . $name);
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
