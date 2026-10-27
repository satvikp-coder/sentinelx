<?php
require_once __DIR__ . '/bootstrap.php';
page_start('Debug');
echo '<h1>Debug info</h1><table>';
$rows = ['PHP version' => PHP_VERSION, 'Server software' => $_SERVER['SERVER_SOFTWARE'] ?? '',
         'Document root' => $_SERVER['DOCUMENT_ROOT'] ?? '', 'Database path' => DB_PATH,
         'App secret' => APP_SECRET, 'Admin password' => ADMIN_PASSWORD, 'Session id' => session_id()];
foreach ($rows as $k => $v) echo '<tr><td>' . h($k) . '</td><td>' . h($v) . '</td></tr>';
echo '</table>';
page_end();
