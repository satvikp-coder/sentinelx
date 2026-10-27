<?php
require_once __DIR__ . '/bootstrap.php';
$me = current_user();
if (!$me || !$me['is_admin']) { http_response_code(403); echo 'Forbidden'; exit; }
page_start('Debug');
echo '<h1>Debug info</h1><table>';
$rows = ['PHP version' => PHP_VERSION, 'Server software' => $_SERVER['SERVER_SOFTWARE'] ?? '',
         'Application' => APP_NAME];
foreach ($rows as $k => $v) echo '<tr><td>' . h($k) . '</td><td>' . h($v) . '</td></tr>';
echo '</table>';
page_end();
