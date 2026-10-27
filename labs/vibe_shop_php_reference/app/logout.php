<?php
require_once __DIR__ . '/bootstrap.php';
session_destroy();
page_start('Logged out');
echo '<h1>Logged out</h1><p>See you soon.</p>';
page_end();
