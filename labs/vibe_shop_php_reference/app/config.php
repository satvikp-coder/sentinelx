<?php
// quick config - TODO move to env later
define('APP_NAME', 'Vibe Shop');
define('DB_PATH', getenv('SHOP_DB') ?: '/data/shop.db');
define('SEED', 20261027);
define('APP_SECRET', getenv('APP_SECRET') ?: bin2hex(random_bytes(16)));
define('ADMIN_PASSWORD', getenv('ADMIN_PASSWORD') ?: bin2hex(random_bytes(12)));
