<?php
declare(strict_types=1);

$key = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
echo base64_encode($key);
