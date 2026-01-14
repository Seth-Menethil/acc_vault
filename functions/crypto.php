<?php
declare(strict_types=1);

require_once __DIR__ . '/env.php';
load_env();

function vault_key(): string
{
    $encoded = getenv('VAULT_KEY') ?: '';
    $decoded = base64_decode($encoded, true);

    if ($decoded === false || strlen($decoded) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
        throw new RuntimeException('Vault encryption key is not configured.');
    }

    return $decoded;
}

function encrypt_secret(string $plaintext): string
{
    $key = vault_key();
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

    return base64_encode($nonce . $ciphertext);
}

function decrypt_secret(string $payload): string
{
    $key = vault_key();
    $raw = base64_decode($payload, true);

    if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        return $payload;
    }

    $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $ciphertext = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);

    if ($plaintext === false) {
        return $payload;
    }

    return $plaintext;
}
