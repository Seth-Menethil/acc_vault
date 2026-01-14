<?php
declare(strict_types=1);

require_once __DIR__ . '/env.php';
load_env();

function sodium_available(): bool
{
    return function_exists('sodium_crypto_secretbox')
        && defined('SODIUM_CRYPTO_SECRETBOX_KEYBYTES')
        && defined('SODIUM_CRYPTO_SECRETBOX_NONCEBYTES');
}

function vault_key(): string
{
    $encoded = getenv('VAULT_KEY') ?: '';
    $decoded = base64_decode($encoded, true);

    if ($decoded === false) {
        throw new RuntimeException('Vault encryption key is not configured.');
    }

    $expectedLength = sodium_available() ? SODIUM_CRYPTO_SECRETBOX_KEYBYTES : 32;
    if (strlen($decoded) !== $expectedLength) {
        throw new RuntimeException('Vault encryption key is not configured.');
    }

    return $decoded;
}

function encrypt_secret(string $plaintext): string
{
    $key = vault_key();
    if (sodium_available()) {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

        return 'sodium:' . base64_encode($nonce . $ciphertext);
    }

    if (!function_exists('openssl_encrypt')) {
        throw new RuntimeException('Encryption is not available.');
    }

    $iv = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

    if ($ciphertext === false || $tag === '') {
        throw new RuntimeException('Unable to encrypt the password.');
    }

    return 'gcm:' . base64_encode($iv . $tag . $ciphertext);
}

function decrypt_secret(string $payload): string
{
    $key = vault_key();
    if (str_starts_with($payload, 'sodium:')) {
        if (!sodium_available()) {
            return '';
        }
        $raw = base64_decode(substr($payload, 7), true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return '';
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);

        return $plaintext === false ? '' : $plaintext;
    }

    if (str_starts_with($payload, 'gcm:')) {
        if (!function_exists('openssl_decrypt')) {
            return '';
        }
        $raw = base64_decode(substr($payload, 4), true);
        if ($raw === false || strlen($raw) < 28) {
            return '';
        }
        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);
        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

        return $plaintext === false ? '' : $plaintext;
    }

    if (sodium_available()) {
        $raw = base64_decode($payload, true);
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return '';
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);

        return $plaintext === false ? '' : $plaintext;
    }

    return '';
}
