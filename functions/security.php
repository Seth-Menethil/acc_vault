<?php
declare(strict_types=1);

function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();
    }
}

function set_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    $csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
        . "img-src 'self' data: https://lh3.googleusercontent.com; connect-src 'self'; frame-ancestors 'none'; "
        . "base-uri 'self'; form-action 'self'; object-src 'none'";
    header('Content-Security-Policy: ' . $csp);
}

function csrf_token(): string
{
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function verify_csrf(): void
{
    $sessionToken = $_SESSION['csrf_token'] ?? '';
    $token = '';

    if (isset($_POST['csrf_token'])) {
        $token = (string) $_POST['csrf_token'];
    } elseif (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
        $token = (string) $_SERVER['HTTP_X_CSRF_TOKEN'];
    }

    if ($sessionToken === '' || $token === '' || !hash_equals($sessionToken, $token)) {
        http_response_code(403);
        exit('Invalid CSRF token.');
    }
}
