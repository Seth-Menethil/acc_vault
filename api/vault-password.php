<?php
declare(strict_types=1);

require_once __DIR__ . '/../functions/security.php';
require_once __DIR__ . '/../functions/crypto.php';

start_secure_session();
set_security_headers();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

verify_csrf();

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit;
}

$rawBody = file_get_contents('php://input');
$payload = json_decode($rawBody, true);

if (!is_array($payload)) {
    $payload = $_POST;
}

$entryId = (int) ($payload['entry_id'] ?? 0);

if ($entryId <= 0) {
    http_response_code(400);
    exit;
}

$pdo = require __DIR__ . '/../connection/dbconn.php';
require_once __DIR__ . '/../functions/queries.php';

$ciphertext = get_vault_entry_password($pdo, (int) $_SESSION['user_id'], $entryId);

if ($ciphertext === null) {
    http_response_code(404);
    exit;
}

try {
    $password = decrypt_secret($ciphertext);
} catch (RuntimeException $e) {
    http_response_code(500);
    exit;
}

header('Content-Type: application/json');
echo json_encode(['password' => $password], JSON_UNESCAPED_SLASHES);
