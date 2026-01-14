<?php
declare(strict_types=1);

function find_user_by_identifier(PDO $pdo, string $identifier): ?array
{
    $stmt = $pdo->prepare(
        'SELECT id, username, email, password_hash FROM users WHERE username = :identifier OR email = :identifier_email LIMIT 1'
    );
    $stmt->execute([
        'identifier' => $identifier,
        'identifier_email' => $identifier,
    ]);
    $user = $stmt->fetch();

    return $user ?: null;
}

function find_user_by_username(PDO $pdo, string $username): ?array
{
    $stmt = $pdo->prepare(
        'SELECT id, username, email FROM users WHERE username = :username LIMIT 1'
    );
    $stmt->execute(['username' => $username]);
    $user = $stmt->fetch();

    return $user ?: null;
}

function find_user_by_email(PDO $pdo, string $email): ?array
{
    $stmt = $pdo->prepare(
        'SELECT id, username, email FROM users WHERE email = :email LIMIT 1'
    );
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch();

    return $user ?: null;
}

function create_user(PDO $pdo, ?string $username, ?string $email, string $passwordHash): int
{
    $stmt = $pdo->prepare(
        'INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password_hash)'
    );
    $stmt->execute([
        'username' => $username,
        'email' => $email,
        'password_hash' => $passwordHash,
    ]);

    return (int) $pdo->lastInsertId();
}

function create_vault_entry(
    PDO $pdo,
    int $userId,
    string $siteName,
    string $loginUsername,
    string $passwordCiphertext,
    ?string $iv,
    ?string $tag,
    bool $favorite = false
): int {
    $stmt = $pdo->prepare(
        'INSERT INTO vault_entries (user_id, site_name, login_username, login_password_ciphertext, login_password_iv, login_password_tag, favorite)'
        . ' VALUES (:user_id, :site_name, :login_username, :login_password_ciphertext, :login_password_iv, :login_password_tag, :favorite)'
    );
    $stmt->execute([
        'user_id' => $userId,
        'site_name' => $siteName,
        'login_username' => $loginUsername,
        'login_password_ciphertext' => $passwordCiphertext,
        'login_password_iv' => $iv,
        'login_password_tag' => $tag,
        'favorite' => $favorite ? 1 : 0,
    ]);

    return (int) $pdo->lastInsertId();
}

function list_vault_entries(PDO $pdo, int $userId, int $limit = 50, int $offset = 0): array
{
    $stmt = $pdo->prepare(
        'SELECT id, site_name, login_username, created_at'
        . ' FROM vault_entries WHERE user_id = :user_id ORDER BY created_at DESC LIMIT :limit OFFSET :offset'
    );
    $stmt->bindValue('user_id', $userId, PDO::PARAM_INT);
    $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue('offset', $offset, PDO::PARAM_INT);
    $stmt->execute();

    return $stmt->fetchAll();
}

function count_vault_entries(PDO $pdo, int $userId): int
{
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM vault_entries WHERE user_id = :user_id');
    $stmt->execute(['user_id' => $userId]);

    return (int) $stmt->fetchColumn();
}

function get_vault_entry_password(PDO $pdo, int $userId, int $entryId): ?string
{
    $stmt = $pdo->prepare(
        'SELECT login_password_ciphertext FROM vault_entries WHERE id = :id AND user_id = :user_id'
    );
    $stmt->execute([
        'id' => $entryId,
        'user_id' => $userId,
    ]);
    $password = $stmt->fetchColumn();

    return $password !== false ? (string) $password : null;
}

function update_vault_entry(
    PDO $pdo,
    int $userId,
    int $entryId,
    string $siteName,
    string $loginUsername,
    ?string $passwordCiphertext = null
): bool {
    if ($passwordCiphertext === null) {
        $stmt = $pdo->prepare(
            'UPDATE vault_entries SET site_name = :site_name, login_username = :login_username,'
            . ' updated_at = CURRENT_TIMESTAMP WHERE id = :id AND user_id = :user_id'
        );

        return $stmt->execute([
            'site_name' => $siteName,
            'login_username' => $loginUsername,
            'id' => $entryId,
            'user_id' => $userId,
        ]);
    }

    $stmt = $pdo->prepare(
        'UPDATE vault_entries SET site_name = :site_name, login_username = :login_username,'
        . ' login_password_ciphertext = :login_password_ciphertext, updated_at = CURRENT_TIMESTAMP'
        . ' WHERE id = :id AND user_id = :user_id'
    );

    return $stmt->execute([
        'site_name' => $siteName,
        'login_username' => $loginUsername,
        'login_password_ciphertext' => $passwordCiphertext,
        'id' => $entryId,
        'user_id' => $userId,
    ]);
}

function delete_vault_entry(PDO $pdo, int $userId, int $entryId): bool
{
    $stmt = $pdo->prepare('DELETE FROM vault_entries WHERE id = :id AND user_id = :user_id');
    $stmt->execute([
        'id' => $entryId,
        'user_id' => $userId,
    ]);

    return $stmt->rowCount() > 0;
}
