<?php

declare(strict_types=1);

require_once __DIR__ . '/../functions/env.php';
load_env();

$DB_HOST = getenv('DB_HOST') ?: 'localhost';

$DB_NAME = getenv('DB_NAME') ?: 'acc_vault';

$DB_USER = getenv('DB_USER') ?: 'root';

$DB_PASS = getenv('DB_PASS') ?: '';



$dsn = sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', $DB_HOST, $DB_NAME);



$options = [

  PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,

  PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,

  PDO::ATTR_EMULATE_PREPARES => false,

];



try {

  $pdo = new PDO($dsn, $DB_USER, $DB_PASS, $options);
} catch (PDOException $e) {

  http_response_code(500);

  exit('Database connection error.');
}



return $pdo;
