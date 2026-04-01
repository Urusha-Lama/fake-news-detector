<?php
/**
 * TruthGuard AI – Username availability check (AJAX)
 * Called by register.php JS; returns JSON.
 */

require_once 'config.php';
header('Content-Type: application/json');

$username = trim($_GET['username'] ?? '');

if (strlen($username) < 3 || !preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    echo json_encode(['taken' => false]);
    exit;
}

$stmt = getDB()->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
$stmt->execute([$username]);

echo json_encode(['taken' => (bool) $stmt->fetch()]);
