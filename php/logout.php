<?php
/**
 * TruthGuard AI – Logout
 * Destroys session, clears remember-me cookie & DB token.
 */

require_once 'config.php';
secureSession();

// Remove remember_me cookie & DB token if present
if (!empty($_COOKIE['remember_token'])) {
    $hash = hash('sha256', $_COOKIE['remember_token']);
    try {
        getDB()->prepare("DELETE FROM remember_tokens WHERE token_hash = ?")
               ->execute([$hash]);
    } catch (Exception $e) {}

    setcookie('remember_token', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

// Destroy session completely
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $p['path'], $p['domain'], $p['secure'], $p['httponly']);
}
session_destroy();

// Redirect to login with confirmation message
redirect('/fake-news-detector/php/login.php?logged_out=1');
