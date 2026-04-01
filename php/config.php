<?php
/**
 * TruthGuard AI – Database & App Configuration
 * Uses PDO (not mysqli) for prepared statements & security
 */

define('DB_HOST', 'localhost');
define('DB_NAME', 'truthguard');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

define('APP_NAME',    'TruthGuard AI');
define('APP_URL',     'http://localhost/fake-news-detector/php');  // change in production
define('SESSION_LIFETIME', 1800);   // 30 minutes idle timeout
define('MAX_LOGIN_ATTEMPTS', 5);    // brute-force lock
define('LOCKOUT_TIME', 900);        // 15 minutes lockout (seconds)
date_default_timezone_set('Asia/Kathmandu');
// ── PDO Connection (singleton) ──────────────────────────────
function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,   // real prepared statements
        ];
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            // Never expose DB errors to the browser
            error_log("DB Connection Error: " . $e->getMessage());
            http_response_code(500);
            die(json_encode(['success' => false, 'message' => 'Service temporarily unavailable.']));
        }
    }
    return $pdo;
}

// ── Secure Session Start ────────────────────────────────────
function secureSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure',   0);   // set to 1 on HTTPS
        ini_set('session.use_strict_mode', 1);
        ini_set('session.cookie_samesite', 'Strict');
        session_start();
    }

    // Idle timeout
    if (isset($_SESSION['last_activity'])) {
        if (time() - $_SESSION['last_activity'] > SESSION_LIFETIME) {
            session_unset();
            session_destroy();
            session_start();
        }
    }
    $_SESSION['last_activity'] = time();

    // Session fixation prevention – regenerate ID periodically
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } elseif (time() - $_SESSION['created'] > 300) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
}

// ── CSRF Token helpers ──────────────────────────────────────
function csrfToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCsrf(string $token): bool {
    return isset($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $token);
}

// ── Redirect helper ─────────────────────────────────────────
function redirect(string $url): void {
    header("Location: $url");
    exit;
}

// ── Auth guard ──────────────────────────────────────────────
function requireLogin(): void {
    secureSession();
    if (empty($_SESSION['user_id'])) {
        redirect(APP_URL . '/login.php');
    }
}
