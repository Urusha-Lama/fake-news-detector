<?php
/**
 * TruthGuard AI – predict.php
 * Sends news text to the Python/Flask ML API and returns the result.
 * Also saves the result to the analyses table if user is logged in.
 *
 * Expects POST: { "news": "article text here" }
 * Returns JSON: { "verdict": "fake|real", "confidence": 0.92, "label": "Fake News" }
 */

require_once 'config.php';
secureSession();

header('Content-Type: application/json');

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Get and validate input
$news = trim($_POST['news'] ?? '');

if (empty($news)) {
    http_response_code(400);
    echo json_encode(['error' => 'News text is required']);
    exit;
}

if (strlen($news) < 20) {
    http_response_code(400);
    echo json_encode(['error' => 'Please enter at least 20 characters']);
    exit;
}

if (strlen($news) > 10000) {
    http_response_code(400);
    echo json_encode(['error' => 'Text is too long (max 10,000 characters)']);
    exit;
}

// ── Call Flask ML API ────────────────────────────────────────
// Your friend runs: python app.py  →  starts on http://127.0.0.1:5000
// When working on SAME computer both use 127.0.0.1
// When on DIFFERENT computers your friend must share their IP (see README)

$flask_url = 'http://127.0.0.1:5000/predict';  // change IP if on different machines

$payload = json_encode(['text' => $news]);

$options = [
    'http' => [
        'method'        => 'POST',
        'header'        => "Content-Type: application/json\r\n"
                         . "Accept: application/json\r\n",
        'content'       => $payload,
        'timeout'       => 15,          // 15 second timeout
        'ignore_errors' => true,        // get response even on HTTP error codes
    ]
];

$context  = stream_context_create($options);
$response = @file_get_contents($flask_url, false, $context);

// ── Handle Flask errors ──────────────────────────────────────
if ($response === false) {
    // Flask server is not running or unreachable
    http_response_code(503);
    echo json_encode([
        'error'   => 'ML service unavailable',
        'message' => 'The ML model server is not running. '
                   . 'Ask your friend to start it with: python app.py',
        'debug'   => 'Could not connect to ' . $flask_url
    ]);
    exit;
}

$result = json_decode($response, true);

if (json_last_error() !== JSON_ERROR_NONE || !$result) {
    http_response_code(502);
    echo json_encode([
        'error'   => 'Invalid response from ML service',
        'raw'     => substr($response, 0, 200)
    ]);
    exit;
}

// ── Save result to database (if logged in) ───────────────────
if (!empty($_SESSION['user_id'])) {
    try {
        $db      = getDB();
        $verdict = $result['verdict'] ?? 'unverified';  // 'fake' | 'real' | 'unverified'
        $score   = isset($result['confidence'])
                   ? (int) round($result['confidence'] * 100)
                   : 50;
        $ip      = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        $db->prepare(
            "INSERT INTO analyses (user_id, content, verdict, score, ip_address, created_at)
             VALUES (?, ?, ?, ?, ?, NOW())"
        )->execute([$_SESSION['user_id'], $news, $verdict, $score, $ip]);

        // Add the DB id to the response
        $result['saved'] = true;
        $result['analysis_id'] = $db->lastInsertId();

    } catch (Exception $e) {
        // Don't fail the whole request just because DB save failed
        $result['saved'] = false;
    }
} else {
    $result['saved'] = false;
    $result['message'] = 'Log in to save your analysis history';
}

// ── Return result to frontend ────────────────────────────────
echo json_encode($result);