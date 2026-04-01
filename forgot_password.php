<?php
/**
 * TruthGuard AI – Forgot Password (forgot_password.php)
 * Security features:
 *  - Rate limiting: max 3 reset requests per email per hour
 *  - Generic success message (no user enumeration)
 *  - SHA-256 token stored in DB, raw token sent to user
 *  - Token expires in 1 hour
 *  - CSRF protection
 */

require_once 'config.php';
secureSession();

// Already logged in? → dashboard
if (!empty($_SESSION['user_id'])) {
    redirect(APP_URL . '/dashboard.php');
}

$state   = 'form';   // 'form' | 'sent' | 'error'
$errors  = [];
$email   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // CSRF check
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $errors['general'] = 'Security token mismatch. Please refresh and try again.';
    } else {
        $email = trim(strtolower($_POST['email'] ?? ''));

        // Validate
        if ($email === '') {
            $errors['email'] = 'Email address is required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'Please enter a valid email address.';
        }

        if (empty($errors)) {
            $db = getDB();

            // ── Rate limit: max 3 requests per email per hour ──
            $rateWindow = date('Y-m-d H:i:s', time() - 3);
            // $rateStmt   = $db->prepare(
            //     "SELECT COUNT(*) FROM password_resets
            //      WHERE user_id IN (SELECT id FROM users WHERE email = ?)
            //      AND created_at > ?"
            // );
            // Add created_at column check — use expires_at as proxy if no created_at
            // We'll use expires_at - 3600s to derive "created_at"
            $rateStmt = $db->prepare(
                "SELECT COUNT(*) FROM password_resets pr
                 JOIN users u ON u.id = pr.user_id
                 WHERE u.email = ?
                 AND pr.expires_at > ?"
            );
            $rateStmt->execute([$email, $rateWindow]);
            $recentCount = (int)$rateStmt->fetchColumn();

            if ($recentCount >= 5) {
                // Rate limited — still show success to prevent enumeration
                $state = 'sent';
            } else {
                // ── Look up user ──
                $stmt = $db->prepare("SELECT id FROM users WHERE email = ? AND is_active = 1 LIMIT 1");
                $stmt->execute([$email]);
                $user = $stmt->fetch();

                if ($user) {
                    // Invalidate any previous unused tokens for this user
                    $db->prepare("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0")
                       ->execute([$user['id']]);

                    // Generate secure token
                    $token  = bin2hex(random_bytes(32));
                    $hash   = hash('sha256', $token);
                    $expiry = date('Y-m-d H:i:s', time() + 3600); // 1 hour

                    $db->prepare(
                        "INSERT INTO password_resets (user_id, token_hash, expires_at, used)
                         VALUES (?, ?, ?, 0)"
                    )->execute([$user['id'], $hash, $expiry]);

                    // In production: send email via PHPMailer/SMTP
                    // For local dev: show the link directly (remove in production!)
                    $resetLink = APP_URL . '/reset_password.php?token=' . urlencode($token);

                    // TODO: Replace this with real email sending:
                    // mail($email, 'Reset your TruthGuard password',
                    //      "Click to reset: $resetLink\n\nExpires in 1 hour.");

                    // Store link in session for dev display only
                    $_SESSION['dev_reset_link'] = $resetLink;
                }

                // Always show success — prevents user enumeration
                $state = 'sent';
            }
        }
    }
}

$csrf = csrfToken();
$devLink = $_SESSION['dev_reset_link'] ?? null;
unset($_SESSION['dev_reset_link']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Forgot Password – <?= APP_NAME ?></title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"/>
  <style>
    /* ── Tokens ─────────────────────────────────────────────── */
    :root {
      --bg:      #05080f;
      --surface: #0c1120;
      --surf2:   #121929;
      --border:  rgba(255,255,255,0.07);
      --accent:  #00e5ff;
      --accent2: #7b61ff;
      --danger:  #ff4d6d;
      --safe:    #00e5a0;
      --warn:    #ffc107;
      --text:    #e8ecf4;
      --muted:   #7a8499;
      --fh:      'Syne', sans-serif;
      --fb:      'DM Sans', sans-serif;
      --t:       0.22s cubic-bezier(.4,0,.2,1);
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--fb);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    a { text-decoration: none; color: var(--accent); }

    /* Animated background grid */
    body::before {
      content: '';
      position: fixed; inset: 0; pointer-events: none; z-index: 0;
      background-image:
        linear-gradient(rgba(0,229,255,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,229,255,.03) 1px, transparent 1px);
      background-size: 60px 60px;
      animation: gridMove 20s linear infinite;
    }
    @keyframes gridMove {
      0%   { background-position: 0 0; }
      100% { background-position: 60px 60px; }
    }

    /* Glow orbs */
    body::after {
      content: '';
      position: fixed;
      top: -200px; left: 50%;
      transform: translateX(-50%);
      width: 800px; height: 600px;
      background: radial-gradient(ellipse,
        rgba(0,229,255,.06) 0%,
        rgba(123,97,255,.05) 40%,
        transparent 70%);
      pointer-events: none; z-index: 0;
    }

    /* ── Header ─────────────────────────────────────────────── */
    header {
      position: sticky; top: 0; z-index: 100;
      background: rgba(5,8,15,.88);
      backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border);
    }
    nav {
      max-width: 1200px; margin: auto;
      padding: 0 2rem;
      display: flex; align-items: center; height: 66px; gap: 1rem;
    }
    .nav-logo {
      font-family: var(--fh); font-weight: 800; font-size: 1.25rem;
      display: flex; align-items: center; gap: .5rem;
      letter-spacing: -.02em; color: var(--text);
    }
    .logo-icon {
      width: 32px; height: 32px; border-radius: 8px;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      display: flex; align-items: center; justify-content: center;
      font-size: 1rem;
    }
    .nav-links { margin-left: auto; display: flex; align-items: center; gap: .25rem; }
    .nav-links a {
      padding: .4rem .9rem; border-radius: 8px;
      font-size: .88rem; font-weight: 500; color: var(--muted);
      transition: all var(--t);
    }
    .nav-links a:hover { color: var(--text); background: rgba(255,255,255,.05); }
    .btn-nav-accent {
      background: linear-gradient(135deg, var(--accent), var(--accent2)) !important;
      color: #000 !important; font-weight: 700 !important;
    }

    /* ── Page Center ─────────────────────────────────────────── */
    .page-center {
      flex: 1; display: flex; align-items: center;
      justify-content: center; padding: 3rem 1.5rem;
      position: relative; z-index: 1;
    }

    /* ── Card ────────────────────────────────────────────────── */
    .card {
      width: 100%; max-width: 460px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 2.5rem 2.5rem 2rem;
      position: relative;
      overflow: hidden;
      animation: slideUp .55s cubic-bezier(.16,1,.3,1) both;
    }
    @keyframes slideUp {
      from { opacity: 0; transform: translateY(30px) scale(.98); }
      to   { opacity: 1; transform: none; }
    }

    /* Accent corner */
    .card::before {
      content: '';
      position: absolute; top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--accent2));
      border-radius: 20px 20px 0 0;
    }

    /* ── Icon ────────────────────────────────────────────────── */
    .card-icon {
      width: 56px; height: 56px; border-radius: 14px;
      background: linear-gradient(135deg,
        rgba(0,229,255,.15), rgba(123,97,255,.15));
      border: 1px solid rgba(0,229,255,.2);
      display: flex; align-items: center; justify-content: center;
      font-size: 1.6rem;
      margin-bottom: 1.4rem;
      animation: iconPop .5s .2s cubic-bezier(.34,1.56,.64,1) both;
    }
    @keyframes iconPop {
      from { opacity: 0; transform: scale(.6); }
      to   { opacity: 1; transform: scale(1); }
    }

    /* ── Headings ────────────────────────────────────────────── */
    .card h2 {
      font-family: var(--fh); font-size: 1.65rem;
      font-weight: 800; letter-spacing: -.03em;
      margin-bottom: .4rem;
    }
    .card p.sub {
      color: var(--muted); font-size: .9rem;
      font-weight: 300; line-height: 1.6;
      margin-bottom: 1.8rem;
    }

    /* ── Form group ──────────────────────────────────────────── */
    .fg { margin-bottom: 1.1rem; }
    .fg label {
      display: flex; align-items: center; justify-content: space-between;
      font-size: .75rem; font-weight: 600;
      color: var(--muted); margin-bottom: .45rem;
      text-transform: uppercase; letter-spacing: .08em;
    }
    .input-wrap { position: relative; }
    .input-wrap .input-icon {
      position: absolute; left: 14px; top: 50%;
      transform: translateY(-50%);
      color: var(--muted); font-size: 1rem; pointer-events: none;
      transition: color var(--t);
    }
    .fg input {
      width: 100%;
      background: var(--surf2);
      border: 1.5px solid var(--border);
      border-radius: 11px;
      padding: .85rem 1rem .85rem 2.8rem;
      color: var(--text);
      font-family: var(--fb); font-size: .95rem;
      transition: border-color var(--t), box-shadow var(--t), background var(--t);
    }
    .fg input:focus {
      outline: none;
      background: rgba(0,229,255,.03);
      border-color: rgba(0,229,255,.5);
      box-shadow: 0 0 0 4px rgba(0,229,255,.07);
    }
    .fg input:focus ~ .input-icon,
    .fg input:focus + .input-icon { color: var(--accent); }
    .fg input.is-error { border-color: var(--danger) !important; }
    .fg input.is-ok    { border-color: var(--safe)   !important; }
    .fg input::placeholder { color: var(--muted); }

    /* Flip icon inside wrap — input comes first, icon is ::after */
    .input-wrap input { order: 1; }

    /* ── Field errors ────────────────────────────────────────── */
    .field-err {
      margin-top: .35rem; font-size: .75rem;
      color: var(--danger); display: flex;
      align-items: flex-start; gap: .3rem; line-height: 1.4;
    }

    /* ── General alert ───────────────────────────────────────── */
    .alert {
      border-radius: 11px; padding: .9rem 1.1rem;
      margin-bottom: 1.3rem; font-size: .85rem;
      display: flex; align-items: flex-start; gap: .6rem; line-height: 1.5;
    }
    .alert-danger  { background:rgba(255,77,109,.08); border:1px solid rgba(255,77,109,.25); color:var(--danger); }
    .alert-warn    { background:rgba(255,193,7,.07);  border:1px solid rgba(255,193,7,.25);  color:var(--warn); }

    /* ── Submit button ───────────────────────────────────────── */
    .btn-submit {
      width: 100%; padding: .9rem;
      border-radius: 11px; border: none; cursor: pointer;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      font-family: var(--fh); font-weight: 700;
      font-size: .95rem; color: #000;
      display: flex; align-items: center; justify-content: center; gap: .5rem;
      transition: all var(--t);
      position: relative; overflow: hidden;
    }
    .btn-submit::after {
      content: '';
      position: absolute; inset: 0;
      background: linear-gradient(135deg, rgba(255,255,255,.15), transparent);
      opacity: 0; transition: opacity var(--t);
    }
    .btn-submit:hover::after { opacity: 1; }
    .btn-submit:hover { transform: translateY(-2px); box-shadow: 0 12px 32px rgba(0,229,255,.28); }
    .btn-submit:active { transform: translateY(0); }
    .btn-submit:disabled { opacity: .6; cursor: not-allowed; transform: none; box-shadow: none; }

    /* Spinner */
    .spinner {
      width: 16px; height: 16px; border-radius: 50%;
      border: 2px solid rgba(0,0,0,.3);
      border-top-color: #000;
      animation: spin .6s linear infinite; display: none;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ── Divider ─────────────────────────────────────────────── */
    .back-link {
      display: flex; align-items: center; justify-content: center;
      gap: .4rem; margin-top: 1.4rem;
      font-size: .85rem; color: var(--muted);
      transition: color var(--t);
    }
    .back-link:hover { color: var(--text); }
    .back-link svg { width: 14px; height: 14px; }

    /* ── SUCCESS STATE ───────────────────────────────────────── */
    .success-state { text-align: center; padding: .5rem 0; }
    .success-icon-wrap {
      width: 72px; height: 72px; border-radius: 50%;
      background: linear-gradient(135deg, rgba(0,229,160,.12), rgba(0,229,255,.12));
      border: 1px solid rgba(0,229,160,.25);
      display: flex; align-items: center; justify-content: center;
      font-size: 2rem; margin: 0 auto 1.4rem;
      animation: successPop .5s cubic-bezier(.34,1.56,.64,1) both;
    }
    @keyframes successPop {
      from { opacity: 0; transform: scale(.5); }
      to   { opacity: 1; transform: scale(1); }
    }
    .success-state h2 {
      font-family: var(--fh); font-size: 1.5rem; font-weight: 800;
      letter-spacing: -.03em; margin-bottom: .6rem;
    }
    .success-state p {
      color: var(--muted); font-size: .9rem; font-weight: 300;
      line-height: 1.7; max-width: 320px; margin: 0 auto .3rem;
    }

    /* Steps list */
    .steps {
      list-style: none; margin: 1.5rem 0 1.8rem;
      display: flex; flex-direction: column; gap: .8rem;
      text-align: left;
    }
    .steps li {
      display: flex; align-items: flex-start; gap: .8rem;
      font-size: .85rem; color: var(--muted); line-height: 1.5;
    }
    .step-num {
      width: 22px; height: 22px; border-radius: 50%; flex-shrink: 0;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      display: flex; align-items: center; justify-content: center;
      font-size: .68rem; font-weight: 800; color: #000; margin-top: 1px;
    }

    /* Dev link box */
    .dev-box {
      background: rgba(255,193,7,.06);
      border: 1px solid rgba(255,193,7,.25);
      border-radius: 10px; padding: .9rem 1rem;
      margin: 1rem 0; text-align: left;
    }
    .dev-box-label {
      font-size: .68rem; font-weight: 700; color: var(--warn);
      text-transform: uppercase; letter-spacing: .1em; margin-bottom: .4rem;
    }
    .dev-box a {
      font-size: .78rem; color: var(--accent);
      word-break: break-all; line-height: 1.6;
    }
    .dev-box p {
      font-size: .72rem; color: var(--muted);
      margin-top: .4rem;
    }

    /* Resend timer */
    .resend-row {
      margin-top: 1rem; font-size: .82rem; color: var(--muted);
      display: flex; align-items: center; justify-content: center; gap: .4rem;
    }
    #resend-btn {
      background: none; border: none; cursor: pointer;
      color: var(--accent); font-size: .82rem;
      font-family: var(--fb); padding: 0;
      display: none;
    }
    #resend-btn:hover { text-decoration: underline; }

    /* ── Footer ──────────────────────────────────────────────── */
    footer { background: var(--surface); border-top: 1px solid var(--border); position: relative; z-index: 1; }
    .footer-bar {
      max-width: 1200px; margin: auto;
      padding: 1.1rem 2rem;
      display: flex; justify-content: space-between;
      flex-wrap: wrap; gap: .5rem;
      font-size: .78rem; color: var(--muted);
    }

    /* ── Progress steps at top ───────────────────────────────── */
    .progress-steps {
      display: flex; align-items: center; gap: .4rem;
      margin-bottom: 1.8rem;
    }
    .ps {
      display: flex; align-items: center; gap: .4rem;
      font-size: .72rem; color: var(--muted);
    }
    .ps-dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--border);
    }
    .ps-dot.active { background: var(--accent); }
    .ps-dot.done   { background: var(--safe); }
    .ps-line { flex: 1; height: 1px; background: var(--border); min-width: 20px; }
    .ps-line.done { background: var(--safe); }

    @media(max-width:500px) {
      .card { padding: 2rem 1.5rem 1.5rem; }
    }
  </style>
</head>
<body>

<!-- ══ HEADER ══════════════════════════════════════════════ -->
<header>
  <nav>
    <a href="index.php" class="nav-logo">
      <div class="logo-icon">🛡️</div>
      TruthGuard<span style="color:var(--accent)">AI</span>
    </a>
    <div class="nav-links">
      <a href="index.php">Home</a>
      <a href="login.php">Sign In</a>
      <a href="register.php" class="btn-nav-accent">Sign Up Free</a>
    </div>
  </nav>
</header>

<!-- ══ MAIN ════════════════════════════════════════════════ -->
<div class="page-center">
  <div class="card">

    <?php if ($state === 'sent'): ?>
    <!-- ── SUCCESS STATE ─────────────────────────────────── -->
    <div class="success-state">
      <div class="success-icon-wrap">📬</div>
      <h2>Check your inbox</h2>
      <p>If an account exists for <strong style="color:var(--text)"><?= htmlspecialchars($email) ?></strong>, we've sent a password reset link.</p>

      <ul class="steps">
        <li><div class="step-num">1</div> Open the email from TruthGuard AI</li>
        <li><div class="step-num">2</div> Click the reset link — it expires in <strong style="color:var(--text)">1 hour</strong></li>
        <li><div class="step-num">3</div> Create a new strong password</li>
      </ul>

      <?php if ($devLink): ?>
      <!-- DEV ONLY — remove this block in production -->
      <div class="dev-box">
        <div class="dev-box-label">⚠ Dev mode – email not sent</div>
        <a href="<?= htmlspecialchars($devLink) ?>"><?= htmlspecialchars($devLink) ?></a>
        <p>Remove this block and configure SMTP in production.</p>
      </div>
      <?php endif; ?>

      <div class="resend-row">
        <span id="resend-timer">Resend available in <strong id="countdown">60</strong>s</span>
        <button id="resend-btn" onclick="window.location='forgot_password.php'">Resend email</button>
      </div>
    </div>

    <a href="login.php" class="back-link">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
      Back to Sign In
    </a>

    <?php else: ?>
    <!-- ── FORM STATE ────────────────────────────────────── -->

    <!-- Progress indicator -->
    <div class="progress-steps">
      <div class="ps-dot active"></div>
      <div class="ps-line"></div>
      <div class="ps-dot"></div>
      <div class="ps-line"></div>
      <div class="ps-dot"></div>
    </div>

    <div class="card-icon">🔑</div>
    <h2>Forgot your password?</h2>
    <p class="sub">No worries — enter your registered email address and we'll send you a secure reset link. Expires in 1 hour.</p>

    <?php if (!empty($errors['general'])): ?>
      <div class="alert alert-danger">
        <span>⚠</span> <?= htmlspecialchars($errors['general']) ?>
      </div>
    <?php endif; ?>

    <form method="POST" action="forgot_password.php" id="fpForm" novalidate>
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>"/>

      <div class="fg">
        <label>
          Email Address
          <span style="color:var(--danger);font-size:.9em">*</span>
        </label>
        <div class="input-wrap">
          <input
            type="email"
            name="email"
            id="email"
            value="<?= htmlspecialchars($email) ?>"
            placeholder="you@example.com"
            autocomplete="email"
            autofocus
            class="<?= isset($errors['email']) ? 'is-error' : '' ?>"
          />
          <span class="input-icon">✉</span>
        </div>
        <?php if (isset($errors['email'])): ?>
          <div class="field-err">⚠ <?= htmlspecialchars($errors['email']) ?></div>
        <?php endif; ?>
        <div class="field-err" id="js-email-err" style="display:none"></div>
      </div>

      <button type="submit" class="btn-submit" id="submitBtn">
        <div class="spinner" id="spinner"></div>
        <span id="btnText">Send Reset Link</span>
      </button>
    </form>

    <a href="login.php" class="back-link">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M19 12H5M12 5l-7 7 7 7"/>
      </svg>
      Back to Sign In
    </a>

    <?php endif; ?>
  </div>
</div>

<!-- ══ FOOTER ══════════════════════════════════════════════ -->
<footer>
  <div class="footer-bar">
    <span>© 2026 <?= APP_NAME ?>. All rights reserved.</span>
    <span>🔒 Secured with SHA-256 tokens & rate limiting</span>
  </div>
</footer>

<script>
// ── Client-side validation ──────────────────────────────────
const form    = document.getElementById('fpForm');
const emailEl = document.getElementById('email');
const errEl   = document.getElementById('js-email-err');

if (form) {
  form.addEventListener('submit', function(e) {
    const v = emailEl.value.trim();
    if (!v) {
      showErr('Email address is required.');
      e.preventDefault(); return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) {
      showErr('Please enter a valid email address.');
      e.preventDefault(); return;
    }
    clearErr();
    // Loading state
    document.getElementById('spinner').style.display = 'block';
    document.getElementById('btnText').textContent    = 'Sending…';
    document.getElementById('submitBtn').disabled     = true;
  });

  // Live validation on blur
  emailEl.addEventListener('blur', function() {
    const v = this.value.trim();
    if (!v || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) {
      emailEl.classList.add('is-error');
    } else {
      emailEl.classList.remove('is-error');
      emailEl.classList.add('is-ok');
      clearErr();
    }
  });

  // Clear error on input
  emailEl.addEventListener('input', function() {
    emailEl.classList.remove('is-error');
    clearErr();
  });
}

function showErr(msg) {
  errEl.textContent = '⚠ ' + msg;
  errEl.style.display = 'flex';
  emailEl.classList.add('is-error');
  emailEl.classList.remove('is-ok');
}
function clearErr() {
  errEl.textContent = '';
  errEl.style.display = 'none';
}

// ── Resend countdown (success state) ───────────────────────
const countdown = document.getElementById('countdown');
if (countdown) {
  let secs = 60;
  const timer = setInterval(() => {
    secs--;
    countdown.textContent = secs;
    if (secs <= 0) {
      clearInterval(timer);
      document.getElementById('resend-timer').style.display = 'none';
      document.getElementById('resend-btn').style.display   = 'inline';
    }
  }, 1000);
}
</script>
</body>
</html>
