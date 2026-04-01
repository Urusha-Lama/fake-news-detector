<?php
/**
 * TruthGuard AI – Registration
 * Server-side validation: required fields, email format, duplicate check,
 * password strength, CSRF protection, bcrypt hashing.
 */

require_once 'config.php';
secureSession();

// Already logged in → go to dashboard
if (!empty($_SESSION['user_id'])) {
    redirect('http://localhost/fake-news-detector/php/index.html');
}

$errors   = [];
$old      = [];   // re-fill form on error
$success  = false;

// ── Handle POST ─────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 1. CSRF check
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $errors['general'] = 'Security token mismatch. Please refresh and try again.';
    } else {

        // 2. Collect & sanitize inputs
        $first_name = trim(strip_tags($_POST['first_name'] ?? ''));
        $last_name  = trim(strip_tags($_POST['last_name']  ?? ''));
        $username   = trim(strip_tags($_POST['username']   ?? ''));
        $email      = trim(strtolower($_POST['email']      ?? ''));
        $password   = $_POST['password']         ?? '';
        $confirm    = $_POST['confirm_password'] ?? '';
        $terms      = isset($_POST['terms']);

        $old = compact('first_name','last_name','username','email');

        // 3. Required field validation
        if ($first_name === '') $errors['first_name'] = 'First name is required.';
        elseif (strlen($first_name) < 2) $errors['first_name'] = 'First name must be at least 2 characters.';
        elseif (strlen($first_name) > 50) $errors['first_name'] = 'First name must be under 50 characters.';
        elseif (!preg_match('/^[A-Za-z\s\'-]+$/', $first_name)) $errors['first_name'] = 'First name contains invalid characters.';

        if ($last_name === '') $errors['last_name'] = 'Last name is required.';
        elseif (strlen($last_name) < 2) $errors['last_name'] = 'Last name must be at least 2 characters.';
        elseif (strlen($last_name) > 50) $errors['last_name'] = 'Last name must be under 50 characters.';
        elseif (!preg_match('/^[A-Za-z\s\'-]+$/', $last_name)) $errors['last_name'] = 'Last name contains invalid characters.';

        if ($username === '') $errors['username'] = 'Username is required.';
        elseif (strlen($username) < 3) $errors['username'] = 'Username must be at least 3 characters.';
        elseif (strlen($username) > 30) $errors['username'] = 'Username must be under 30 characters.';
        elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) $errors['username'] = 'Username may only contain letters, numbers, and underscores.';

        if ($email === '') {
            $errors['email'] = 'Email address is required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'Please enter a valid email address.';
        } elseif (strlen($email) > 100) {
            $errors['email'] = 'Email address is too long.';
        }

        // Password strength
        if ($password === '') {
            $errors['password'] = 'Password is required.';
        } elseif (strlen($password) < 8) {
            $errors['password'] = 'Password must be at least 8 characters.';
        } elseif (!preg_match('/[A-Z]/', $password)) {
            $errors['password'] = 'Password must contain at least one uppercase letter.';
        } elseif (!preg_match('/[a-z]/', $password)) {
            $errors['password'] = 'Password must contain at least one lowercase letter.';
        } elseif (!preg_match('/[0-9]/', $password)) {
            $errors['password'] = 'Password must contain at least one number.';
        } elseif (!preg_match('/[\W_]/', $password)) {
            $errors['password'] = 'Password must contain at least one special character (!@#$...).';
        }

        if ($confirm === '') {
            $errors['confirm_password'] = 'Please confirm your password.';
        } elseif (!isset($errors['password']) && $confirm !== $password) {
            $errors['confirm_password'] = 'Passwords do not match.';
        }

        if (!$terms) {
            $errors['terms'] = 'You must accept the Terms of Service to register.';
        }

        // 4. Database uniqueness checks (only if no format errors)
        if (empty($errors)) {
            $db = getDB();

            $stmt = $db->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $errors['email'] = 'This email address is already registered. <a href="login.php">Sign in instead?</a>';
            }

            $stmt = $db->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $errors['username'] = 'This username is already taken. Please choose another.';
            }
        }

        // 5. Insert user
        if (empty($errors)) {
            $db = getDB();
            $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

            $stmt = $db->prepare(
                "INSERT INTO users (first_name, last_name, username, email, password, created_at)
                 VALUES (?, ?, ?, ?, ?, NOW())"
            );
            $stmt->execute([$first_name, $last_name, $username, $email, $hash]);

            $userId = $db->lastInsertId();

            // Auto-login after registration
            session_regenerate_id(true);
            $_SESSION['user_id']    = $userId;
            $_SESSION['username']   = $username;
            $_SESSION['first_name'] = $first_name;
            $_SESSION['role']       = 'user';

            // Regenerate CSRF
            unset($_SESSION['csrf_token']);

            redirect('/fake-news-detector/php/index.php?welcome=1');
        }
    }
}

$csrf = csrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Create Account – <?= APP_NAME ?></title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"/>
  <style>
    :root{--bg:#05080f;--surface:#0c1120;--surface2:#121929;--border:rgba(255,255,255,0.07);--accent:#00e5ff;--accent2:#7b61ff;--danger:#ff4d6d;--safe:#00e5a0;--text:#e8ecf4;--muted:#7a8499;--font-head:'Syne',sans-serif;--font-body:'DM Sans',sans-serif;--radius:14px;--t:0.22s cubic-bezier(.4,0,.2,1);}
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
    body{background:var(--bg);color:var(--text);font-family:var(--font-body);min-height:100vh;display:flex;flex-direction:column;}
    a{text-decoration:none;color:var(--accent);}
    body::before{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");pointer-events:none;z-index:0;}
    /* NAV */
    header{position:sticky;top:0;z-index:100;background:rgba(5,8,15,.85);backdrop-filter:blur(18px);border-bottom:1px solid var(--border);}
    nav{max-width:1200px;margin:auto;padding:0 2rem;display:flex;align-items:center;height:66px;gap:1rem;}
    .nav-logo{font-family:var(--font-head);font-weight:800;font-size:1.25rem;display:flex;align-items:center;gap:.5rem;letter-spacing:-.02em;color:var(--text);}
    .logo-icon{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:1rem;}
    .nav-links{margin-left:auto;display:flex;align-items:center;gap:.25rem;}
    .nav-links a{padding:.4rem .9rem;border-radius:8px;font-size:.88rem;font-weight:500;color:var(--muted);transition:all var(--t);}
    .nav-links a:hover{color:var(--text);background:var(--border);}
    .btn-outline{border:1px solid var(--border) !important;color:var(--text) !important;}
    .btn-outline:hover{border-color:var(--muted) !important;}
    /* LAYOUT */
    .auth-wrap{flex:1;display:grid;grid-template-columns:1fr 1fr;min-height:calc(100vh - 66px);}
    .auth-panel{background:linear-gradient(160deg,rgba(123,97,255,.09),rgba(0,229,255,.05));border-right:1px solid var(--border);padding:4rem 3rem;display:flex;flex-direction:column;justify-content:center;position:relative;overflow:hidden;}
    .auth-panel::before{content:'';position:absolute;top:-150px;left:-150px;width:500px;height:500px;border-radius:50%;background:radial-gradient(circle,rgba(0,229,255,.07),transparent 70%);pointer-events:none;}
    .auth-panel h2{font-family:var(--font-head);font-size:2rem;font-weight:800;letter-spacing:-.03em;line-height:1.1;margin-bottom:1rem;}
    .auth-panel h2 span{background:linear-gradient(90deg,var(--accent2),var(--accent));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
    .auth-panel p{color:var(--muted);font-weight:300;line-height:1.7;max-width:340px;font-size:.92rem;}
    .perks{list-style:none;margin-top:2rem;display:flex;flex-direction:column;gap:.75rem;}
    .perks li{display:flex;align-items:center;gap:.8rem;font-size:.88rem;}
    .pk{width:30px;height:30px;border-radius:8px;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.2);display:flex;align-items:center;justify-content:center;font-size:.9rem;flex-shrink:0;}
    /* FORM SIDE */
    .auth-form-side{display:flex;align-items:center;justify-content:center;padding:2.5rem 2rem;}
    .auth-card{width:100%;max-width:460px;animation:fadeUp .5s ease both;}
    @keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
    .auth-card h3{font-family:var(--font-head);font-size:1.6rem;font-weight:800;letter-spacing:-.02em;margin-bottom:.3rem;}
    .auth-card .sub{color:var(--muted);font-size:.88rem;margin-bottom:1.8rem;}
    /* FORM FIELDS */
    .form-row{display:grid;grid-template-columns:1fr 1fr;gap:1rem;}
    .fg{margin-bottom:1.1rem;position:relative;}
    .fg label{display:flex;align-items:center;justify-content:space-between;font-size:.78rem;font-weight:500;color:var(--muted);margin-bottom:.4rem;letter-spacing:.03em;}
    .fg label span.req{color:var(--danger);margin-left:2px;}
    .fg input{width:100%;background:var(--surface);border:1.5px solid var(--border);border-radius:10px;padding:.8rem 1rem;color:var(--text);font-family:var(--font-body);font-size:.93rem;transition:border-color var(--t),box-shadow var(--t);}
    .fg input:focus{outline:none;border-color:rgba(0,229,255,.5);box-shadow:0 0 0 3px rgba(0,229,255,.07);}
    .fg input.is-error{border-color:var(--danger);}
    .fg input.is-ok{border-color:var(--safe);}
    .fg input::placeholder{color:var(--muted);}
    .field-err{font-size:.75rem;color:var(--danger);margin-top:.3rem;display:flex;align-items:flex-start;gap:.3rem;line-height:1.4;}
    .field-err a{color:var(--danger);text-decoration:underline;}
    .field-ok{font-size:.75rem;color:var(--safe);margin-top:.3rem;}
    /* Password strength */
    .pwd-wrap{position:relative;}
    .pwd-toggle{position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);cursor:pointer;font-size:.85rem;padding:4px;}
    .pwd-toggle:hover{color:var(--text);}
    .strength-bar{display:flex;gap:3px;margin-top:.4rem;}
    .sb{flex:1;height:4px;border-radius:100px;background:var(--surface2);transition:background .3s ease;}
    .strength-hint{font-size:.72rem;color:var(--muted);margin-top:.25rem;}
    /* Checkbox */
    .check-row{display:flex;align-items:flex-start;gap:.6rem;margin-bottom:1.3rem;}
    .check-row input[type=checkbox]{width:16px;height:16px;accent-color:var(--accent);margin-top:2px;flex-shrink:0;}
    .check-row label{font-size:.82rem;color:var(--muted);line-height:1.5;cursor:pointer;}
    /* Alert */
    .alert{background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.25);border-radius:10px;padding:.9rem 1rem;margin-bottom:1.2rem;font-size:.85rem;color:var(--danger);}
    /* Submit */
    .btn-submit{width:100%;padding:.85rem;border-radius:10px;border:none;cursor:pointer;background:linear-gradient(135deg,var(--accent),var(--accent2));font-family:var(--font-head);font-weight:700;font-size:.95rem;color:#fff;transition:all var(--t);display:flex;align-items:center;justify-content:center;gap:.5rem;}
    .btn-submit:hover{transform:translateY(-2px);box-shadow:0 10px 28px rgba(0,229,255,.25);}
    .btn-submit:disabled{opacity:.6;cursor:not-allowed;transform:none;}
    .divider{display:flex;align-items:center;gap:1rem;margin:1.3rem 0;color:var(--muted);font-size:.78rem;}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border);}
    .btn-google{width:100%;padding:.78rem;border-radius:10px;cursor:pointer;background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:var(--font-body);font-size:.88rem;font-weight:500;display:flex;align-items:center;justify-content:center;gap:.6rem;transition:all var(--t);}
    .btn-google:hover{border-color:var(--muted);background:var(--surface2);}
    .switch-link{text-align:center;margin-top:1.3rem;font-size:.85rem;color:var(--muted);}
    /* Footer */
    footer{background:var(--surface);border-top:1px solid var(--border);}
    .footer-bar{max-width:1200px;margin:auto;padding:1.1rem 2rem;display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem;font-size:.78rem;color:var(--muted);}
    @media(max-width:800px){.auth-wrap{grid-template-columns:1fr;}.auth-panel{display:none;}.form-row{grid-template-columns:1fr;}}
  </style>
</head>
<body>
<header>
  <nav>
    <a href="/fake-news-detector/php/index.php" class="nav-logo">
      <div class="logo-icon">🛡️</div>
      TruthGuard<span style="color:var(--accent)">AI</span>
    </a>
    <div class="nav-links">
      <a href="http://localhost/fake-news-detector/php/index.html">Home</a>
      <a href="http://localhost/fake-news-detector/php/login.php" class="btn-outline">Sign In</a>
    </div>
  </nav>
</header>

<div class="auth-wrap">
  <!-- Left -->
  <div class="auth-panel">
    <h2>Start fighting<br><span>misinformation</span><br>today</h2>
    <p>Create your free account and get instant access to AI-powered fake news detection. No credit card required.</p>
    <ul class="perks">
      <li><div class="pk">🔍</div> 10 free analyses every day</li>
      <li><div class="pk">📊</div> Full credibility reports</li>
      <li><div class="pk">🌐</div> 150+ languages supported</li>
      <li><div class="pk">⚡</div> Results in under 2 seconds</li>
      <li><div class="pk">🔒</div> Your data is always private</li>
    </ul>
  </div>

  <!-- Right – Form -->
  <div class="auth-form-side">
    <div class="auth-card">
      <h3>Create your account</h3>
      <p class="sub">Already have an account? <a href="login.php">Sign in →</a></p>

      <?php if (!empty($errors['general'])): ?>
        <div class="alert"><?= $errors['general'] ?></div>
      <?php endif; ?>

      <button class="btn-google" type="button">
        <svg width="17" height="17" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
        Sign up with Google
      </button>
      <div class="divider">or register with email</div>

      <form method="POST" id="regForm" novalidate>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>"/>

        <div class="form-row">
          <div class="fg">
            <label>First Name <span class="req">*</span></label>
            <input type="text" name="first_name" id="first_name"
              value="<?= htmlspecialchars($old['first_name'] ?? '') ?>"
              placeholder="John" maxlength="50" autocomplete="given-name"
              class="<?= isset($errors['first_name']) ? 'is-error' : '' ?>"/>
            <?php if (isset($errors['first_name'])): ?>
              <div class="field-err">⚠ <?= $errors['first_name'] ?></div>
            <?php endif; ?>
          </div>
          <div class="fg">
            <label>Last Name <span class="req">*</span></label>
            <input type="text" name="last_name" id="last_name"
              value="<?= htmlspecialchars($old['last_name'] ?? '') ?>"
              placeholder="Doe" maxlength="50" autocomplete="family-name"
              class="<?= isset($errors['last_name']) ? 'is-error' : '' ?>"/>
            <?php if (isset($errors['last_name'])): ?>
              <div class="field-err">⚠ <?= $errors['last_name'] ?></div>
            <?php endif; ?>
          </div>
        </div>

        <div class="fg">
          <label>Username <span class="req">*</span></label>
          <input type="text" name="username" id="username"
            value="<?= htmlspecialchars($old['username'] ?? '') ?>"
            placeholder="e.g. johndoe99" maxlength="30" autocomplete="username"
            class="<?= isset($errors['username']) ? 'is-error' : '' ?>"/>
          <?php if (isset($errors['username'])): ?>
            <div class="field-err">⚠ <?= $errors['username'] ?></div>
          <?php endif; ?>
        </div>

        <div class="fg">
          <label>Email Address <span class="req">*</span></label>
          <input type="email" name="email" id="email"
            value="<?= htmlspecialchars($old['email'] ?? '') ?>"
            placeholder="you@example.com" maxlength="100" autocomplete="email"
            class="<?= isset($errors['email']) ? 'is-error' : '' ?>"/>
          <?php if (isset($errors['email'])): ?>
            <div class="field-err">⚠ <?= $errors['email'] ?></div>
          <?php endif; ?>
        </div>

        <div class="fg">
          <label>Password <span class="req">*</span></label>
          <div class="pwd-wrap">
            <input type="password" name="password" id="password"
              placeholder="Min. 8 chars, upper, number, symbol" maxlength="128"
              autocomplete="new-password"
              class="<?= isset($errors['password']) ? 'is-error' : '' ?>"
              oninput="updateStrength(this.value)"/>
            <button type="button" class="pwd-toggle" onclick="togglePwd('password',this)">👁</button>
          </div>
          <div class="strength-bar">
            <div class="sb" id="sb1"></div><div class="sb" id="sb2"></div>
            <div class="sb" id="sb3"></div><div class="sb" id="sb4"></div>
          </div>
          <div class="strength-hint" id="strengthHint">Enter a password</div>
          <?php if (isset($errors['password'])): ?>
            <div class="field-err">⚠ <?= $errors['password'] ?></div>
          <?php endif; ?>
        </div>

        <div class="fg">
          <label>Confirm Password <span class="req">*</span></label>
          <div class="pwd-wrap">
            <input type="password" name="confirm_password" id="confirm_password"
              placeholder="Repeat your password" maxlength="128"
              autocomplete="new-password"
              class="<?= isset($errors['confirm_password']) ? 'is-error' : '' ?>"
              oninput="checkMatch()"/>
            <button type="button" class="pwd-toggle" onclick="togglePwd('confirm_password',this)">👁</button>
          </div>
          <div id="matchMsg"></div>
          <?php if (isset($errors['confirm_password'])): ?>
            <div class="field-err">⚠ <?= $errors['confirm_password'] ?></div>
          <?php endif; ?>
        </div>

        <div class="check-row">
          <input type="checkbox" name="terms" id="terms" <?= isset($old['terms']) ? 'checked' : '' ?>/>
          <label for="terms">I agree to the <a href="#">Terms of Service</a> and <a href="#">Privacy Policy</a>. We never sell your data.</label>
        </div>
        <?php if (isset($errors['terms'])): ?>
          <div class="field-err" style="margin-top:-.8rem;margin-bottom:.8rem">⚠ <?= $errors['terms'] ?></div>
        <?php endif; ?>

        <button type="submit" class="btn-submit" id="submitBtn">
          <span id="submitText">🚀 Create Free Account</span>
          <span id="submitSpinner" style="display:none">⏳ Creating account...</span>
        </button>
      </form>

      <div class="switch-link">Already have an account? <a href="login.php">Sign in →</a></div>
    </div>
  </div>
</div>

<footer>
  <div class="footer-bar">
    <span>© 2026 <?= APP_NAME ?>. All rights reserved.</span>
    <span>🔒 Your data is encrypted and never sold.</span>
  </div>
</footer>

<script>
// ── Client-side validation ────────────────────────────────
const form = document.getElementById('regForm');

form.addEventListener('submit', function(e) {
  let valid = true;

  // First name
  valid &= validateField('first_name', v => {
    if (!v) return 'First name is required.';
    if (v.length < 2) return 'Must be at least 2 characters.';
    if (!/^[A-Za-z\s'\-]+$/.test(v)) return 'Letters only, please.';
    return null;
  });

  // Last name
  valid &= validateField('last_name', v => {
    if (!v) return 'Last name is required.';
    if (v.length < 2) return 'Must be at least 2 characters.';
    return null;
  });

  // Username
  valid &= validateField('username', v => {
    if (!v) return 'Username is required.';
    if (v.length < 3) return 'At least 3 characters.';
    if (!/^[a-zA-Z0-9_]+$/.test(v)) return 'Letters, numbers, underscore only.';
    return null;
  });

  // Email
  valid &= validateField('email', v => {
    if (!v) return 'Email is required.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'Enter a valid email address.';
    return null;
  });

  // Password
  const pwd = document.getElementById('password').value;
  valid &= validateField('password', v => {
    if (!v) return 'Password is required.';
    if (v.length < 8) return 'At least 8 characters.';
    if (!/[A-Z]/.test(v)) return 'At least one uppercase letter.';
    if (!/[0-9]/.test(v)) return 'At least one number.';
    if (!/[\W_]/.test(v)) return 'At least one special character.';
    return null;
  });

  // Confirm
  valid &= validateField('confirm_password', v => {
    if (!v) return 'Please confirm your password.';
    if (v !== pwd) return 'Passwords do not match.';
    return null;
  });

  // Terms
  if (!document.getElementById('terms').checked) {
    showErr('terms', 'You must accept the Terms of Service.');
    valid = false;
  }

  if (!valid) { e.preventDefault(); return; }

  // Show loading state
  document.getElementById('submitText').style.display = 'none';
  document.getElementById('submitSpinner').style.display = 'inline';
  document.getElementById('submitBtn').disabled = true;
});

function validateField(id, ruleFn) {
  const input = document.getElementById(id);
  if (!input) return true;
  const val = input.value.trim();
  const err = ruleFn(val);
  if (err) {
    input.classList.add('is-error'); input.classList.remove('is-ok');
    showErr(id, err);
    return false;
  }
  input.classList.remove('is-error'); input.classList.add('is-ok');
  clearErr(id);
  return true;
}

function showErr(id, msg) {
  clearErr(id);
  const wrap = document.getElementById(id)?.closest('.fg') || document.getElementById('terms')?.closest('.check-row');
  if (!wrap) return;
  const d = document.createElement('div');
  d.className = 'field-err'; d.id = 'err_' + id;
  d.textContent = '⚠ ' + msg;
  wrap.appendChild(d);
}
function clearErr(id) {
  document.getElementById('err_' + id)?.remove();
}

// Real-time blur validation
['first_name','last_name','username','email','password','confirm_password'].forEach(id => {
  const el = document.getElementById(id);
  if (el) el.addEventListener('blur', () => el.dispatchEvent(new Event('input')));
});

// Email live check
document.getElementById('email').addEventListener('input', function() {
  const v = this.value.trim();
  if (v && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) {
    this.classList.add('is-error'); this.classList.remove('is-ok');
  } else if (v) {
    this.classList.remove('is-error'); this.classList.add('is-ok');
    clearErr('email');
  }
});

// Password strength meter
function updateStrength(v) {
  const bars = [document.getElementById('sb1'),document.getElementById('sb2'),document.getElementById('sb3'),document.getElementById('sb4')];
  const hint = document.getElementById('strengthHint');
  let score = 0;
  if (v.length >= 8) score++;
  if (/[A-Z]/.test(v) && /[a-z]/.test(v)) score++;
  if (/[0-9]/.test(v)) score++;
  if (/[\W_]/.test(v)) score++;
  const levels = [
    {color:'transparent', label:'Enter a password'},
    {color:'#ff4d6d',     label:'Weak – add numbers & symbols'},
    {color:'#ffc107',     label:'Fair – add a special character'},
    {color:'#00c6ff',     label:'Good – almost there!'},
    {color:'#00e5a0',     label:'Strong ✓ Great password!'}
  ];
  bars.forEach((b, i) => b.style.background = i < score ? levels[score].color : 'var(--surface2)');
  hint.textContent = levels[score].label;
  hint.style.color = levels[score].color || 'var(--muted)';
}

// Confirm password match indicator
function checkMatch() {
  const p1 = document.getElementById('password').value;
  const p2 = document.getElementById('confirm_password').value;
  const msg = document.getElementById('matchMsg');
  clearErr('confirm_password');
  if (!p2) { msg.innerHTML = ''; return; }
  if (p1 === p2) {
    msg.innerHTML = '<div class="field-ok">✓ Passwords match</div>';
    document.getElementById('confirm_password').classList.remove('is-error');
    document.getElementById('confirm_password').classList.add('is-ok');
  } else {
    msg.innerHTML = '<div class="field-err">⚠ Passwords do not match</div>';
    document.getElementById('confirm_password').classList.add('is-error');
    document.getElementById('confirm_password').classList.remove('is-ok');
  }
}

// Toggle password visibility
function togglePwd(id, btn) {
  const inp = document.getElementById(id);
  if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '🙈'; }
  else { inp.type = 'password'; btn.textContent = '👁'; }
}

// Username availability check (debounced AJAX)
let usernameTimer;
document.getElementById('username').addEventListener('input', function() {
  clearTimeout(usernameTimer);
  const v = this.value.trim();
  if (v.length < 3) return;
  usernameTimer = setTimeout(() => {
    fetch('check_username.php?username=' + encodeURIComponent(v))
      .then(r => r.json())
      .then(data => {
        const el = document.getElementById('username');
        clearErr('username');
        if (data.taken) {
          el.classList.add('is-error'); el.classList.remove('is-ok');
          showErr('username', 'Username is already taken.');
        } else {
          el.classList.remove('is-error'); el.classList.add('is-ok');
        }
      }).catch(() => {});
  }, 500);
});
</script>
</body>
</html>
