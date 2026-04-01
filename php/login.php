<?php
/**
 * TruthGuard AI – Login Page (login.php)
 * - CSRF protection
 * - Brute-force lockout via login_attempts table
 * - Remember Me cookie (30 days)
 * - Session stores full profile (id, name, email, role)
 * - Redirects to dashboard.php after login
 */

require_once 'config.php';
secureSession();

// Already logged in → go to dashboard
if (!empty($_SESSION['user_id'])) {
    redirect('http://localhost/fake-news-detector/php/dashboard.php');
}

$errors = [];
$old    = [];

// ── Handle POST ─────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 1. CSRF check
    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $errors['general'] = 'Security token mismatch. Please refresh and try again.';
    } else {
        $email    = trim(strtolower($_POST['email']    ?? ''));
        $password = $_POST['password'] ?? '';
        $remember = isset($_POST['remember']);
        $ip       = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $old      = ['email' => $email];

        // 2. Basic validation
        if ($email === '') {
            $errors['email'] = 'Email address is required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'Please enter a valid email address.';
        }
        if ($password === '') {
            $errors['password'] = 'Password is required.';
        }

        if (empty($errors)) {
            $db = getDB();

            // 3. Brute-force check — reads login_attempts table
            $window = date('Y-m-d H:i:s', time() - LOCKOUT_TIME);
            $stmt   = $db->prepare(
                "SELECT COUNT(*) FROM login_attempts
                 WHERE (email = ? OR ip_address = ?) AND attempted_at > ?"
            );
            $stmt->execute([$email, $ip, $window]);
            $attempts = (int) $stmt->fetchColumn();

            if ($attempts >= MAX_LOGIN_ATTEMPTS) {
                $errors['general'] = 'Too many failed login attempts. Please wait 15 minutes before trying again.';
            } else {
                // 4. Fetch user by email (safe prepared statement)
                $stmt = $db->prepare(
                    "SELECT id, first_name, last_name, username, email,
                            password, role, is_active
                     FROM users WHERE email = ? LIMIT 1"
                );
                $stmt->execute([$email]);
                $user = $stmt->fetch();

                if ($user && (int)$user['is_active'] === 1
                    && password_verify($password, $user['password']))
                {
                    // ✅ SUCCESS — clear failed attempts
                    $db->prepare(
                        "DELETE FROM login_attempts WHERE email = ? OR ip_address = ?"
                    )->execute([$email, $ip]);

                    // Prevent session fixation
                    session_regenerate_id(true);

                    // Store full profile in session
                    $_SESSION['user_id']    = $user['id'];
                    $_SESSION['username']   = $user['username'];
                    $_SESSION['first_name'] = $user['first_name'];
                    $_SESSION['last_name']  = $user['last_name'];
                    $_SESSION['email']      = $user['email'];
                    $_SESSION['role']       = $user['role'];

                    // Update last login timestamp
                    $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?")
                       ->execute([$user['id']]);

                    // Remember Me cookie
                    if ($remember) {
                        $token = bin2hex(random_bytes(32));
                        $hash  = hash('sha256', $token);
                        $exp   = date('Y-m-d H:i:s', time() + 30 * 86400);
                        $db->prepare(
                            "INSERT INTO remember_tokens (user_id, token_hash, expires_at) VALUES (?,?,?)"
                        )->execute([$user['id'], $hash, $exp]);
                        setcookie('remember_token', $token, [
                            'expires'  => time() + 30 * 86400,
                            'path'     => '/',
                            'httponly' => true,
                            'secure'   => false,
                            'samesite' => 'Strict',
                        ]);
                    }

                    unset($_SESSION['csrf_token']);
                    redirect(APP_URL . '/dashboard.php');

                } else {
                    // ❌ FAILED — insert into login_attempts
                    $db->prepare(
                        "INSERT INTO login_attempts (email, ip_address, attempted_at) VALUES (?,?,NOW())"
                    )->execute([$email, $ip]);

                    $remaining = MAX_LOGIN_ATTEMPTS - $attempts - 1;
                    $errors['general'] = 'Invalid email or password.'
                        . ($remaining > 0
                            ? " ($remaining attempt" . ($remaining > 1 ? 's' : '') . " remaining before lockout)"
                            : '');
                }
            }
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
  <title>Sign In – <?= APP_NAME ?></title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"/>
  <style>
    :root{--bg:#05080f;--surface:#0c1120;--surface2:#121929;--border:rgba(255,255,255,0.07);--accent:#00e5ff;--accent2:#7b61ff;--danger:#ff4d6d;--safe:#00e5a0;--warn:#ffc107;--text:#e8ecf4;--muted:#7a8499;--font-head:'Syne',sans-serif;--font-body:'DM Sans',sans-serif;--t:0.22s cubic-bezier(.4,0,.2,1);}
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
    body{background:var(--bg);color:var(--text);font-family:var(--font-body);min-height:100vh;display:flex;flex-direction:column;}
    a{text-decoration:none;color:var(--accent);}
    body::before{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");pointer-events:none;z-index:0;}
    header{position:sticky;top:0;z-index:100;background:rgba(5,8,15,.85);backdrop-filter:blur(18px);border-bottom:1px solid var(--border);}
    nav{max-width:1200px;margin:auto;padding:0 2rem;display:flex;align-items:center;height:66px;gap:1rem;}
    .nav-logo{font-family:var(--font-head);font-weight:800;font-size:1.25rem;display:flex;align-items:center;gap:.5rem;letter-spacing:-.02em;color:var(--text);}
    .logo-icon{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:1rem;}
    .nav-links{margin-left:auto;display:flex;align-items:center;gap:.25rem;}
    .nav-links a{padding:.4rem .9rem;border-radius:8px;font-size:.88rem;font-weight:500;color:var(--muted);transition:all var(--t);}
    .nav-links a:hover{color:var(--text);background:rgba(255,255,255,.05);}
    .btn-accent{background:linear-gradient(135deg,var(--accent),var(--accent2)) !important;color:#000 !important;font-weight:600 !important;}
    .auth-wrap{flex:1;display:grid;grid-template-columns:1fr 1fr;min-height:calc(100vh - 66px);}
    .auth-panel{background:linear-gradient(160deg,rgba(0,229,255,.07),rgba(123,97,255,.08));border-right:1px solid var(--border);padding:4rem 3rem;display:flex;flex-direction:column;justify-content:center;overflow:hidden;position:relative;}
    .auth-panel::before{content:'';position:absolute;bottom:-150px;right:-150px;width:500px;height:500px;border-radius:50%;background:radial-gradient(circle,rgba(123,97,255,.1),transparent 70%);pointer-events:none;}
    .auth-panel h2{font-family:var(--font-head);font-size:2rem;font-weight:800;letter-spacing:-.03em;line-height:1.1;margin-bottom:1rem;}
    .auth-panel h2 span{background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
    .auth-panel p{color:var(--muted);font-weight:300;line-height:1.7;max-width:340px;font-size:.92rem;}
    .perks{list-style:none;margin-top:2rem;display:flex;flex-direction:column;gap:.75rem;}
    .perks li{display:flex;align-items:center;gap:.8rem;font-size:.88rem;}
    .pk{width:30px;height:30px;border-radius:8px;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.2);display:flex;align-items:center;justify-content:center;font-size:.9rem;flex-shrink:0;}
    .auth-form-side{display:flex;align-items:center;justify-content:center;padding:2.5rem 2rem;}
    .auth-card{width:100%;max-width:420px;animation:fadeUp .5s ease both;}
    @keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
    .auth-card h3{font-family:var(--font-head);font-size:1.6rem;font-weight:800;letter-spacing:-.02em;margin-bottom:.3rem;}
    .auth-card .sub{color:var(--muted);font-size:.88rem;margin-bottom:1.8rem;}
    .fg{margin-bottom:1.1rem;}
    .fg label{display:block;font-size:.78rem;font-weight:500;color:var(--muted);margin-bottom:.4rem;letter-spacing:.05em;text-transform:uppercase;}
    .fg input{width:100%;background:var(--surface);border:1.5px solid var(--border);border-radius:10px;padding:.82rem 1rem;color:var(--text);font-family:var(--font-body);font-size:.93rem;transition:border-color var(--t),box-shadow var(--t);}
    .fg input:focus{outline:none;border-color:rgba(0,229,255,.5);box-shadow:0 0 0 3px rgba(0,229,255,.07);}
    .fg input.is-error{border-color:var(--danger) !important;}
    .fg input.is-ok{border-color:var(--safe) !important;}
    .fg input::placeholder{color:var(--muted);}
    .field-err{font-size:.75rem;color:var(--danger);margin-top:.35rem;display:flex;align-items:flex-start;gap:.3rem;line-height:1.4;}
    .pwd-wrap{position:relative;}
    .pwd-toggle{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);cursor:pointer;font-size:.85rem;padding:4px;transition:color var(--t);}
    .pwd-toggle:hover{color:var(--text);}
    .form-extra{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.4rem;font-size:.82rem;}
    .form-extra label{display:flex;align-items:center;gap:.45rem;color:var(--muted);cursor:pointer;user-select:none;}
    .form-extra input[type=checkbox]{accent-color:var(--accent);width:15px;height:15px;}
    .alert{border-radius:10px;padding:.85rem 1rem;margin-bottom:1.2rem;font-size:.85rem;display:flex;align-items:flex-start;gap:.5rem;line-height:1.5;}
    .alert-danger{background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.28);color:var(--danger);}
    .alert-warn{background:rgba(255,193,7,.07);border:1px solid rgba(255,193,7,.3);color:var(--warn);}
    .alert-success{background:rgba(0,229,160,.07);border:1px solid rgba(0,229,160,.3);color:var(--safe);}
    .attempts-bar{display:flex;gap:4px;margin-top:.5rem;}
    .att-dot{width:10px;height:10px;border-radius:50%;}
    .divider{display:flex;align-items:center;gap:1rem;margin:1.2rem 0;color:var(--muted);font-size:.78rem;}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border);}
    .btn-google{width:100%;padding:.78rem;border-radius:10px;cursor:pointer;background:var(--surface);border:1px solid var(--border);color:var(--text);font-family:var(--font-body);font-size:.88rem;font-weight:500;display:flex;align-items:center;justify-content:center;gap:.6rem;transition:all var(--t);}
    .btn-google:hover{border-color:var(--muted);background:var(--surface2);}
    .btn-submit{width:100%;padding:.88rem;border-radius:10px;border:none;cursor:pointer;background:linear-gradient(135deg,var(--accent),var(--accent2));font-family:var(--font-head);font-weight:700;font-size:.95rem;color:#000;transition:all var(--t);display:flex;align-items:center;justify-content:center;gap:.5rem;}
    .btn-submit:hover{transform:translateY(-2px);box-shadow:0 10px 28px rgba(0,229,255,.25);}
    .btn-submit:disabled{opacity:.6;cursor:not-allowed;transform:none;}
    .switch-link{text-align:center;margin-top:1.3rem;font-size:.85rem;color:var(--muted);}
    footer{background:var(--surface);border-top:1px solid var(--border);}
    .footer-bar{max-width:1200px;margin:auto;padding:1.1rem 2rem;display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem;font-size:.78rem;color:var(--muted);}
    @media(max-width:800px){.auth-wrap{grid-template-columns:1fr;}.auth-panel{display:none;}}
  </style>
</head>
<body>
<header>
  <nav>
    <a href="index.php" class="nav-logo">
      <div class="logo-icon">🛡️</div>
      TruthGuard<span style="color:var(--accent)">AI</span>
    </a>
    <div class="nav-links">
      <a href="http://localhost/fake-news-detector/php/index.html">Home</a>
      <a href="http://localhost/fake-news-detector/php/index.html#features">Features</a>
      <a href="http://localhost/fake-news-detector/php/index.html#pricing">Pricing</a>
      <a href="http://localhost/fake-news-detector/php/register.php" class="btn-accent">Sign Up Free</a>
    </div>
  </nav>
</header>

<div class="auth-wrap">
  <div class="auth-panel">
    <h2>Welcome back to<br><span>TruthGuard AI</span></h2>
    <p>The world's most accurate AI-powered fake news detector — trusted by 2M+ users, journalists, and educators worldwide.</p>
    <ul class="perks">
      <li><div class="pk">🔍</div> Unlimited news analysis</li>
      <li><div class="pk">📊</div> Detailed credibility reports</li>
      <li><div class="pk">🌐</div> 150+ language support</li>
      <li><div class="pk">⚡</div> Results in under 2 seconds</li>
      <li><div class="pk">🔒</div> Your data is always private</li>
    </ul>
  </div>

  <div class="auth-form-side">
    <div class="auth-card">
      <h3>Sign in</h3>
      <p class="sub">Don't have an account? <a href="http://localhost/fake-news-detector/php/register.php">Create one free →</a></p>

      <?php if (isset($_GET['registered'])): ?>
        <div class="alert alert-success">✅ Account created! Please sign in below.</div>
      <?php endif; ?>
      <?php if (isset($_GET['logged_out'])): ?>
        <div class="alert alert-warn">👋 You have been signed out successfully.</div>
      <?php endif; ?>
      <?php if (!empty($errors['general'])): ?>
        <div class="alert alert-danger">
          <span style="flex-shrink:0">⚠</span>
          <div>
            <?= htmlspecialchars($errors['general']) ?>
            <?php
              // Show attempt dots
              try {
                $db2 = getDB();
                $w2  = date('Y-m-d H:i:s', time() - LOCKOUT_TIME);
                $ip2 = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
                $s2  = $db2->prepare("SELECT COUNT(*) FROM login_attempts WHERE (email=? OR ip_address=?) AND attempted_at>?");
                $s2->execute([$old['email'] ?? '', $ip2, $w2]);
                $att = (int)$s2->fetchColumn();
                if ($att > 0 && $att < MAX_LOGIN_ATTEMPTS):
            ?>
            <div class="attempts-bar">
              <?php for ($i=0;$i<MAX_LOGIN_ATTEMPTS;$i++): ?>
                <div class="att-dot" style="background:<?= $i<$att?'var(--danger)':'rgba(255,255,255,.15)' ?>"></div>
              <?php endfor; ?>
            </div>
            <?php endif; } catch(Exception $e) {} ?>
          </div>
        </div>
      <?php endif; ?>

      <button class="btn-google" type="button">
        <svg width="17" height="17" viewBox="0 0 48 48">
          <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
          <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
          <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
          <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.18 1.48-4.97 2.31-8.16 2.31-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
        </svg>
        Continue with Google
      </button>
      <div class="divider">or sign in with email</div>

      <form method="POST" action="login.php" id="loginForm" novalidate>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>"/>

        <div class="fg">
          <label>Email Address</label>
          <input type="email" name="email" id="email"
            value="<?= htmlspecialchars($old['email'] ?? '') ?>"
            placeholder="you@example.com" autocomplete="email"
            class="<?= isset($errors['email']) ? 'is-error' : '' ?>"/>
          <?php if (isset($errors['email'])): ?>
            <div class="field-err">⚠ <?= htmlspecialchars($errors['email']) ?></div>
          <?php endif; ?>
        </div>

        <div class="fg">
          <label>Password</label>
          <div class="pwd-wrap">
            <input type="password" name="password" id="password"
              placeholder="Your password" autocomplete="current-password"
              class="<?= isset($errors['password']) ? 'is-error' : '' ?>"/>
            <button type="button" class="pwd-toggle" onclick="togglePwd(this)">👁</button>
          </div>
          <?php if (isset($errors['password'])): ?>
            <div class="field-err">⚠ <?= htmlspecialchars($errors['password']) ?></div>
          <?php endif; ?>
        </div>

        <div class="form-extra">
          <label>
            <input type="checkbox" name="remember" value="1"/> Remember me for 30 days
          </label>
          <a href="forgot_password.php">Forgot password?</a>
        </div>

        <button type="submit" class="btn-submit" id="submitBtn">
          <span id="btnText">🔐 Sign In</span>
          <span id="btnSpinner" style="display:none">⏳ Signing in...</span>
        </button>
      </form>
      <div class="switch-link">Don't have an account? <a href="register.php">Create one free →</a></div>
    </div>
  </div>
</div>

<footer>
  <div class="footer-bar">
    <span>© 2026 <?= APP_NAME ?>. All rights reserved.</span>
    <span>🔒 Protected by bcrypt + CSRF + brute-force detection</span>
  </div>
</footer>

<script>
document.getElementById('loginForm').addEventListener('submit', function(e) {
  let ok = true;
  ok &= check('email', v => {
    if (!v) return 'Email address is required.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) return 'Enter a valid email address.';
    return null;
  });
  ok &= check('password', v => {
    if (!v) return 'Password is required.';
    return null;
  });
  if (!ok) { e.preventDefault(); return; }
  document.getElementById('btnText').style.display    = 'none';
  document.getElementById('btnSpinner').style.display = 'inline';
  document.getElementById('submitBtn').disabled       = true;
});

function check(id, ruleFn) {
  const el  = document.getElementById(id);
  const val = el.value.trim();
  const err = ruleFn(val);
  document.getElementById('js_' + id)?.remove();
  if (err) {
    el.classList.add('is-error'); el.classList.remove('is-ok');
    const d = document.createElement('div');
    d.id = 'js_' + id; d.className = 'field-err';
    d.textContent = '⚠ ' + err;
    el.closest('.fg').appendChild(d);
    return false;
  }
  el.classList.remove('is-error'); el.classList.add('is-ok');
  return true;
}

['email','password'].forEach(id => {
  document.getElementById(id).addEventListener('input', function() {
    this.classList.remove('is-error');
    document.getElementById('js_' + id)?.remove();
  });
  document.getElementById(id).addEventListener('blur', function() {
    if (id === 'email') check('email', v => {
      if (!v) return 'Email is required.';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v)) return 'Invalid email.';
      return null;
    });
  });
});

function togglePwd(btn) {
  const inp = document.getElementById('password');
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '👁' : '🙈';
}
</script>
</body>
</html>
