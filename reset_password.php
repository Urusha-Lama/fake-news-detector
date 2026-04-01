<?php
/**
 * TruthGuard AI – Reset Password (reset_password.php)
 * - Validates token from URL (SHA-256 hash lookup)
 * - Checks token not expired and not already used
 * - Enforces password strength
 * - Marks token as used after successful reset
 * - Clears all sessions for that user (forces re-login everywhere)
 */

require_once 'config.php';
secureSession();

$state  = 'form';   // 'form' | 'invalid' | 'success'
$errors = [];
$token  = $_GET['token'] ?? $_POST['token'] ?? '';

// ── Validate token ──────────────────────────────────────────
$validToken = null;
$tokenUser  = null;

if ($token) {
    $hash = hash('sha256', $token);
    $db   = getDB();
    $stmt = $db->prepare(
        "SELECT pr.*, u.email, u.first_name
         FROM password_resets pr
         JOIN users u ON u.id = pr.user_id
         WHERE pr.token_hash = ?
           AND pr.used = 0
           AND pr.expires_at > NOW()
         LIMIT 1"
    );
    $stmt->execute([$hash]);
    $validToken = $stmt->fetch();
    if ($validToken) {
        $tokenUser = $validToken;
    }
}

if (!$validToken) {
    $state = 'invalid';
}

// ── Handle POST (new password submission) ───────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $state !== 'invalid') {

    if (!verifyCsrf($_POST['csrf_token'] ?? '')) {
        $errors['general'] = 'Security token mismatch. Please refresh.';
    } else {
        $password = $_POST['password']         ?? '';
        $confirm  = $_POST['confirm_password'] ?? '';

        if ($password === '') {
            $errors['password'] = 'New password is required.';
        } elseif (strlen($password) < 8) {
            $errors['password'] = 'Password must be at least 8 characters.';
        } elseif (!preg_match('/[A-Z]/', $password)) {
            $errors['password'] = 'Must include at least one uppercase letter.';
        } elseif (!preg_match('/[0-9]/', $password)) {
            $errors['password'] = 'Must include at least one number.';
        } elseif (!preg_match('/[\W_]/', $password)) {
            $errors['password'] = 'Must include at least one special character (!@#$...).';
        }

        if ($confirm === '') {
            $errors['confirm'] = 'Please confirm your new password.';
        } elseif (!isset($errors['password']) && $confirm !== $password) {
            $errors['confirm'] = 'Passwords do not match.';
        }

        if (empty($errors)) {
            $db   = getDB();
            $hash_new = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

            // Update password
            $db->prepare("UPDATE users SET password = ? WHERE id = ?")
               ->execute([$hash_new, $validToken['user_id']]);

            // Mark token as used
            $db->prepare("UPDATE password_resets SET used = 1 WHERE token_hash = ?")
               ->execute([hash('sha256', $token)]);

            // Invalidate all remember_me tokens (force re-login everywhere)
            $db->prepare("DELETE FROM remember_tokens WHERE user_id = ?")
               ->execute([$validToken['user_id']]);

            $state = 'success';
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
  <title>Reset Password – <?= APP_NAME ?></title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"/>
  <style>
    :root{--bg:#05080f;--surface:#0c1120;--surf2:#121929;--border:rgba(255,255,255,0.07);--accent:#00e5ff;--accent2:#7b61ff;--danger:#ff4d6d;--safe:#00e5a0;--warn:#ffc107;--text:#e8ecf4;--muted:#7a8499;--fh:'Syne',sans-serif;--fb:'DM Sans',sans-serif;--t:0.22s cubic-bezier(.4,0,.2,1);}
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
    body{background:var(--bg);color:var(--text);font-family:var(--fb);min-height:100vh;display:flex;flex-direction:column;}
    a{text-decoration:none;color:var(--accent);}
    body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(rgba(0,229,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.03) 1px,transparent 1px);background-size:60px 60px;animation:gridMove 20s linear infinite;}
    @keyframes gridMove{0%{background-position:0 0}100%{background-position:60px 60px}}
    body::after{content:'';position:fixed;top:-200px;left:50%;transform:translateX(-50%);width:800px;height:600px;background:radial-gradient(ellipse,rgba(0,229,255,.06) 0%,rgba(123,97,255,.05) 40%,transparent 70%);pointer-events:none;z-index:0;}
    header{position:sticky;top:0;z-index:100;background:rgba(5,8,15,.88);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);}
    nav{max-width:1200px;margin:auto;padding:0 2rem;display:flex;align-items:center;height:66px;gap:1rem;}
    .nav-logo{font-family:var(--fh);font-weight:800;font-size:1.25rem;display:flex;align-items:center;gap:.5rem;letter-spacing:-.02em;color:var(--text);}
    .logo-icon{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:1rem;}
    .nav-links{margin-left:auto;display:flex;align-items:center;gap:.25rem;}
    .nav-links a{padding:.4rem .9rem;border-radius:8px;font-size:.88rem;font-weight:500;color:var(--muted);transition:all var(--t);}
    .nav-links a:hover{color:var(--text);background:rgba(255,255,255,.05);}
    .page-center{flex:1;display:flex;align-items:center;justify-content:center;padding:3rem 1.5rem;position:relative;z-index:1;}
    .card{width:100%;max-width:460px;background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:2.5rem 2.5rem 2rem;position:relative;overflow:hidden;animation:slideUp .55s cubic-bezier(.16,1,.3,1) both;}
    @keyframes slideUp{from{opacity:0;transform:translateY(30px) scale(.98)}to{opacity:1;transform:none}}
    .card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:20px 20px 0 0;}
    .card-icon{width:56px;height:56px;border-radius:14px;background:linear-gradient(135deg,rgba(0,229,255,.15),rgba(123,97,255,.15));border:1px solid rgba(0,229,255,.2);display:flex;align-items:center;justify-content:center;font-size:1.6rem;margin-bottom:1.4rem;animation:iconPop .5s .2s cubic-bezier(.34,1.56,.64,1) both;}
    @keyframes iconPop{from{opacity:0;transform:scale(.6)}to{opacity:1;transform:scale(1)}}
    .card h2{font-family:var(--fh);font-size:1.65rem;font-weight:800;letter-spacing:-.03em;margin-bottom:.4rem;}
    .card p.sub{color:var(--muted);font-size:.9rem;font-weight:300;line-height:1.6;margin-bottom:1.8rem;}
    .fg{margin-bottom:1.1rem;}
    .fg label{display:block;font-size:.75rem;font-weight:600;color:var(--muted);margin-bottom:.45rem;text-transform:uppercase;letter-spacing:.08em;}
    .pwd-wrap{position:relative;}
    .fg input{width:100%;background:var(--surf2);border:1.5px solid var(--border);border-radius:11px;padding:.85rem 2.8rem .85rem 1rem;color:var(--text);font-family:var(--fb);font-size:.95rem;transition:border-color var(--t),box-shadow var(--t);}
    .fg input:focus{outline:none;background:rgba(0,229,255,.03);border-color:rgba(0,229,255,.5);box-shadow:0 0 0 4px rgba(0,229,255,.07);}
    .fg input.is-error{border-color:var(--danger) !important;}
    .fg input.is-ok{border-color:var(--safe) !important;}
    .fg input::placeholder{color:var(--muted);}
    .pwd-toggle{position:absolute;right:12px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);cursor:pointer;font-size:.85rem;padding:4px;transition:color var(--t);}
    .pwd-toggle:hover{color:var(--text);}
    .field-err{margin-top:.35rem;font-size:.75rem;color:var(--danger);display:flex;align-items:flex-start;gap:.3rem;line-height:1.4;}
    .field-ok{margin-top:.35rem;font-size:.75rem;color:var(--safe);}
    .strength-bar{display:flex;gap:3px;margin-top:.5rem;}
    .sb{flex:1;height:4px;border-radius:100px;background:var(--surf2);transition:background .3s;}
    .strength-hint{font-size:.72rem;color:var(--muted);margin-top:.3rem;}
    .match-msg{font-size:.75rem;margin-top:.35rem;}
    .alert{border-radius:11px;padding:.9rem 1.1rem;margin-bottom:1.3rem;font-size:.85rem;display:flex;align-items:flex-start;gap:.6rem;line-height:1.5;}
    .alert-danger{background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.25);color:var(--danger);}
    .alert-warn{background:rgba(255,77,109,.04);border:1px solid rgba(255,77,109,.15);color:var(--warn);}
    .btn-submit{width:100%;padding:.9rem;border-radius:11px;border:none;cursor:pointer;background:linear-gradient(135deg,var(--accent),var(--accent2));font-family:var(--fh);font-weight:700;font-size:.95rem;color:#000;display:flex;align-items:center;justify-content:center;gap:.5rem;transition:all var(--t);}
    .btn-submit:hover{transform:translateY(-2px);box-shadow:0 12px 32px rgba(0,229,255,.28);}
    .btn-submit:disabled{opacity:.6;cursor:not-allowed;transform:none;}
    .spinner{width:16px;height:16px;border-radius:50%;border:2px solid rgba(0,0,0,.3);border-top-color:#000;animation:spin .6s linear infinite;display:none;}
    @keyframes spin{to{transform:rotate(360deg)}}
    .back-link{display:flex;align-items:center;justify-content:center;gap:.4rem;margin-top:1.4rem;font-size:.85rem;color:var(--muted);transition:color var(--t);}
    .back-link:hover{color:var(--text);}
    .back-link svg{width:14px;height:14px;}
    /* Success / invalid */
    .center-state{text-align:center;padding:.5rem 0;}
    .big-icon{width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:2rem;margin:0 auto 1.4rem;animation:successPop .5s cubic-bezier(.34,1.56,.64,1) both;}
    .big-icon.success{background:linear-gradient(135deg,rgba(0,229,160,.12),rgba(0,229,255,.12));border:1px solid rgba(0,229,160,.25);}
    .big-icon.invalid{background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.2);}
    @keyframes successPop{from{opacity:0;transform:scale(.5)}to{opacity:1;transform:scale(1)}}
    .center-state h2{font-family:var(--fh);font-size:1.5rem;font-weight:800;letter-spacing:-.03em;margin-bottom:.6rem;}
    .center-state p{color:var(--muted);font-size:.9rem;font-weight:300;line-height:1.7;max-width:320px;margin:0 auto .3rem;}
    .btn-cta{display:inline-flex;align-items:center;gap:.5rem;padding:.8rem 1.8rem;border-radius:11px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#000;font-family:var(--fh);font-weight:700;font-size:.9rem;margin-top:1.5rem;transition:all var(--t);}
    .btn-cta:hover{transform:translateY(-2px);box-shadow:0 10px 28px rgba(0,229,255,.25);}
    .progress-steps{display:flex;align-items:center;gap:.4rem;margin-bottom:1.8rem;}
    .ps-dot{width:8px;height:8px;border-radius:50%;background:var(--border);}
    .ps-dot.active{background:var(--accent);}
    .ps-dot.done{background:var(--safe);}
    .ps-line{flex:1;height:1px;background:var(--border);min-width:20px;}
    .ps-line.done{background:var(--safe);}
    footer{background:var(--surface);border-top:1px solid var(--border);position:relative;z-index:1;}
    .footer-bar{max-width:1200px;margin:auto;padding:1.1rem 2rem;display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem;font-size:.78rem;color:var(--muted);}
    @media(max-width:500px){.card{padding:2rem 1.5rem 1.5rem;}}
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
      <a href="login.php">Sign In</a>
      <a href="register.php">Create Account</a>
    </div>
  </nav>
</header>

<div class="page-center">
  <div class="card">

  <?php if ($state === 'invalid'): ?>
    <!-- ── INVALID TOKEN ── -->
    <div class="center-state">
      <div class="big-icon invalid">⛔</div>
      <h2>Link expired or invalid</h2>
      <p>This password reset link has already been used, expired, or is invalid. Reset links are only valid for <strong style="color:var(--text)">1 hour</strong>.</p>
      <a href="forgot_password.php" class="btn-cta">🔑 Request a new link</a>
    </div>
    <a href="login.php" class="back-link">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
      Back to Sign In
    </a>

  <?php elseif ($state === 'success'): ?>
    <!-- ── SUCCESS ── -->
    <div class="center-state">
      <div class="big-icon success">✅</div>
      <h2>Password updated!</h2>
      <p>Your password has been reset successfully. All other sessions have been signed out for your security.</p>
      <a href="login.php" class="btn-cta">🔐 Sign In Now</a>
    </div>

  <?php else: ?>
    <!-- ── FORM ── -->
    <div class="progress-steps">
      <div class="ps-dot done"></div>
      <div class="ps-line done"></div>
      <div class="ps-dot active"></div>
      <div class="ps-line"></div>
      <div class="ps-dot"></div>
    </div>

    <div class="card-icon">🔒</div>
    <h2>Create new password</h2>
    <p class="sub">
      Hi <strong style="color:var(--text)"><?= htmlspecialchars($tokenUser['first_name']) ?></strong> — choose a strong new password for your account.
    </p>

    <?php if (!empty($errors['general'])): ?>
      <div class="alert alert-danger"><span>⚠</span> <?= htmlspecialchars($errors['general']) ?></div>
    <?php endif; ?>

    <form method="POST" action="reset_password.php?token=<?= urlencode($token) ?>" id="resetForm" novalidate>
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf) ?>"/>
      <input type="hidden" name="token"      value="<?= htmlspecialchars($token) ?>"/>

      <div class="fg">
        <label>New Password</label>
        <div class="pwd-wrap">
          <input type="password" name="password" id="password"
            placeholder="Min 8 chars, uppercase, number, symbol"
            autocomplete="new-password" maxlength="128"
            class="<?= isset($errors['password']) ? 'is-error' : '' ?>"
            oninput="updateStrength(this.value)"/>
          <button type="button" class="pwd-toggle" onclick="togglePwd('password',this)">👁</button>
        </div>
        <div class="strength-bar">
          <div class="sb" id="sb1"></div>
          <div class="sb" id="sb2"></div>
          <div class="sb" id="sb3"></div>
          <div class="sb" id="sb4"></div>
        </div>
        <div class="strength-hint" id="sHint">Enter your new password</div>
        <?php if (isset($errors['password'])): ?>
          <div class="field-err">⚠ <?= htmlspecialchars($errors['password']) ?></div>
        <?php endif; ?>
        <div class="field-err" id="js-pwd-err" style="display:none"></div>
      </div>

      <div class="fg">
        <label>Confirm New Password</label>
        <div class="pwd-wrap">
          <input type="password" name="confirm_password" id="confirm_password"
            placeholder="Repeat your new password"
            autocomplete="new-password" maxlength="128"
            class="<?= isset($errors['confirm']) ? 'is-error' : '' ?>"
            oninput="checkMatch()"/>
          <button type="button" class="pwd-toggle" onclick="togglePwd('confirm_password',this)">👁</button>
        </div>
        <div class="match-msg" id="matchMsg"></div>
        <?php if (isset($errors['confirm'])): ?>
          <div class="field-err">⚠ <?= htmlspecialchars($errors['confirm']) ?></div>
        <?php endif; ?>
      </div>

      <button type="submit" class="btn-submit" id="submitBtn">
        <div class="spinner" id="spinner"></div>
        <span id="btnText">Update Password</span>
      </button>
    </form>

    <a href="login.php" class="back-link">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
      Back to Sign In
    </a>
  <?php endif; ?>

  </div>
</div>

<footer>
  <div class="footer-bar">
    <span>© 2026 <?= APP_NAME ?>. All rights reserved.</span>
    <span>🔒 Tokens expire in 1 hour & are single-use</span>
  </div>
</footer>

<script>
// Strength meter
function updateStrength(v) {
  const bars  = ['sb1','sb2','sb3','sb4'].map(i => document.getElementById(i));
  const hint  = document.getElementById('sHint');
  let s = 0;
  if (v.length >= 8) s++;
  if (/[A-Z]/.test(v) && /[a-z]/.test(v)) s++;
  if (/[0-9]/.test(v)) s++;
  if (/[\W_]/.test(v)) s++;
  const lvl = [
    {c:'transparent',l:'Enter your new password'},
    {c:'#ff4d6d',    l:'Weak – add numbers & symbols'},
    {c:'#ffc107',    l:'Fair – add a special character'},
    {c:'#00c6ff',    l:'Good – almost there!'},
    {c:'#00e5a0',    l:'Strong ✓'}
  ];
  bars.forEach((b,i) => b.style.background = i < s ? lvl[s].c : 'var(--surf2)');
  hint.textContent = lvl[s].l;
  hint.style.color = s === 0 ? 'var(--muted)' : lvl[s].c;
}

// Match check
function checkMatch() {
  const p1  = document.getElementById('password').value;
  const p2  = document.getElementById('confirm_password').value;
  const msg = document.getElementById('matchMsg');
  const el  = document.getElementById('confirm_password');
  if (!p2) { msg.innerHTML = ''; return; }
  if (p1 === p2) {
    msg.innerHTML = '<span style="color:var(--safe)">✓ Passwords match</span>';
    el.classList.remove('is-error'); el.classList.add('is-ok');
  } else {
    msg.innerHTML = '<span style="color:var(--danger)">⚠ Passwords do not match</span>';
    el.classList.add('is-error'); el.classList.remove('is-ok');
  }
}

// Toggle visibility
function togglePwd(id, btn) {
  const inp = document.getElementById(id);
  inp.type  = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '👁' : '🙈';
}

// Form submit validation
const form = document.getElementById('resetForm');
if (form) {
  form.addEventListener('submit', function(e) {
    const pwd  = document.getElementById('password').value;
    const conf = document.getElementById('confirm_password').value;
    const err  = document.getElementById('js-pwd-err');
    let ok = true;

    err.style.display = 'none'; err.textContent = '';

    if (!pwd) {
      err.textContent = '⚠ Password is required.';
      err.style.display = 'flex';
      document.getElementById('password').classList.add('is-error');
      ok = false;
    } else if (pwd.length < 8) {
      err.textContent = '⚠ At least 8 characters.';
      err.style.display = 'flex';
      ok = false;
    } else if (!/[A-Z]/.test(pwd)) {
      err.textContent = '⚠ Add at least one uppercase letter.';
      err.style.display = 'flex';
      ok = false;
    } else if (!/[0-9]/.test(pwd)) {
      err.textContent = '⚠ Add at least one number.';
      err.style.display = 'flex';
      ok = false;
    } else if (!/[\W_]/.test(pwd)) {
      err.textContent = '⚠ Add at least one special character.';
      err.style.display = 'flex';
      ok = false;
    } else if (pwd !== conf) {
      document.getElementById('confirm_password').classList.add('is-error');
      ok = false;
    }

    if (!ok) { e.preventDefault(); return; }

    document.getElementById('spinner').style.display = 'block';
    document.getElementById('btnText').textContent    = 'Updating…';
    document.getElementById('submitBtn').disabled     = true;
  });
}
</script>
</body>
</html>
