<?php
/**
 * TruthGuard AI – Dashboard (dashboard.php)
 * Protected page — only accessible when logged in.
 * Shows user profile from session.
 */

require_once 'config.php';
secureSession();
requireLogin(); // Redirects to login.php if not logged in

// Get fresh user data from DB (session could be stale)
$db   = getDB();
$stmt = $db->prepare("SELECT * FROM users WHERE id = ? LIMIT 1");
$stmt->execute([$_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user) {
    // User deleted from DB — force logout
    session_destroy();
    redirect(APP_URL . '/login.php');
}

// Get analysis count for this user
$stmtCount = $db->prepare("SELECT COUNT(*) FROM analyses WHERE user_id = ?");
$stmtCount->execute([$user['id']]);
$analysisCount = (int)$stmtCount->fetchColumn();

// Get recent analyses
$stmtRecent = $db->prepare(
    "SELECT verdict, score, created_at, SUBSTRING(content,1,80) as preview
     FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 5"
);
$stmtRecent->execute([$user['id']]);
$recentAnalyses = $stmtRecent->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Dashboard – <?= APP_NAME ?></title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet"/>
  <style>
    :root{--bg:#05080f;--surface:#0c1120;--surface2:#121929;--border:rgba(255,255,255,0.07);--accent:#00e5ff;--accent2:#7b61ff;--danger:#ff4d6d;--safe:#00e5a0;--warn:#ffc107;--text:#e8ecf4;--muted:#7a8499;--font-head:'Syne',sans-serif;--font-body:'DM Sans',sans-serif;--t:0.22s cubic-bezier(.4,0,.2,1);}
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
    body{background:var(--bg);color:var(--text);font-family:var(--font-body);min-height:100vh;display:flex;flex-direction:column;}
    a{text-decoration:none;color:var(--accent);}
    body::before{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");pointer-events:none;z-index:0;}

    /* NAV */
    header{position:sticky;top:0;z-index:100;background:rgba(5,8,15,.9);backdrop-filter:blur(18px);border-bottom:1px solid var(--border);}
    nav{max-width:1200px;margin:auto;padding:0 2rem;display:flex;align-items:center;height:66px;gap:1rem;}
    .nav-logo{font-family:var(--font-head);font-weight:800;font-size:1.25rem;display:flex;align-items:center;gap:.5rem;letter-spacing:-.02em;color:var(--text);}
    .logo-icon{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:1rem;}
    .nav-links{margin-left:auto;display:flex;align-items:center;gap:.5rem;}
    .nav-links a{padding:.4rem .9rem;border-radius:8px;font-size:.88rem;font-weight:500;color:var(--muted);transition:all var(--t);}
    .nav-links a:hover{color:var(--text);background:rgba(255,255,255,.05);}

    /* User pill in nav */
    .nav-user{display:flex;align-items:center;gap:.6rem;background:var(--surface);border:1px solid var(--border);border-radius:100px;padding:.35rem .8rem .35rem .45rem;cursor:pointer;transition:border-color var(--t);}
    .nav-user:hover{border-color:rgba(0,229,255,.3);}
    .user-avatar{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.8rem;color:#000;flex-shrink:0;}
    .user-name{font-size:.85rem;font-weight:500;color:var(--text);}
    .btn-logout{padding:.4rem .9rem;border-radius:8px;font-size:.85rem;font-weight:600;color:var(--danger);background:rgba(255,77,109,.08);border:1px solid rgba(255,77,109,.2);cursor:pointer;transition:all var(--t);}
    .btn-logout:hover{background:rgba(255,77,109,.15);}

    /* MAIN */
    main{max-width:1200px;margin:0 auto;padding:2.5rem 2rem;flex:1;width:100%;}

    /* Welcome banner */
    .welcome-banner{background:linear-gradient(135deg,rgba(0,229,255,.07),rgba(123,97,255,.07));border:1px solid var(--border);border-radius:16px;padding:2rem 2.5rem;display:flex;align-items:center;gap:2rem;margin-bottom:2rem;flex-wrap:wrap;}
    .welcome-avatar{width:64px;height:64px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-family:var(--font-head);font-weight:800;font-size:1.5rem;color:#000;flex-shrink:0;}
    .welcome-text h1{font-family:var(--font-head);font-size:1.5rem;font-weight:800;letter-spacing:-.02em;}
    .welcome-text p{color:var(--muted);font-size:.9rem;margin-top:.3rem;}
    .role-badge{display:inline-flex;align-items:center;gap:.3rem;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.2);color:var(--accent);border-radius:100px;padding:.2rem .8rem;font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.08em;margin-top:.6rem;}

    /* Stats grid */
    .stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem;}
    .stat-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:1.5rem;transition:border-color var(--t);}
    .stat-card:hover{border-color:rgba(0,229,255,.2);}
    .stat-label{font-size:.75rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:.5rem;}
    .stat-value{font-family:var(--font-head);font-size:1.8rem;font-weight:800;}
    .stat-sub{font-size:.78rem;color:var(--muted);margin-top:.3rem;}

    /* Two column layout */
    .dash-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;}

    /* Cards */
    .card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:1.5rem;}
    .card-title{font-family:var(--font-head);font-weight:700;font-size:1rem;margin-bottom:1.2rem;display:flex;align-items:center;gap:.5rem;}

    /* Profile info */
    .profile-field{display:flex;flex-direction:column;gap:.2rem;padding:.75rem 0;border-bottom:1px solid var(--border);}
    .profile-field:last-child{border-bottom:none;}
    .pf-label{font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);}
    .pf-value{font-size:.92rem;color:var(--text);}

    /* Recent analyses */
    .analysis-item{padding:.75rem 0;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:.8rem;}
    .analysis-item:last-child{border-bottom:none;}
    .verdict-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;margin-top:4px;}
    .v-credible{background:var(--safe);}
    .v-fake{background:var(--danger);}
    .v-unverified{background:var(--warn);}
    .analysis-preview{font-size:.83rem;color:var(--muted);line-height:1.5;}
    .analysis-meta{font-size:.72rem;color:var(--muted);margin-top:.2rem;}

    /* Empty state */
    .empty{text-align:center;padding:2rem;color:var(--muted);font-size:.88rem;}
    .empty-icon{font-size:2rem;margin-bottom:.5rem;}

    /* Action buttons */
    .btn-primary{display:inline-flex;align-items:center;gap:.5rem;padding:.7rem 1.4rem;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--accent2));color:#000;font-family:var(--font-head);font-weight:700;font-size:.88rem;border:none;cursor:pointer;transition:all var(--t);}
    .btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,229,255,.25);}

    footer{background:var(--surface);border-top:1px solid var(--border);}
    .footer-bar{max-width:1200px;margin:auto;padding:1rem 2rem;display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem;font-size:.78rem;color:var(--muted);}

    @media(max-width:768px){.dash-grid{grid-template-columns:1fr;}.welcome-banner{flex-direction:column;text-align:center;}}
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
      <a href="index.php">Home</a>
      <a href="index.php#detect">Detector</a>
      <!-- User pill -->
      <div class="nav-user">
        <div class="user-avatar"><?= strtoupper(substr($user['first_name'],0,1)) ?></div>
        <span class="user-name"><?= htmlspecialchars($user['first_name']) ?></span>
      </div>
      <!-- Logout -->
      <a href="logout.php" class="btn-logout">Sign Out</a>
    </div>
  </nav>
</header>

<main>

  <!-- Welcome Banner -->
  <div class="welcome-banner">
    <div class="welcome-avatar"><?= strtoupper(substr($user['first_name'],0,1)) ?></div>
    <div class="welcome-text">
      <h1>Welcome back, <?= htmlspecialchars($user['first_name']) ?>! 👋</h1>
      <p>Here's your TruthGuard AI dashboard. Keep fighting misinformation.</p>
      <div class="role-badge">
        <?= $user['role'] === 'admin' ? '⚡ Admin' : '🛡 ' . ucfirst($user['role']) ?>
      </div>
    </div>
    <div style="margin-left:auto">
      <a href="index.php#detect" class="btn-primary">🔍 Analyze News</a>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Analyses</div>
      <div class="stat-value" style="color:var(--accent)"><?= $analysisCount ?></div>
      <div class="stat-sub">articles verified</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Member Since</div>
      <div class="stat-value" style="font-size:1.2rem;margin-top:.3rem"><?= date('M Y', strtotime($user['created_at'])) ?></div>
      <div class="stat-sub"><?= floor((time() - strtotime($user['created_at'])) / 86400) ?> days ago</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Last Login</div>
      <div class="stat-value" style="font-size:1rem;margin-top:.3rem">
        <?= $user['last_login'] ? date('d M Y, H:i', strtotime($user['last_login'])) : 'First time!' ?>
      </div>
      <div class="stat-sub">previous session</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Account Plan</div>
      <div class="stat-value" style="font-size:1.2rem;margin-top:.3rem;color:var(--accent2)">
        <?= $user['role'] === 'admin' ? 'Admin' : 'Free' ?>
      </div>
      <div class="stat-sub"><a href="index.php#pricing">Upgrade to Pro →</a></div>
    </div>
  </div>

  <!-- Two column: Profile + Recent Activity -->
  <div class="dash-grid">

    <!-- Profile Card -->
    <div class="card">
      <div class="card-title">👤 Your Profile</div>

      <div class="profile-field">
        <span class="pf-label">Full Name</span>
        <span class="pf-value"><?= htmlspecialchars($user['first_name'] . ' ' . $user['last_name']) ?></span>
      </div>
      <div class="profile-field">
        <span class="pf-label">Username</span>
        <span class="pf-value">@<?= htmlspecialchars($user['username']) ?></span>
      </div>
      <div class="profile-field">
        <span class="pf-label">Email Address</span>
        <span class="pf-value"><?= htmlspecialchars($user['email']) ?></span>
      </div>
      <div class="profile-field">
        <span class="pf-label">Account Role</span>
        <span class="pf-value"><?= ucfirst(htmlspecialchars($user['role'])) ?></span>
      </div>
      <div class="profile-field">
        <span class="pf-label">Account Status</span>
        <span class="pf-value" style="color:<?= $user['is_active'] ? 'var(--safe)' : 'var(--danger)' ?>">
          <?= $user['is_active'] ? '✅ Active' : '❌ Inactive' ?>
        </span>
      </div>
      <div class="profile-field">
        <span class="pf-label">Member Since</span>
        <span class="pf-value"><?= date('d F Y', strtotime($user['created_at'])) ?></span>
      </div>

      <div style="margin-top:1.2rem">
        <a href="index.php#detect" class="btn-primary" style="font-size:.82rem;padding:.6rem 1.2rem">🔍 Start Analyzing</a>
      </div>
    </div>

    <!-- Recent Activity -->
    <div class="card">
      <div class="card-title">📋 Recent Analyses</div>

      <?php if (empty($recentAnalyses)): ?>
        <div class="empty">
          <div class="empty-icon">📰</div>
          <p>No analyses yet.</p>
          <p style="margin-top:.4rem"><a href="index.php#detect">Analyze your first article →</a></p>
        </div>
      <?php else: ?>
        <?php foreach ($recentAnalyses as $a): ?>
          <div class="analysis-item">
            <div class="verdict-dot v-<?= htmlspecialchars($a['verdict']) ?>"></div>
            <div>
              <div class="analysis-preview"><?= htmlspecialchars($a['preview']) ?>…</div>
              <div class="analysis-meta">
                <?= ucfirst($a['verdict']) ?> · Score: <?= $a['score'] ?>% · <?= date('d M Y', strtotime($a['created_at'])) ?>
              </div>
            </div>
          </div>
        <?php endforeach; ?>
      <?php endif; ?>
    </div>

  </div><!-- /dash-grid -->

</main>

<footer>
  <div class="footer-bar">
    <span>© 2026 <?= APP_NAME ?>. All rights reserved.</span>
    <span>Logged in as <?= htmlspecialchars($user['email']) ?> · <a href="logout.php">Sign out</a></span>
  </div>
</footer>
</body>
</html>
