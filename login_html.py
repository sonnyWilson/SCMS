"""
server/login_html.py — Secure Continuous Monitoring System
Login page HTML. All user-facing strings rendered server-side with
Jinja2 escaping — no client-side interpolation of server data.
"""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCMS — Login</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#060a0e;--surface:#0b1018;--panel:#0f161e;--card:#111c26;
  --border:#1a2d3d;--text:#cdd6e0;--muted:#5a7080;
  --accent:#00d4aa;--red:#f85149;--blue:#0ea5e9;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  background:var(--bg);color:var(--text);
  font-family:'IBM Plex Sans',sans-serif;font-size:14px;
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  background-image:
    radial-gradient(ellipse at 20% 50%, rgba(0,212,170,0.04) 0%, transparent 60%),
    radial-gradient(ellipse at 80% 20%, rgba(14,165,233,0.04) 0%, transparent 60%);
}
body::before{
  content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.05) 2px,rgba(0,0,0,0.05) 4px);
  pointer-events:none;z-index:0;
}
.login-wrap{
  position:relative;z-index:1;
  width:100%;max-width:400px;padding:20px;
}
.brand-block{text-align:center;margin-bottom:32px}
.brand-tag{
  display:inline-block;
  font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;
  color:var(--accent);border:1px solid var(--accent);
  padding:4px 14px;border-radius:3px;letter-spacing:.14em;
  margin-bottom:16px;
}
.brand-title{
  font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:600;
  color:var(--text);letter-spacing:.04em;
}
.brand-sub{font-size:12px;color:var(--muted);margin-top:6px;letter-spacing:.04em}

.card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:32px;
}
.card-title{
  font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;
  letter-spacing:.12em;color:var(--muted);text-transform:uppercase;
  margin-bottom:24px;
}
.field{margin-bottom:18px}
.field label{
  display:block;font-size:11px;font-weight:500;
  color:var(--muted);letter-spacing:.06em;text-transform:uppercase;
  margin-bottom:7px;
}
.field input{
  width:100%;background:var(--panel);border:1px solid var(--border);
  border-radius:5px;padding:11px 14px;color:var(--text);
  font-family:'IBM Plex Mono',monospace;font-size:13px;outline:none;
  transition:border-color .15s;
}
.field input:focus{border-color:var(--accent);}
.field input::placeholder{color:var(--muted)}

.error-box{
  background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.3);
  border-radius:5px;padding:10px 14px;margin-bottom:18px;
  font-size:12px;color:var(--red);font-family:'IBM Plex Mono',monospace;
  display:{% if error %}flex{% else %}none{% endif %};
  align-items:center;gap:8px;
}
.btn-login{
  width:100%;padding:12px;background:var(--accent);border:none;
  border-radius:5px;color:#060a0e;font-family:'IBM Plex Mono',monospace;
  font-size:13px;font-weight:600;letter-spacing:.06em;cursor:pointer;
  transition:opacity .15s;margin-top:4px;
}
.btn-login:hover{opacity:.88}
.btn-login:active{opacity:.75}
.login-footer{
  text-align:center;margin-top:20px;
  font-size:11px;color:var(--muted);font-family:'IBM Plex Mono',monospace;
}
.security-badges{
  display:flex;justify-content:center;gap:10px;margin-top:16px;flex-wrap:wrap;
}
.badge{
  font-size:9px;font-family:'IBM Plex Mono',monospace;
  color:var(--muted);border:1px solid var(--border);
  padding:2px 8px;border-radius:2px;letter-spacing:.06em;
}
</style>
</head>
<body>
<div class="login-wrap">
  <div class="brand-block">
    <div class="brand-tag">SCMS</div>
    <div class="brand-title">Secure Continuous Monitoring System</div>
    <div class="brand-sub">Secure Dashboard Access</div>
  </div>

  <div class="card">
    <div class="card-title">Sign In</div>

    {% if error %}
    <div class="error-box">
      <span>⊘</span>
      <span>{{ error | e }}</span>
    </div>
    {% endif %}

    <form method="POST" action="/login" autocomplete="off">
      <!-- CSRF token as hidden field for form submissions -->
      <input type="hidden" name="_csrf_token" value="{{ csrf_token | e }}">

      <div class="field">
        <label for="username">Username</label>
        <input type="text" id="username" name="username"
               placeholder="admin" required
               autocomplete="username" maxlength="64"
               value="{{ username_prefill | e }}">
      </div>

      <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" name="password"
               placeholder="••••••••••••" required
               autocomplete="current-password" maxlength="128">
      </div>

      <button type="submit" class="btn-login">AUTHENTICATE →</button>
    </form>
  </div>

  <div class="login-footer">Protected system — authorised access only</div>

</div>
</body>
</html>
"""
