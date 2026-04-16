"""server/login_html.py — SCMS login page HTML template."""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCMS — Login</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#060a0e;--surface:#0b1018;--panel:#0f161e;--border:#1a2d3d;--text:#cdd6e0;--muted:#5a7080;--accent:#00d4aa;--red:#f85149}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.07) 2px,rgba(0,0,0,.07) 4px);pointer-events:none}
body::after{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% 50%,rgba(0,212,170,.04),transparent 60%);pointer-events:none}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:44px 40px;width:100%;max-width:420px;position:relative;z-index:1}
.brand{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;color:var(--accent);border:1px solid var(--accent);padding:4px 12px;border-radius:3px;letter-spacing:.12em;display:inline-block;margin-bottom:28px}
h1{font-size:22px;font-weight:500;margin-bottom:4px}
.sub{font-size:12px;color:var(--muted);margin-bottom:32px;font-family:'IBM Plex Mono',monospace}
.fg{margin-bottom:18px}
label{display:block;font-size:10px;font-weight:500;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;margin-bottom:7px}
input[type=text],input[type=password]{width:100%;background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:11px 14px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:13px;outline:none;transition:border .15s}
input:focus{border-color:var(--accent)}
.btn{width:100%;background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.5);border-radius:5px;padding:12px;color:var(--accent);font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;letter-spacing:.08em;cursor:pointer;transition:all .15s;margin-top:8px}
.btn:hover{background:rgba(0,212,170,.2);border-color:var(--accent)}
.error{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);border-radius:5px;padding:10px 14px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--red);margin-bottom:20px}
.foot{text-align:center;margin-top:24px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)}
</style>
</head>
<body>
<div class="card">
  <div class="brand">SCMS</div>
  <h1>Secure Login</h1>
  <p class="sub">Secure Continuous Monitoring System</p>
  {% if error %}<div class="error">&#10005; {{ error }}</div>{% endif %}
  <form method="post" action="/login">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
    <div class="fg">
      <label>Username</label>
      <input type="text" name="username" value="{{ username_prefill or '' }}" autocomplete="username" autofocus required>
    </div>
    <div class="fg">
      <label>Password</label>
      <input type="password" name="password" autocomplete="current-password" required>
    </div>
    <button type="submit" class="btn">AUTHENTICATE</button>
  </form>
  <div class="foot">ICS/SCADA Security Monitoring Platform</div>
</div>
</body>
</html>"""
