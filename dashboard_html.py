"""
server/dashboard_html.py — Secure Continuous Monitoring System
The full dashboard HTML template, extracted into its own module so
app.py stays lean.  Rendered by routes.py via render_template_string().
"""

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCMS — Secure Continuous Monitoring System</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:ital,wght@0,400;0,500;0,600;1,400&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" nonce="{{ nonce }}"></script>
<style>
:root {
  --bg:      #060a0e;
  --surface: #0b1018;
  --panel:   #0f161e;
  --card:    #111c26;
  --border:  #1a2d3d;
  --border2: #223344;
  --text:    #cdd6e0;
  --muted:   #5a7080;
  --accent:  #00d4aa;
  --blue:    #0ea5e9;
  --red:     #f85149;
  --orange:  #e3a03a;
  --yellow:  #d29922;
  --green:   #3fb950;
  --purple:  #bc8cff;
  --cyan:    #79c0ff;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;font-size:13px;min-height:100vh;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.06) 2px,rgba(0,0,0,0.06) 4px);pointer-events:none;z-index:9999}

/* NAV */
nav{background:var(--surface);border-bottom:1px solid var(--border);height:52px;display:flex;align-items:center;justify-content:space-between;padding:0 20px;position:sticky;top:0;z-index:300}
.brand{font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:600;color:var(--accent);border:1px solid var(--accent);padding:3px 10px;border-radius:3px;letter-spacing:.1em}
.nav-center{display:flex;align-items:center;gap:4px;overflow-x:auto}
.nav-tab{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:500;letter-spacing:.06em;padding:5px 14px;border-radius:4px;border:1px solid transparent;background:none;color:var(--muted);cursor:pointer;transition:all .15s;white-space:nowrap}
.nav-tab:hover{color:var(--text);border-color:var(--border2)}
.nav-tab.active{color:var(--accent);border-color:var(--accent);background:rgba(0,212,170,.08)}
.nav-right{display:flex;align-items:center;gap:12px;flex-shrink:0}
.live-badge{display:flex;align-items:center;gap:5px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--accent)}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--accent);animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}
.nav-time{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)}
.nav-btn{font-family:'IBM Plex Mono',monospace;font-size:10px;padding:4px 11px;border-radius:3px;border:1px solid var(--border2);background:var(--panel);color:var(--text);cursor:pointer;transition:all .12s}
.nav-btn:hover{border-color:var(--blue);color:var(--blue)}
.nav-btn.danger{border-color:#2a1010;color:var(--red)}
.nav-btn.danger:hover{border-color:var(--red);background:rgba(248,81,73,.1)}

/* LAYOUT */
.shell{display:flex;height:calc(100vh - 52px);overflow:hidden}
.sidebar{width:260px;min-width:260px;background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;display:flex;flex-direction:column}
.main-area{flex:1;overflow-y:auto;padding:18px}

/* SIDEBAR */
.sb-section{padding:14px;border-bottom:1px solid var(--border)}
.sb-label{font-family:'IBM Plex Mono',monospace;font-size:9px;font-weight:600;letter-spacing:.14em;color:var(--muted);text-transform:uppercase;margin-bottom:10px}
.kpi-stack{display:flex;flex-direction:column;gap:6px}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center}
.kpi-lbl{font-size:10px;color:var(--muted)}
.kpi-val{font-family:'IBM Plex Mono',monospace;font-size:20px;font-weight:600;line-height:1}
.alert-stack{display:flex;flex-direction:column;gap:5px}
.al-item{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--red);border-radius:4px;padding:7px 9px;font-size:11px;cursor:pointer;transition:background .12s}
.al-item:hover{background:var(--card)}
.al-item.warn{border-left-color:var(--orange)}
.al-item.info{border-left-color:var(--blue)}
.al-ip{font-family:'IBM Plex Mono',monospace;font-weight:600;color:var(--text);font-size:11px}
.al-meta{color:var(--muted);font-size:10px;margin-top:1px}
.etype-list{display:flex;flex-direction:column;gap:3px}
.etype-row{display:flex;justify-content:space-between;align-items:center;padding:4px 7px;border-radius:3px;cursor:pointer;transition:background .1s}
.etype-row:hover,.etype-row.active{background:var(--border)}
.etype-name{font-family:'IBM Plex Mono',monospace;font-size:10px;display:flex;align-items:center;gap:7px}
.etype-dot{width:5px;height:5px;border-radius:50%}
.etype-count{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);background:var(--border);padding:1px 6px;border-radius:8px}
.sb-host{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--text);padding:4px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between}
.sb-host:last-child{border-bottom:none}

/* PAGES */
.page{display:none}.page.active{display:block}

/* STAT CARDS */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:14px 16px;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;bottom:0;left:0;right:0;height:2px}
.stat.s-red::after{background:var(--red)}.stat.s-orange::after{background:var(--orange)}
.stat.s-blue::after{background:var(--blue)}.stat.s-green::after{background:var(--green)}
.stat.s-purple::after{background:var(--purple)}.stat.s-cyan::after{background:var(--cyan)}
.stat-lbl{font-size:10px;color:var(--muted);margin-bottom:5px;letter-spacing:.04em}
.stat-val{font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:600;line-height:1}
.c-red{color:var(--red)}.c-orange{color:var(--orange)}.c-blue{color:var(--blue)}
.c-green{color:var(--green)}.c-purple{color:var(--purple)}.c-cyan{color:var(--cyan)}
.c-yellow{color:var(--yellow)}

/* PANELS */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:7px;margin-bottom:14px;overflow:hidden}
.ph{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.pt{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;letter-spacing:.1em;color:var(--muted);text-transform:uppercase}
.pb{padding:16px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:14px}

/* LOG TABLE */
.search-bar{background:var(--surface);border:1px solid var(--border);border-radius:5px;display:flex;align-items:center;padding:0 12px;gap:9px;margin-bottom:12px}
.search-bar:focus-within{border-color:var(--blue)}
.search-input{flex:1;background:none;border:none;outline:none;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:12px;padding:9px 0}
.search-input::placeholder{color:var(--muted)}
.filter-row{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.fl{font-size:10px;color:var(--muted);margin-right:4px}
.chip{font-family:'IBM Plex Mono',monospace;font-size:9px;font-weight:500;letter-spacing:.07em;padding:3px 9px;border-radius:3px;border:1px solid var(--border2);background:var(--panel);color:var(--muted);cursor:pointer;transition:all .12s;text-transform:uppercase}
.chip:hover{color:var(--text)}.chip.active{background:rgba(0,212,170,.1);border-color:var(--accent);color:var(--accent)}
.chip.cr.active{background:rgba(248,81,73,.1);border-color:var(--red);color:var(--red)}
.chip.co.active{background:rgba(227,160,58,.1);border-color:var(--orange);color:var(--orange)}
.chip.cb.active{background:rgba(14,165,233,.1);border-color:var(--blue);color:var(--blue)}
.chip.cp.active{background:rgba(188,140,255,.1);border-color:var(--purple);color:var(--purple)}
.chip.cc.active{background:rgba(121,192,255,.1);border-color:var(--cyan);color:var(--cyan)}
.chip.cy.active{background:rgba(210,153,34,.1);border-color:var(--yellow);color:var(--yellow)}
table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px}
thead{position:sticky;top:0;z-index:10}
th{background:var(--panel);padding:8px 12px;text-align:left;font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--text)}
td{padding:7px 12px;border-bottom:1px solid rgba(26,45,61,.5);vertical-align:middle;max-width:0}
tr.lr{cursor:pointer;transition:background .08s}
tr.lr:hover td{background:rgba(255,255,255,.02)}
tr.r-red td{background:rgba(248,81,73,.04)}tr.r-red:hover td{background:rgba(248,81,73,.08)}
tr.r-orange td{background:rgba(227,160,58,.03)}tr.r-orange:hover td{background:rgba(227,160,58,.07)}
.col-time{width:140px;color:var(--muted);white-space:nowrap}
.col-type{width:130px}.col-host{width:110px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.col-user{width:90px;color:var(--blue);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.col-ip{width:110px;color:var(--accent);white-space:nowrap}
.col-msg{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.col-sev{width:80px;text-align:center}
.badge{display:inline-block;padding:2px 7px;border-radius:2px;font-size:9px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;white-space:nowrap}
.badge-AUTH{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.badge-SUDO{background:rgba(227,160,58,.15);color:var(--orange);border:1px solid rgba(227,160,58,.3)}
.badge-SUSPICIOUS_COMMAND{background:rgba(248,81,73,.2);color:#ff7070;border:1px solid rgba(248,81,73,.4)}
.badge-BASH_HISTORY{background:rgba(188,140,255,.15);color:var(--purple);border:1px solid rgba(188,140,255,.3)}
.badge-SYS{background:rgba(90,112,128,.15);color:var(--muted);border:1px solid rgba(90,112,128,.3)}
.badge-CRON{background:rgba(121,192,255,.15);color:var(--cyan);border:1px solid rgba(121,192,255,.3)}
.badge-PKG_MGMT{background:rgba(14,165,233,.15);color:var(--blue);border:1px solid rgba(14,165,233,.3)}
.badge-NET_CHANGE{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.badge-SYS_ERROR{background:rgba(227,160,58,.2);color:var(--orange);border:1px solid rgba(227,160,58,.4)}
.sev-badge{display:inline-block;width:60px;text-align:center;padding:2px 0;border-radius:2px;font-size:9px;font-weight:600;letter-spacing:.06em}
.sev-3{background:rgba(248,81,73,.2);color:var(--red)}.sev-2{background:rgba(227,160,58,.2);color:var(--orange)}
.sev-1{background:rgba(210,153,34,.15);color:var(--yellow)}.sev-0{background:rgba(63,185,80,.1);color:var(--green)}
.pagination{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-top:1px solid var(--border)}
.pg-info{font-size:10px;color:var(--muted);font-family:'IBM Plex Mono',monospace}
.pg-btns{display:flex;gap:5px}
.pg-btn{font-family:'IBM Plex Mono',monospace;font-size:10px;padding:3px 10px;border:1px solid var(--border2);background:var(--panel);color:var(--text);border-radius:3px;cursor:pointer;transition:all .12s}
.pg-btn:hover{border-color:var(--accent);color:var(--accent)}.pg-btn:disabled{opacity:.3;cursor:not-allowed}
.pg-btn.cur{border-color:var(--accent);color:var(--accent);background:rgba(0,212,170,.08)}

/* DETAIL DRAWER */
#drawer{background:var(--surface);border:1px solid var(--border);border-top:2px solid var(--accent);border-radius:8px 8px 0 0;position:fixed;bottom:0;left:260px;right:0;max-height:260px;overflow-y:auto;padding:14px 20px;transform:translateY(100%);transition:transform .2s ease;z-index:250}
#drawer.open{transform:translateY(0)}
.dh{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.dt{font-family:'IBM Plex Mono',monospace;font-size:11px;font-weight:600;color:var(--accent);letter-spacing:.08em;text-transform:uppercase}
.dc{background:none;border:none;color:var(--muted);cursor:pointer;font-size:15px}
.dc:hover{color:var(--text)}
.dg{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.dk{font-size:9px;letter-spacing:.08em;color:var(--muted);text-transform:uppercase;margin-bottom:2px}
.dv{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--text);word-break:break-all}
.dr{margin-top:10px;background:var(--panel);border:1px solid var(--border);border-radius:3px;padding:8px 12px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);word-break:break-all;white-space:pre-wrap}
.mitre-chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.mitre-chip{font-family:'IBM Plex Mono',monospace;font-size:9px;padding:3px 8px;border-radius:3px;border:1px solid rgba(14,165,233,.3);background:rgba(14,165,233,.08);color:var(--blue);cursor:pointer;text-decoration:none}
.mitre-chip:hover{border-color:var(--blue);background:rgba(14,165,233,.15)}

/* FORMS */
.form-group{margin-bottom:12px}
.form-label{font-size:10px;color:var(--muted);letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px;display:block}
.form-input{width:100%;background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:8px 12px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:12px;outline:none;transition:border .15s}
.form-input:focus{border-color:var(--blue)}
.form-select{width:100%;background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:8px 12px;color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:12px;outline:none;cursor:pointer}
.btn{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:500;letter-spacing:.06em;padding:7px 14px;border-radius:4px;border:1px solid var(--border2);background:var(--panel);color:var(--text);cursor:pointer;transition:all .14s;display:inline-flex;align-items:center;gap:6px}
.btn:hover{border-color:var(--blue);color:var(--blue)}
.btn.btn-accent{border-color:var(--accent);color:var(--accent);background:rgba(0,212,170,.08)}
.btn.btn-accent:hover{background:rgba(0,212,170,.15)}
.btn.btn-red{border-color:#2a1010;color:var(--red)}
.btn.btn-red:hover{border-color:var(--red);background:rgba(248,81,73,.1)}
.btn.btn-blue{border-color:rgba(14,165,233,.3);color:var(--blue);background:rgba(14,165,233,.06)}
.btn.btn-blue:hover{background:rgba(14,165,233,.12)}
.btn.btn-sm{padding:3px 9px;font-size:9px}

/* TOAST */
#toast{position:fixed;top:64px;right:20px;z-index:400;display:flex;flex-direction:column;gap:8px}
.toast-msg{background:var(--card);border:1px solid var(--border2);border-radius:5px;padding:10px 16px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--text);animation:slideIn .2s ease;display:flex;align-items:center;gap:8px;max-width:320px}
.toast-msg.ok{border-left:3px solid var(--green)}.toast-msg.err{border-left:3px solid var(--red)}.toast-msg.info{border-left:3px solid var(--blue)}
@keyframes slideIn{from{transform:translateX(20px);opacity:0}to{transform:translateX(0);opacity:1}}

/* MISC */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.empty-state{text-align:center;padding:40px 20px;color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:11px}
.tag{font-family:'IBM Plex Mono',monospace;font-size:9px;padding:2px 7px;border-radius:2px;white-space:nowrap}
.tag-crit{background:rgba(248,81,73,.2);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.tag-high{background:rgba(227,160,58,.2);color:var(--orange);border:1px solid rgba(227,160,58,.3)}
.tag-med{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.tag-low{background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.2)}
.tag-info{background:rgba(90,112,128,.15);color:var(--muted);border:1px solid rgba(90,112,128,.3)}

/* FIM / SCA / VULN */
.fim-table,.sca-table,.vuln-table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px}
.fim-table th,.sca-table th,.vuln-table th{background:var(--panel);padding:7px 12px;text-align:left;font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
.fim-table td,.sca-table td,.vuln-table td{padding:7px 12px;border-bottom:1px solid rgba(26,45,61,.5);vertical-align:middle}
.progress-bar{height:4px;background:var(--border);border-radius:2px;overflow:hidden;margin-top:6px}
.progress-fill{height:100%;border-radius:2px;transition:width .4s ease}
.chart-wrap{position:relative;height:160px}
.mitre-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
.mitre-card{background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:10px 12px;cursor:pointer;transition:border-color .15s}
.mitre-card:hover{border-color:var(--blue)}
.mitre-id{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;color:var(--blue)}
.mitre-name{font-size:11px;color:var(--text);margin:3px 0}
.mitre-tactic{font-size:9px;color:var(--muted)}
.mitre-count{font-family:'IBM Plex Mono',monospace;font-size:20px;font-weight:600;color:var(--accent)}

/* DB Manager */
.db-list{display:flex;flex-direction:column;gap:6px}
.db-item{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:8px 12px;display:flex;justify-content:space-between;align-items:center;cursor:pointer;transition:all .12s}
.db-item:hover{border-color:var(--blue)}.db-item.active-db{border-color:var(--accent);background:rgba(0,212,170,.06)}
.db-name{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--text)}

/* Log path manager */
.path-list{display:flex;flex-direction:column;gap:5px}
.path-item{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:7px 12px;display:flex;justify-content:space-between;align-items:center;font-family:'IBM Plex Mono',monospace;font-size:11px}
.path-status{width:7px;height:7px;border-radius:50%;background:var(--green)}
.path-status.off{background:var(--muted)}
.ip-table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px}
.ip-table th{background:var(--panel);padding:7px 12px;text-align:left;font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
.ip-table td{padding:7px 12px;border-bottom:1px solid rgba(26,45,61,.5)}

/* Compliance badges */
.comp-card{background:var(--panel);border:1px solid var(--border);border-radius:7px;padding:18px;text-align:center}
.comp-status{font-family:'IBM Plex Mono',monospace;font-size:10px;font-weight:600;letter-spacing:.08em;padding:3px 10px;border-radius:3px;display:inline-block;margin-top:6px}
.comp-status.COMPLIANT{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.comp-status.PARTIAL{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.comp-status.NON-COMPLIANT{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}

/* Process table */
.proc-table{width:100%;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;font-size:11px}
.proc-table th{background:var(--panel);padding:7px 12px;text-align:left;font-size:9px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border)}
.proc-table td{padding:6px 12px;border-bottom:1px solid rgba(26,45,61,.5);vertical-align:middle}
</style>
</head>
<body>

<!-- NAV -->
<nav>
  <div style="display:flex;align-items:center;gap:14px;flex-shrink:0">
    <span class="brand">SCMS</span>
    <span style="font-size:13px;font-weight:500;letter-spacing:.02em">Secure Continuous Monitoring System</span>
  </div>
  <div class="nav-center">
    <button class="nav-tab active" id="nav-overview">Overview</button>
    <button class="nav-tab" id="nav-logs">Log Events</button>
    <button class="nav-tab" id="nav-analytics">Analytics</button>
    <button class="nav-tab" id="nav-assets">Assets</button>
    <button class="nav-tab" id="nav-network">Network</button>
    <button class="nav-tab" id="nav-ics">ICS/SCADA</button>
    <button class="nav-tab" id="nav-honeypot">Honeypot</button>
    <button class="nav-tab" id="nav-fim">File Integrity</button>
    <button class="nav-tab" id="nav-sca">Config Audit</button>
    <button class="nav-tab" id="nav-vuln">Vulnerabilities</button>
    <button class="nav-tab" id="nav-mitre">MITRE ATT&CK</button>
    <button class="nav-tab" id="nav-response">Active Response</button>
    <button class="nav-tab" id="nav-admin">Administration</button>
  </div>
  <div class="nav-right">
    <div class="live-badge"><div class="live-dot"></div><span>LIVE</span></div>
    <span class="nav-time" id="nav-time">--:--:--</span>
    <button class="nav-btn" id="btn-export-nav">⬇ Export CSV</button>
    <button class="nav-btn danger" id="btn-clear-nav">✕ Clear Logs</button>
  </div>
</nav>

<div class="shell">
<!-- SIDEBAR -->
<div class="sidebar">
  <div class="sb-section">
    <div class="sb-label">Live Metrics</div>
    <div class="kpi-stack">
      <div class="kpi"><span class="kpi-lbl">Failed Logins / min</span><span class="kpi-val c-red" id="s-failed">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Brute Force IPs</span><span class="kpi-val c-orange" id="s-brute">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Sudo Abuse</span><span class="kpi-val c-purple" id="s-sudo">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Unique Source IPs</span><span class="kpi-val c-cyan" id="s-ips">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Total Log Events</span><span class="kpi-val" id="s-total">0</span></div>
      <div class="kpi"><span class="kpi-lbl">Suspicious Commands</span><span class="kpi-val c-red" id="s-susp">0</span></div>
    </div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Active Alerts</div>
    <div class="alert-stack" id="sb-alerts"><div class="empty-state">No alerts</div></div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Event Types</div>
    <div class="etype-list" id="sb-etypes"></div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Monitored Hosts</div>
    <div id="sb-hosts" style="font-family:'IBM Plex Mono',monospace;font-size:10px"></div>
  </div>
  <div class="sb-section">
    <div class="sb-label">Blocked IPs</div>
    <div id="sb-blocked" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">None</div>
  </div>
</div>

<!-- MAIN AREA -->
<div class="main-area">

<!-- OVERVIEW -->
<div class="page active" id="page-overview">
  <div class="stats-row">
    <div class="stat s-red"><div class="stat-lbl">Failed Auth Events</div><div class="stat-val c-red" id="ov-failed">0</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Auth Events Total</div><div class="stat-val c-orange" id="ov-auth">0</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Suspicious Commands</div><div class="stat-val c-blue" id="ov-susp">0</div></div>
    <div class="stat s-purple"><div class="stat-lbl">Monitored Hosts</div><div class="stat-val c-purple" id="ov-hosts">0</div></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Events Over Time (60 min)</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="chart-timeline"></canvas></div></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Event Type Breakdown</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="chart-etypes"></canvas></div></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Top Attacker IPs</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="chart-ips"></canvas></div></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Severity Distribution</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="chart-sev"></canvas></div></div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Recent High-Severity Events</span><span id="ov-log-count" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">—</span></div>
    <div style="overflow-x:auto">
      <table><thead><tr>
        <th class="col-time">Timestamp</th><th class="col-type">Type</th>
        <th class="col-host">Host</th><th class="col-user">User</th>
        <th class="col-ip">Source IP</th><th class="col-msg">Message</th><th class="col-sev">Severity</th>
      </tr></thead>
      <tbody id="ov-table"></tbody></table>
    </div>
  </div>
</div>

<!-- LOG EVENTS -->
<div class="page" id="page-logs">
  <div class="search-bar">
    <span style="color:var(--muted);font-size:13px">⌕</span>
    <input class="search-input" id="log-search" placeholder="Search messages, IPs, usernames…">
    <span id="log-count" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);white-space:nowrap">0 events</span>
  </div>
  <div class="filter-row">
    <span class="fl">Filter:</span>
    <span class="chip active" data-filter="ALL">ALL</span>
    <span class="chip cr" data-filter="AUTH">AUTH</span>
    <span class="chip co" data-filter="SUDO">SUDO</span>
    <span class="chip cr" data-filter="SUSPICIOUS_COMMAND">SUSPICIOUS</span>
    <span class="chip cp" data-filter="BASH_HISTORY">BASH</span>
    <span class="chip cb" data-filter="SYS">SYS</span>
    <span class="chip cc" data-filter="CRON">CRON</span>
    <span class="chip cb" data-filter="PKG_MGMT">PKG_MGMT</span>
    <span class="chip cy" data-filter="NET_CHANGE">NET_CHANGE</span>
    <span class="chip co" data-filter="SYS_ERROR">SYS_ERROR</span>
    <span style="flex:1"></span>
    <span class="fl">Severity:</span>
    <span class="chip cr" data-sev="3">CRITICAL</span>
    <span class="chip co" data-sev="2">HIGH</span>
    <span class="chip" data-sev="1">MEDIUM</span>
    <span class="chip" data-sev="0">LOW</span>
  </div>
  <div class="panel" style="margin-bottom:0">
    <div style="overflow-x:auto">
      <table><thead><tr>
        <th class="col-time" data-sort="timestamp">Timestamp</th>
        <th class="col-type" data-sort="eventtype">Type</th>
        <th class="col-host" data-sort="hostname">Host</th>
        <th class="col-user" data-sort="username">User</th>
        <th class="col-ip" data-sort="sourceip">Source IP</th>
        <th class="col-msg">Message</th>
        <th class="col-sev" data-sort="threat_level">Severity</th>
      </tr></thead>
      <tbody id="log-table"></tbody></table>
    </div>
    <div class="pagination">
      <span class="pg-info" id="pg-info">Showing 0–0 of 0</span>
      <div class="pg-btns" id="pg-btns"></div>
    </div>
  </div>
</div>

<!-- ANALYTICS -->
<div class="page" id="page-analytics">
  <div class="stats-row" style="grid-template-columns:repeat(5,1fr)">
    <div class="stat s-red"><div class="stat-lbl">Total Events</div><div class="stat-val" id="an-total">0</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Failed Logins</div><div class="stat-val c-red" id="an-failed">0</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Auth Events</div><div class="stat-val c-orange" id="an-auth">0</div></div>
    <div class="stat s-green"><div class="stat-lbl">Suspicious Cmds</div><div class="stat-val c-blue" id="an-susp">0</div></div>
    <div class="stat s-purple"><div class="stat-lbl">Sudo Events</div><div class="stat-val c-purple" id="an-sudo-count">0</div></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Failed Logins Timeline</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="an-chart-tl"></canvas></div></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Auth Success vs Failure</span></div>
      <div class="pb"><div class="chart-wrap"><canvas id="an-chart-sf"></canvas></div></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Top Attacker IPs (Failed Auth)</span></div>
      <div class="pb">
        <table class="ip-table">
          <thead><tr><th>IP Address</th><th>Count</th><th>Threat</th><th>Action</th></tr></thead>
          <tbody id="an-ip-table"></tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Sudo Usage by User</span></div>
      <div class="pb">
        <table class="ip-table">
          <thead><tr><th>Username</th><th>Events</th><th>Risk</th></tr></thead>
          <tbody id="an-sudo-table"></tbody>
        </table>
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Event Heatmap (Hour of Day)</span></div>
    <div class="pb"><div style="height:100px;display:flex;align-items:flex-end;gap:3px" id="an-heatmap"></div></div>
  </div>
</div>

<!-- FILE INTEGRITY -->
<div class="page" id="page-fim">
  <div class="panel">
    <div class="ph">
      <span class="pt">File Integrity Monitoring</span>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input class="form-input" id="fim-path-input" placeholder="/path/to/file" style="width:240px;font-size:11px;padding:5px 10px">
        <button class="btn btn-accent" id="btn-add-fim-path">+ Add Path</button>
        <button class="btn btn-blue" id="btn-run-fim">▶ Run Scan</button>
        <button class="btn" id="btn-reset-fim-baseline" title="Clear baseline and re-establish">↺ Reset Baseline</button>
      </div>
    </div>
    <div class="pb">
      <div class="path-list" id="fim-paths" style="margin-bottom:14px"></div>
      <table class="fim-table">
        <thead><tr><th>File Path</th><th>SHA-256</th><th>Size</th><th>Modified</th><th>Status</th></tr></thead>
        <tbody id="fim-results"></tbody>
      </table>
      <div id="fim-empty" class="empty-state">No scan results. Add paths and run scan.</div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Baseline Comparison</span></div>
    <div class="pb">
      <div class="grid-3">
        <div class="stat s-green"><div class="stat-lbl">Files Unchanged</div><div class="stat-val c-green" id="fim-ok">0</div></div>
        <div class="stat s-orange"><div class="stat-lbl">Files Modified</div><div class="stat-val c-orange" id="fim-mod">0</div></div>
        <div class="stat s-red"><div class="stat-lbl">Files Missing/Error</div><div class="stat-val c-red" id="fim-miss">0</div></div>
      </div>
    </div>
  </div>
</div>

<!-- CONFIG AUDIT (SCA) -->
<div class="page" id="page-sca">
  <div class="stats-row" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat s-green"><div class="stat-lbl">Checks Passed</div><div class="stat-val c-green" id="sca-pass">—</div></div>
    <div class="stat s-red"><div class="stat-lbl">Checks Failed</div><div class="stat-val c-red" id="sca-fail">—</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Score</div><div class="stat-val c-blue" id="sca-score">—</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Critical Fails</div><div class="stat-val c-orange" id="sca-crit">—</div></div>
  </div>
  <div class="panel">
    <div class="ph">
      <span class="pt">CIS Benchmark — 32 Security Checks</span>
      <div style="display:flex;gap:8px;align-items:center">
        <select class="form-select" id="sca-filter" style="width:160px;padding:5px 10px;font-size:10px">
          <option value="ALL">All Checks</option>
          <option value="FAIL">Failures Only</option>
          <option value="PASS">Passed Only</option>
          <option value="CRITICAL">Critical Only</option>
        </select>
        <button class="btn btn-accent" id="btn-run-sca">▶ Run Checks</button>
      </div>
    </div>
    <div class="pb">
      <div id="sca-progress" style="display:none;margin-bottom:12px">
        <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-bottom:6px">Running CIS benchmark checks…</div>
        <div class="progress-bar"><div class="progress-fill" id="sca-pb" style="width:0%;background:var(--accent)"></div></div>
      </div>
      <table class="sca-table">
        <thead><tr><th>Check ID</th><th>Description</th><th>Framework Tags</th><th>Severity</th><th>Result</th></tr></thead>
        <tbody id="sca-results"></tbody>
      </table>
      <div id="sca-empty" class="empty-state">Click "Run Checks" to assess security configuration against 32 CIS Benchmark controls</div>
    </div>
  </div>
</div>

<!-- VULNERABILITIES -->
<div class="page" id="page-vuln">
  <div class="stats-row" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat s-red"><div class="stat-lbl">Critical CVEs</div><div class="stat-val c-red" id="vn-crit">—</div></div>
    <div class="stat s-orange"><div class="stat-lbl">High CVEs</div><div class="stat-val c-orange" id="vn-high">—</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Medium CVEs</div><div class="stat-val c-blue" id="vn-med">—</div></div>
    <div class="stat s-green"><div class="stat-lbl">Total Findings</div><div class="stat-val" id="vn-total">—</div></div>
  </div>
  <div class="panel">
    <div class="ph">
      <span class="pt">Vulnerability Detection</span>
      <div style="display:flex;gap:8px;align-items:center">
        <span id="vuln-source-badge" style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted)"></span>
        <button class="btn btn-accent" id="btn-run-vuln">▶ Scan Packages</button>
      </div>
    </div>
    <div class="pb">
      <table class="vuln-table">
        <thead><tr><th>Package</th><th>CVE ID</th><th>Severity</th><th>Description</th><th>Source</th><th>Reference</th></tr></thead>
        <tbody id="vuln-results"></tbody>
      </table>
      <div id="vuln-empty" class="empty-state">Click "Scan Packages" to check for known vulnerabilities</div>
    </div>
  </div>
</div>

<!-- MITRE ATT&CK -->
<div class="page" id="page-mitre">
  <div class="panel">
    <div class="ph">
      <span class="pt">MITRE ATT&CK v15 — Technique Correlations</span>
      <span style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">Based on live log data · Click cards to open ATT&CK</span>
    </div>
    <div class="pb">
      <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px" id="mitre-tactics"></div>
      <div class="mitre-grid" id="mitre-cards"></div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">ATT&CK Matrix Coverage</span></div>
    <div class="pb">
      <div class="grid-2">
        <div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-bottom:8px">DETECTED TACTICS</div>
          <div id="mitre-tactic-list" style="display:flex;flex-direction:column;gap:6px"></div>
        </div>
        <div><div class="chart-wrap"><canvas id="mitre-chart"></canvas></div></div>
      </div>
    </div>
  </div>
</div>

<!-- ACTIVE RESPONSE -->
<div class="page" id="page-response">
  <div class="stats-row" style="grid-template-columns:repeat(3,1fr)">
    <div class="stat s-red"><div class="stat-lbl">Blocked IPs</div><div class="stat-val c-red" id="ar-blocked-count">0</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Brute Force Detected</div><div class="stat-val c-orange" id="ar-brute">0</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Auto-Responses Fired</div><div class="stat-val c-blue" id="ar-auto">0</div></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Block IP Address</span></div>
      <div class="pb">
        <div class="form-group">
          <label class="form-label">IP Address</label>
          <input class="form-input" id="ar-ip-input" placeholder="192.168.1.100" type="text">
        </div>
        <div class="form-group">
          <label class="form-label">Reason</label>
          <select class="form-select" id="ar-reason">
            <option>Brute Force Attack</option>
            <option>Suspicious Commands</option>
            <option>Port Scanning</option>
            <option>Manual Block</option>
          </select>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-red" id="btn-block-ip">⊘ Block IP</button>
          <button class="btn" id="btn-unblock-ip">✓ Unblock IP</button>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Auto-Response Rules</span><button class="btn btn-accent" style="font-size:9px;padding:4px 10px" id="btn-save-auto-rules">Save Rules</button></div>
      <div class="pb">
        <div style="display:flex;flex-direction:column;gap:10px">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
            <input type="checkbox" id="ar-auto-brute" checked style="accent-color:var(--accent)">
            Auto-block IPs with &gt;10 failed logins
          </label>
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
            <input type="checkbox" id="ar-auto-sudo" style="accent-color:var(--accent)">
            Alert on sudo abuse (&gt;5 events)
          </label>
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
            <input type="checkbox" id="ar-auto-susp" checked style="accent-color:var(--accent)">
            Alert on suspicious commands
          </label>
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12px">
            <input type="checkbox" id="ar-email-alert" style="accent-color:var(--accent)">
            Send email on critical events (configure SMTP in .env)
          </label>
        </div>
      </div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Currently Blocked IPs</span></div>
    <div class="pb">
      <table class="ip-table">
        <thead><tr><th>IP Address</th><th>Reason</th><th>Blocked At</th><th>Action</th></tr></thead>
        <tbody id="ar-blocked-list"></tbody>
      </table>
      <div id="ar-blocked-empty" class="empty-state">No blocked IPs</div>
    </div>
  </div>
  <!-- Process Manager -->
  <div class="panel">
    <div class="ph">
      <span class="pt">Process Manager</span>
      <button class="btn btn-blue" id="btn-load-processes">↺ Refresh</button>
    </div>
    <div class="pb" style="max-height:280px;overflow-y:auto">
      <table class="proc-table">
        <thead><tr><th>PID</th><th>User</th><th>CPU%</th><th>MEM%</th><th>Command</th><th>Action</th></tr></thead>
        <tbody id="proc-table-body"></tbody>
      </table>
      <div id="proc-empty" class="empty-state">Click Refresh to load running processes</div>
    </div>
  </div>
  <div class="panel">
    <div class="ph"><span class="pt">Response Action Log</span></div>
    <div class="pb" style="max-height:200px;overflow-y:auto">
      <div id="ar-log" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);display:flex;flex-direction:column;gap:4px">
        <div style="color:var(--green)">[ SYSTEM ] Active Response module initialized</div>
      </div>
    </div>
  </div>
</div>

<!-- ADMIN -->
<div class="page" id="page-admin">
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">Database Manager</span></div>
      <div class="pb">
        <div class="form-group">
          <label class="form-label">Search / Select Database</label>
          <div style="display:flex;gap:8px">
            <input class="form-input" id="db-search-input" placeholder="Search databases…" style="flex:1">
            <button class="btn btn-accent" id="btn-load-dbs">↺ Refresh</button>
          </div>
        </div>
        <div class="db-list" id="db-list" style="max-height:180px;overflow-y:auto;margin-bottom:12px"></div>
        <hr style="border:none;border-top:1px solid var(--border);margin:12px 0">
        <div class="form-group">
          <label class="form-label">Create New Database</label>
          <div style="display:flex;gap:8px">
            <input class="form-input" id="db-create-name" placeholder="new_database_name" style="flex:1">
            <button class="btn btn-blue" id="btn-create-db">+ Create</button>
          </div>
        </div>
        <div id="db-status" style="font-family:'IBM Plex Mono',monospace;font-size:10px;margin-top:8px"></div>
      </div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">Log Path Manager</span></div>
      <div class="pb">
        <div class="form-group">
          <label class="form-label">Add Log Path to Monitor</label>
          <div style="display:flex;gap:8px">
            <input class="form-input" id="log-path-input" placeholder="/var/log/custom.log" style="flex:1">
            <button class="btn btn-accent" id="btn-add-log-path">+ Add</button>
          </div>
        </div>
        <div class="path-list" id="log-paths" style="max-height:220px;overflow-y:auto"></div>
      </div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="ph"><span class="pt">System Inventory</span></div>
      <div class="pb" id="sys-inv"><div class="empty-state">Loading inventory…</div></div>
    </div>
    <div class="panel">
      <div class="ph"><span class="pt">System Health</span></div>
      <div class="pb" id="sys-health">
        <table class="ip-table">
          <thead><tr><th>Component</th><th>Status</th></tr></thead>
          <tbody id="health-table"></tbody>
        </table>
      </div>
    </div>
  </div>
  <!-- Compliance Panel -->
  <div class="panel">
    <div class="ph">
      <span class="pt">Regulatory Compliance</span>
      <button class="btn btn-accent" id="btn-run-compliance">▶ Compute Scores</button>
    </div>
    <div class="pb">
      <div class="grid-3" id="comp-grid">
        <div class="comp-card">
          <div style="font-size:10px;color:var(--muted);margin-bottom:6px">PCI-DSS</div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:32px;font-weight:600;color:var(--orange)" id="comp-pci-val">—</div>
          <div id="comp-pci-status"></div>
          <div id="comp-pci-detail" style="font-size:10px;color:var(--muted);margin-top:6px"></div>
        </div>
        <div class="comp-card">
          <div style="font-size:10px;color:var(--muted);margin-bottom:6px">HIPAA</div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:32px;font-weight:600;color:var(--orange)" id="comp-hipaa-val">—</div>
          <div id="comp-hipaa-status"></div>
          <div id="comp-hipaa-detail" style="font-size:10px;color:var(--muted);margin-top:6px"></div>
        </div>
        <div class="comp-card">
          <div style="font-size:10px;color:var(--muted);margin-bottom:6px">NIST CSF</div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:32px;font-weight:600;color:var(--orange)" id="comp-nist-val">—</div>
          <div id="comp-nist-status"></div>
          <div id="comp-nist-detail" style="font-size:10px;color:var(--muted);margin-top:6px"></div>
        </div>
      </div>
      <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-top:10px;padding-top:8px;border-top:1px solid var(--border)">
        Scores computed from live SCA check results · Penalties applied for critical failures
      </div>
    </div>
  </div>
  <!-- CSV Import -->
  <div class="panel">
    <div class="ph"><span class="pt">CSV Import / Export</span></div>
    <div class="pb">
      <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">
        <button class="btn btn-accent" id="btn-export-admin">⬇ Export CSV (last 5000 events)</button>
        <div style="display:flex;gap:8px;align-items:center">
          <label class="btn btn-blue" style="cursor:pointer">
            ⬆ Import CSV
            <input type="file" id="csv-import-file" accept=".csv" style="display:none">
          </label>
          <span id="import-status" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)"></span>
        </div>
      </div>
    </div>
  </div>
</div>

</div><!-- /page-admin -->

<!-- ASSET MANAGEMENT -->
<div class="page" id="page-assets">
  <div class="stats-row" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat s-blue"><div class="stat-lbl">Total Assets</div><div class="stat-val c-blue" id="ast-total">—</div></div>
    <div class="stat s-red"><div class="stat-lbl">ICS Devices</div><div class="stat-val c-red" id="ast-ics">—</div></div>
    <div class="stat s-orange"><div class="stat-lbl">High Risk</div><div class="stat-val c-orange" id="ast-highrisk">—</div></div>
    <div class="stat s-green"><div class="stat-lbl">Zones</div><div class="stat-val c-green" id="ast-zones">—</div></div>
  </div>
  <div class="panel">
    <div class="ph">
      <span class="pt">Asset Inventory</span>
      <div style="display:flex;gap:8px;align-items:center">
        <input class="form-input" id="ast-search" placeholder="Search IP, hostname, vendor…" style="width:220px;font-size:11px;padding:5px 10px">
        <select class="form-select" id="ast-filter-zone" style="width:140px;font-size:10px;padding:5px 10px">
          <option value="">All Zones</option>
        </select>
        <select class="form-select" id="ast-filter-type" style="width:140px;font-size:10px;padding:5px 10px">
          <option value="">All Types</option>
          <option value="ICS">ICS Only</option>
          <option value="IT">IT Only</option>
        </select>
        <button class="btn btn-accent" id="btn-load-assets">↺ Refresh</button>
      </div>
    </div>
    <div class="pb" style="overflow-x:auto">
      <table id="ast-table">
        <thead><tr>
          <th>IP Address</th><th>Hostname</th><th>MAC</th><th>Vendor</th>
          <th>Type</th><th>OS</th><th>Zone</th><th>Criticality</th>
          <th>ICS Proto</th><th>Threat Score</th><th>Last Seen</th><th>Actions</th>
        </tr></thead>
        <tbody id="ast-tbody"></tbody>
      </table>
      <div id="ast-empty" class="empty-state">No assets found. Run a network scan to discover devices.</div>
    </div>
  </div>
  <!-- Asset Edit Modal -->
  <div id="ast-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:500;display:none;align-items:center;justify-content:center">
    <div style="background:var(--card);border:1px solid var(--border2);border-radius:8px;padding:24px;width:420px;max-width:95vw">
      <div class="ph" style="margin-bottom:16px"><span class="pt">Edit Asset</span><button class="dc" id="btn-close-ast-modal">✕</button></div>
      <input type="hidden" id="ast-edit-id">
      <div class="form-group"><label class="form-label">Criticality</label>
        <select class="form-select" id="ast-edit-crit">
          <option>CRITICAL</option><option>HIGH</option><option selected>MEDIUM</option><option>LOW</option>
        </select></div>
      <div class="form-group"><label class="form-label">Zone</label>
        <input class="form-input" id="ast-edit-zone" placeholder="e.g. Turbine Control"></div>
      <div class="form-group"><label class="form-label">Notes</label>
        <input class="form-input" id="ast-edit-notes" placeholder="Free-text notes"></div>
      <button class="btn btn-accent" id="btn-save-asset" style="margin-top:8px">Save Changes</button>
    </div>
  </div>
</div>

<!-- NETWORK ANALYSIS -->
<div class="page" id="page-network">
  <div class="stats-row" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat s-blue"><div class="stat-lbl">Packets Captured</div><div class="stat-val c-blue" id="net-pkts">0</div></div>
    <div class="stat s-red"><div class="stat-lbl">Anomalies</div><div class="stat-val c-red" id="net-anomalies">0</div></div>
    <div class="stat s-orange"><div class="stat-lbl">ICS Packets</div><div class="stat-val c-orange" id="net-ics-pkts">0</div></div>
    <div class="stat s-green"><div class="stat-lbl">Capture Status</div><div class="stat-val" id="net-status" style="font-size:12px">IDLE</div></div>
  </div>
  <div class="grid-2">
    <!-- Capture Control -->
    <div class="panel">
      <div class="ph"><span class="pt">Packet Capture</span></div>
      <div class="pb">
        <div class="form-group"><label class="form-label">Network Interface</label>
          <select class="form-select" id="net-iface"><option>eth0</option></select></div>
        <div style="display:flex;gap:8px;margin-top:10px">
          <button class="btn btn-accent" id="btn-capture-start">▶ Start Capture</button>
          <button class="btn btn-red" id="btn-capture-stop">■ Stop</button>
          <button class="btn" id="btn-capture-refresh">↺ Refresh Stats</button>
        </div>
        <div id="capture-log" style="margin-top:12px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);max-height:80px;overflow-y:auto"></div>
      </div>
    </div>
    <!-- Network Scanner -->
    <div class="panel">
      <div class="ph"><span class="pt">Network Scanner</span></div>
      <div class="pb">
        <div class="form-group"><label class="form-label">Target (IP or CIDR)</label>
          <input class="form-input" id="net-scan-target" placeholder="192.168.1.0/24"></div>
        <div class="form-group"><label class="form-label">Port Range (for port scan)</label>
          <input class="form-input" id="net-scan-ports" placeholder="1-1024" value="1-1024"></div>
        <div style="display:flex;gap:8px;margin-top:10px">
          <button class="btn btn-accent" id="btn-host-scan">🔍 Host Discovery</button>
          <button class="btn btn-blue" id="btn-port-scan">⚡ Port Scan</button>
        </div>
        <div id="scan-status" style="margin-top:8px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)"></div>
      </div>
    </div>
  </div>
  <!-- Scan Results -->
  <div class="panel" id="scan-results-panel" style="display:none">
    <div class="ph"><span class="pt">Scan Results</span><span id="scan-result-count" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)"></span></div>
    <div class="pb" style="overflow-x:auto">
      <table><thead><tr><th>IP Address</th><th>Hostname</th><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
      <tbody id="scan-results-tbody"></tbody></table>
    </div>
  </div>
  <!-- Live Packet Table -->
  <div class="panel">
    <div class="ph">
      <span class="pt">Live Packet Stream</span>
      <div style="display:flex;gap:8px;align-items:center">
        <input class="form-input" id="pkt-filter" placeholder="Filter src/dst IP…" style="width:180px;font-size:11px;padding:5px 10px">
        <select class="form-select" id="pkt-filter-proto" style="width:120px;font-size:10px;padding:5px 10px">
          <option value="">All Protocols</option>
          <option>TCP</option><option>UDP</option><option>Modbus</option>
          <option>DNP3</option><option>EtherNet/IP</option>
        </select>
        <button class="btn" id="btn-load-packets">↺ Refresh</button>
      </div>
    </div>
    <div class="pb" style="overflow-x:auto;max-height:420px">
      <table>
        <thead><tr>
          <th>Time</th><th>Src IP</th><th>Dst IP</th><th>Src Port</th><th>Dst Port</th>
          <th>Proto</th><th>Len</th><th>Flags</th><th>ICS Proto</th><th>FC</th>
          <th>Anomaly</th><th>Threat</th>
        </tr></thead>
        <tbody id="pkt-tbody"></tbody>
      </table>
      <div id="pkt-empty" class="empty-state">No packets captured yet. Start capture above.</div>
    </div>
  </div>
</div>

<!-- ICS / SCADA -->
<div class="page" id="page-ics">
  <!-- Risk Assessment -->
  <div class="panel">
    <div class="ph">
      <span class="pt">ICS Risk Assessment — IEC 62443 / NIST SP 800-82</span>
      <button class="btn btn-accent" id="btn-ics-risk">▶ Run Assessment</button>
    </div>
    <div class="pb">
      <div class="stats-row" style="grid-template-columns:repeat(5,1fr)">
        <div class="stat" id="ics-risk-overall-card">
          <div class="stat-lbl">Overall Risk</div>
          <div class="stat-val" id="ics-risk-overall">—</div>
          <div id="ics-risk-level" style="font-size:10px;margin-top:4px;font-family:'IBM Plex Mono',monospace"></div>
        </div>
        <div class="stat s-blue"><div class="stat-lbl">Availability</div><div class="stat-val c-blue" id="ics-risk-avail">—</div></div>
        <div class="stat s-orange"><div class="stat-lbl">Integrity</div><div class="stat-val c-orange" id="ics-risk-integ">—</div></div>
        <div class="stat s-purple"><div class="stat-lbl">Confidentiality</div><div class="stat-val c-purple" id="ics-risk-conf">—</div></div>
        <div class="stat s-green"><div class="stat-lbl">Authentication</div><div class="stat-val c-green" id="ics-risk-auth">—</div></div>
      </div>
      <div id="ics-risk-standards" style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);margin-top:8px;padding-top:8px;border-top:1px solid var(--border)"></div>
    </div>
  </div>
  <div class="grid-2">
    <!-- SIS Rules -->
    <div class="panel">
      <div class="ph"><span class="pt">SIS Trip Rules</span><span id="sis-rule-count" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)"></span></div>
      <div class="pb" style="max-height:340px;overflow-y:auto">
        <table>
          <thead><tr><th>ID</th><th>Name</th><th>Protocol</th><th>Zone</th><th>Severity</th></tr></thead>
          <tbody id="sis-rules-tbody"></tbody>
        </table>
        <div id="sis-rules-empty" class="empty-state">Loading SIS rules…</div>
      </div>
    </div>
    <!-- SIS Events -->
    <div class="panel">
      <div class="ph"><span class="pt">SIS Trip Events</span>
        <button class="btn btn-blue btn-sm" id="btn-load-sis-events">↺ Refresh</button>
      </div>
      <div class="pb" style="max-height:340px;overflow-y:auto">
        <table>
          <thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Src IP</th><th>Zone</th><th>Action</th></tr></thead>
          <tbody id="sis-events-tbody"></tbody>
        </table>
        <div id="sis-events-empty" class="empty-state">No SIS trip events recorded.</div>
      </div>
    </div>
  </div>
  <!-- ICS Protocol Events -->
  <div class="panel">
    <div class="ph">
      <span class="pt">ICS Protocol Events</span>
      <div style="display:flex;gap:8px;align-items:center">
        <select class="form-select" id="ics-proto-filter" style="width:160px;font-size:10px;padding:5px 10px">
          <option value="">All Protocols</option>
          <option>ICS_MODBUS</option><option>ICS_DNP3</option>
          <option>ICS_ENIP</option><option>ICS_IEC104</option>
        </select>
        <button class="btn" id="btn-load-ics-events">↺ Refresh</button>
      </div>
    </div>
    <div class="pb" style="overflow-x:auto;max-height:350px">
      <table>
        <thead><tr><th>Time</th><th>Type</th><th>Src IP</th><th>Dst IP</th><th>Port</th><th>Severity</th><th>Message</th><th>MITRE</th></tr></thead>
        <tbody id="ics-events-tbody"></tbody>
      </table>
      <div id="ics-events-empty" class="empty-state">No ICS protocol events yet. Start packet capture on the Network tab.</div>
    </div>
  </div>
  <!-- ICS Packet Decode -->
  <div class="panel">
    <div class="ph"><span class="pt">ICS Packet Decode</span>
      <button class="btn" id="btn-load-ics-packets">↺ Refresh</button>
    </div>
    <div class="pb" style="overflow-x:auto;max-height:320px">
      <table>
        <thead><tr><th>Time</th><th>Src</th><th>Dst</th><th>Protocol</th><th>FC</th><th>Function</th><th>Address</th><th>Value</th><th>Threat</th><th>Anomaly</th></tr></thead>
        <tbody id="ics-pkts-tbody"></tbody>
      </table>
      <div id="ics-pkts-empty" class="empty-state">No ICS packets decoded yet.</div>
    </div>
  </div>
</div>

<!-- HONEYPOT / CONPOT -->
<div class="page" id="page-honeypot">
  <div class="stats-row" style="grid-template-columns:repeat(4,1fr)">
    <div class="stat s-red"><div class="stat-lbl">Total Interactions</div><div class="stat-val c-red" id="hp-total">0</div></div>
    <div class="stat s-orange"><div class="stat-lbl">Unique Attackers</div><div class="stat-val c-orange" id="hp-ips">0</div></div>
    <div class="stat s-blue"><div class="stat-lbl">Top Protocol Hit</div><div class="stat-val c-blue" id="hp-top-proto" style="font-size:14px">—</div></div>
    <div class="stat s-purple"><div class="stat-lbl">Last Hit</div><div class="stat-val c-purple" id="hp-last" style="font-size:11px">—</div></div>
  </div>
  <div class="grid-2">
    <!-- Honeypot Config -->
    <div class="panel">
      <div class="ph"><span class="pt">Conpot / Honeypot Configuration</span></div>
      <div class="pb">
        <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);margin-bottom:12px">
          SCMS monitors the following ICS honeypot ports for interaction events.
          Deploy Conpot on this host to generate realistic decoy traffic.
        </div>
        <table class="ip-table">
          <thead><tr><th>Port</th><th>Protocol</th><th>Emulated Device</th><th>Hits</th></tr></thead>
          <tbody id="hp-port-table"></tbody>
        </table>
        <div style="margin-top:16px;padding:12px;background:var(--surface);border-radius:5px;border:1px solid var(--border)">
          <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--accent);margin-bottom:8px">▶ Deploy Conpot Honeypot</div>
          <div style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);line-height:1.8">
            pip3 install conpot<br>
            sudo conpot --template default<br>
            <span style="color:var(--text)"># Then set LOG_FILES to include conpot log path in .env</span>
          </div>
        </div>
      </div>
    </div>
    <!-- Top Attackers -->
    <div class="panel">
      <div class="ph"><span class="pt">Top Attacker IPs</span>
        <button class="btn btn-blue btn-sm" id="btn-load-hp">↺ Refresh</button>
      </div>
      <div class="pb">
        <table class="ip-table">
          <thead><tr><th>IP Address</th><th>Hits</th><th>Action</th></tr></thead>
          <tbody id="hp-attacker-table"></tbody>
        </table>
        <div id="hp-attacker-empty" class="empty-state">No honeypot interactions yet.</div>
      </div>
    </div>
  </div>
  <!-- Interaction Feed -->
  <div class="panel">
    <div class="ph">
      <span class="pt">Interaction Feed</span>
      <div style="display:flex;gap:8px;align-items:center">
        <select class="form-select" id="hp-proto-filter" style="width:160px;font-size:10px;padding:5px 10px">
          <option value="">All Protocols</option>
          <option value="502">Modbus (502)</option>
          <option value="20000">DNP3 (20000)</option>
          <option value="102">S7/IEC104 (102)</option>
          <option value="44818">EtherNet/IP (44818)</option>
          <option value="47808">BACnet (47808)</option>
        </select>
        <button class="btn" id="btn-load-hp-events">↺ Refresh</button>
      </div>
    </div>
    <div class="pb" style="overflow-x:auto;max-height:400px">
      <table>
        <thead><tr><th>Time</th><th>Src IP</th><th>Dst IP</th><th>Port</th><th>Protocol</th><th>Message</th><th>Severity</th><th>Action</th></tr></thead>
        <tbody id="hp-events-tbody"></tbody>
      </table>
      <div id="hp-events-empty" class="empty-state">No interactions logged yet.</div>
    </div>
  </div>
</div>

</div><!-- /main-area -->
</div><!-- /shell -->

<!-- DETAIL DRAWER -->
<div id="drawer">
  <div class="dh">
    <span class="dt">Event Detail</span>
    <button class="dc" id="btn-close-drawer">✕</button>
  </div>
  <div class="dg" id="drawer-fields"></div>
  <div class="dr" id="drawer-raw"></div>
  <div class="mitre-chips" id="drawer-mitre"></div>
</div>

<!-- TOAST -->
<div id="toast"></div>

<script nonce="{{ nonce }}">
// STATE
let allLogs = [], filteredLogs = [];
let curPage = 1, pageSize = 50;
let activeFilter = 'ALL', activeSev = null, searchTerm = '';
let sortCol = 'timestamp', sortDir = -1;
let activeTypeFilter = null;
let charts = {};
let blockedIPs = {};
let autoResponseCount = 0;
let logPaths = {{ log_paths|tojson }};
let allDbs = [];
let scaChecksCache = [];
let scaFilter = 'ALL';

// INIT
document.addEventListener('DOMContentLoaded', () => {
  updateClock();
  setInterval(updateClock, 1000);
  fetchStats();
  setInterval(fetchStats, 5000);
  renderLogPaths();
  loadDbs();
  loadInventory();
  loadHealth();
  buildMitreMatrix();
  renderFimPaths();

  // ── Nav tabs ──────────────────────────────────────────────────────────────
  ['overview','logs','analytics','assets','network','ics','honeypot','fim','sca','vuln','mitre','response','admin'].forEach(name => {
    const el = document.getElementById('nav-' + name);
    if (el) el.addEventListener('click', function(){ showPage(name, this); });
  });

  // ── Nav-right buttons ─────────────────────────────────────────────────────
  document.getElementById('btn-export-nav').addEventListener('click', exportCSV);
  document.getElementById('btn-clear-nav').addEventListener('click', confirmClear);

  // ── Log search ────────────────────────────────────────────────────────────
  document.getElementById('log-search').addEventListener('input', filterLogs);

  // ── Filter chips (data-filter) ────────────────────────────────────────────
  document.querySelectorAll('.chip[data-filter]').forEach(el =>
    el.addEventListener('click', function(){ setFilter(this, this.dataset.filter); }));

  // ── Severity chips (data-sev) ─────────────────────────────────────────────
  document.querySelectorAll('.chip[data-sev]').forEach(el =>
    el.addEventListener('click', function(){ setSev(this, parseInt(this.dataset.sev)); }));

  // ── Sortable table headers (data-sort) ────────────────────────────────────
  document.querySelectorAll('th[data-sort]').forEach(el =>
    el.addEventListener('click', function(){ sortTable(this.dataset.sort); }));

  // ── FIM buttons ───────────────────────────────────────────────────────────
  document.getElementById('btn-add-fim-path').addEventListener('click', addFimPath);
  document.getElementById('btn-run-fim').addEventListener('click', runFim);
  document.getElementById('btn-reset-fim-baseline').addEventListener('click', resetFimBaseline);

  // ── SCA ───────────────────────────────────────────────────────────────────
  document.getElementById('sca-filter').addEventListener('change', filterSca);
  document.getElementById('btn-run-sca').addEventListener('click', runSca);

  // ── Vulnerabilities ───────────────────────────────────────────────────────
  document.getElementById('btn-run-vuln').addEventListener('click', runVuln);

  // ── Active Response ───────────────────────────────────────────────────────
  document.getElementById('btn-block-ip').addEventListener('click', blockIP);
  document.getElementById('btn-unblock-ip').addEventListener('click', unblockIP);
  document.getElementById('btn-save-auto-rules').addEventListener('click', saveAutoRules);
  document.getElementById('btn-load-processes').addEventListener('click', loadProcesses);

  // ── Admin ─────────────────────────────────────────────────────────────────
  document.getElementById('db-search-input').addEventListener('input', filterDbs);
  document.getElementById('btn-load-dbs').addEventListener('click', loadDbs);
  document.getElementById('btn-create-db').addEventListener('click', createDb);
  document.getElementById('btn-add-log-path').addEventListener('click', addLogPath);
  document.getElementById('btn-run-compliance').addEventListener('click', runComplianceCheck);
  document.getElementById('btn-export-admin').addEventListener('click', exportCSV);
  document.getElementById('csv-import-file').addEventListener('change', function(){ importCSV(this); });

  // ── Assets ────────────────────────────────────────────────────────────────
  document.getElementById('btn-load-assets').addEventListener('click', loadAssets);
  document.getElementById('ast-search').addEventListener('input', filterAssets);
  document.getElementById('ast-filter-zone').addEventListener('change', filterAssets);
  document.getElementById('ast-filter-type').addEventListener('change', filterAssets);
  document.getElementById('btn-save-asset').addEventListener('click', saveAsset);
  document.getElementById('btn-close-ast-modal').addEventListener('click', () => {
    document.getElementById('ast-modal').style.display = 'none';
  });

  // ── Network ───────────────────────────────────────────────────────────────
  document.getElementById('btn-capture-start').addEventListener('click', startCapture);
  document.getElementById('btn-capture-stop').addEventListener('click', stopCapture);
  document.getElementById('btn-capture-refresh').addEventListener('click', () => { refreshCaptureStats(); loadPackets(); });
  document.getElementById('btn-host-scan').addEventListener('click', runHostScan);
  document.getElementById('btn-port-scan').addEventListener('click', runPortScan);
  document.getElementById('btn-load-packets').addEventListener('click', loadPackets);
  document.getElementById('pkt-filter').addEventListener('input', filterPackets);
  document.getElementById('pkt-filter-proto').addEventListener('change', filterPackets);

  // ── ICS ───────────────────────────────────────────────────────────────────
  document.getElementById('btn-ics-risk').addEventListener('click', loadIcsRisk);
  document.getElementById('btn-load-sis-events').addEventListener('click', loadSisEvents);
  document.getElementById('btn-load-ics-events').addEventListener('click', loadIcsEvents);
  document.getElementById('btn-load-ics-packets').addEventListener('click', loadIcsPackets);
  document.getElementById('ics-proto-filter').addEventListener('change', filterIcsEvents);

  // ── Honeypot ──────────────────────────────────────────────────────────────
  document.getElementById('btn-load-hp').addEventListener('click', () => { loadHoneypotStats(); loadHoneypotEvents(); });
  document.getElementById('btn-load-hp-events').addEventListener('click', loadHoneypotEvents);
  document.getElementById('hp-proto-filter').addEventListener('change', filterHpEvents);

  // ── Drawer close ──────────────────────────────────────────────────────────
  document.getElementById('btn-close-drawer').addEventListener('click', closeDrawer);

  // ── Event delegation ──────────────────────────────────────────────────────
  document.addEventListener('click', function(e) {
    const row = e.target.closest('tr[data-log]');
    if (row) { try { openDrawer(JSON.parse(row.dataset.log)); } catch(_){} return; }

    const pgBtn = e.target.closest('button[data-page]');
    if (pgBtn && !pgBtn.disabled) { changePage(parseInt(pgBtn.dataset.page)); return; }

    const qbBtn = e.target.closest('[data-quick-block]');
    if (qbBtn) { quickBlock(qbBtn.dataset.quickBlock); return; }

    const fimBtn = e.target.closest('[data-remove-fim-idx]');
    if (fimBtn) { removeFimPath(parseInt(fimBtn.dataset.removeFimIdx)); return; }

    const logBtn = e.target.closest('[data-remove-log-idx]');
    if (logBtn) { removeLogPath(parseInt(logBtn.dataset.removeLogIdx)); return; }

    const ubEl = e.target.closest('[data-unblock-ip]');
    if (ubEl) { unblockIPDirect(ubEl.dataset.unblockIp); return; }

    const killBtn = e.target.closest('[data-kill-pid]');
    if (killBtn) { killProcess(parseInt(killBtn.dataset.killPid), killBtn.dataset.killName); return; }

    const mitreCard = e.target.closest('[data-mitre-url]');
    if (mitreCard) { window.open(mitreCard.dataset.mitreUrl, '_blank'); return; }

    const etypeRow = e.target.closest('[data-etype]');
    if (etypeRow) { typeFilterClick(etypeRow.dataset.etype); return; }

    const dbItem = e.target.closest('[data-select-db]');
    if (dbItem) { selectDb(dbItem.dataset.selectDb); return; }

    // Asset edit buttons (data-edit-asset)
    const astBtn = e.target.closest('[data-edit-asset]');
    if (astBtn) { try { openAssetModal(JSON.parse(astBtn.dataset.editAsset)); } catch(_){} return; }
  });
});

function updateClock() {
  const n = new Date();
  document.getElementById('nav-time').textContent =
    n.toTimeString().slice(0,8) + ' UTC' + (n.getTimezoneOffset() > 0 ? '-' : '+') +
    String(Math.abs(n.getTimezoneOffset()/60)).padStart(2,'0');
}

// PAGE NAV
function showPage(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  el.classList.add('active');
  if (name === 'analytics') buildAnalytics();
  if (name === 'mitre') buildMitreMatrix();
  if (name === 'admin') { loadDbs(); loadInventory(); loadHealth(); }
  if (name === 'assets') loadAssets();
  if (name === 'network') { loadInterfaces(); loadPackets(); }
  if (name === 'ics') { loadSisRules(); loadSisEvents(); loadIcsEvents(); loadIcsPackets(); loadIcsRisk(); }
  if (name === 'honeypot') { loadHoneypotStats(); loadHoneypotEvents(); }
}

// FETCH STATS
async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    if (!r.ok) return;
    const d = await r.json();
    setNum('s-failed', d.failed_logins);
    setNum('s-brute',  d.brute_total);
    setNum('s-sudo',   d.sudo_total);
    setNum('s-ips',    d.unique_ips);
    setNum('s-total',  d.total_logs);
    setNum('s-susp',   d.suspicious_count);
    setNum('ov-failed', d.failed_logins);
    setNum('ov-auth',   d.auth_count);
    setNum('ov-susp',   d.suspicious_count);
    setNum('ov-hosts',  d.host_count);
    renderSidebarAlerts(d.top_ips, d.sudo_users);
    renderEtypes(d.event_types);
    renderHosts(d.logs);
    renderSidebarBlocked();
    buildTimelineChart(d.logs);
    buildEtypeChart(d.event_types);
    buildIPChart(d.top_ips);
    buildSevChart(d.logs);
    allLogs = d.logs || [];
    if (document.getElementById('page-logs').classList.contains('active') ||
        document.getElementById('page-overview').classList.contains('active')) {
      applyFilters();
    }
    renderOverviewTable(allLogs);
    checkAutoResponse(d);
  } catch(e) { console.error(e); }
}

function setNum(id, v) {
  const el = document.getElementById(id);
  if (el) el.textContent = (v || 0).toLocaleString();
}

// SIDEBAR
function renderSidebarAlerts(topIps, sudoUsers) {
  const c = document.getElementById('sb-alerts');
  if ((!topIps || !topIps.length) && (!sudoUsers || !sudoUsers.length)) {
    c.innerHTML = '<div class="empty-state">No alerts</div>'; return;
  }
  let html = '';
  (topIps||[]).slice(0,4).forEach(([ip,count]) => {
    html += `<div class="al-item"><div class="al-ip">${ip}</div><div class="al-meta">${count} failed auth events</div></div>`;
  });
  (sudoUsers||[]).slice(0,3).forEach(([u,count]) => {
    html += `<div class="al-item warn"><div class="al-ip">${u}</div><div class="al-meta">${count} sudo events</div></div>`;
  });
  c.innerHTML = html;
}

function renderEtypes(etypes) {
  const c = document.getElementById('sb-etypes');
  if (!etypes || !etypes.length) { c.innerHTML = ''; return; }
  c.innerHTML = etypes.map(e =>
    `<div class="etype-row ${activeTypeFilter===e.name?'active':''}" data-etype="${e.name}">
      <span class="etype-name"><span class="etype-dot" style="background:${e.color}"></span>${e.name}</span>
      <span class="etype-count">${e.count}</span>
    </div>`
  ).join('');
}

function renderHosts(logs) {
  const hosts = {};
  (logs||[]).forEach(l => { if(l.hostname && l.hostname!=='—') hosts[l.hostname] = (hosts[l.hostname]||0)+1; });
  const c = document.getElementById('sb-hosts');
  c.innerHTML = Object.entries(hosts).slice(0,6).map(([h,n]) =>
    `<div class="sb-host"><span>${h}</span><span style="color:var(--muted)">${n}</span></div>`
  ).join('') || '<div style="color:var(--muted);font-size:10px">No host data</div>';
}

function renderSidebarBlocked() {
  const c = document.getElementById('sb-blocked');
  const ips = Object.keys(blockedIPs);
  if (!ips.length) { c.innerHTML = '<span style="color:var(--muted)">None</span>'; return; }
  c.innerHTML = ips.map(ip =>
    `<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--border)">
      <span style="color:var(--red)">${ip}</span>
      <span style="cursor:pointer;color:var(--muted)" data-unblock-ip="${ip}">✕</span>
    </div>`
  ).join('');
}

function typeFilterClick(name) {
  activeTypeFilter = activeTypeFilter === name ? null : name;
  activeFilter = activeTypeFilter || 'ALL';
  showPage('logs', document.querySelectorAll('.nav-tab')[1]);
  applyFilters();
}

// OVERVIEW TABLE
function renderOverviewTable(logs) {
  const high = logs.filter(l => l.threat_level >= 2).slice(0,20);
  const tb = document.getElementById('ov-table');
  document.getElementById('ov-log-count').textContent = `${high.length} high-severity events`;
  if (!high.length) { tb.innerHTML = '<tr><td colspan="7" class="empty-state">No high-severity events</td></tr>'; return; }
  tb.innerHTML = high.map(l => rowHtml(l)).join('');
}

// LOG TABLE
function applyFilters() {
  let list = [...allLogs];
  if (activeFilter !== 'ALL') list = list.filter(l => l.eventtype === activeFilter);
  if (activeSev !== null) list = list.filter(l => l.threat_level === activeSev);
  if (searchTerm) {
    const q = searchTerm.toLowerCase();
    list = list.filter(l =>
      (l.message||'').toLowerCase().includes(q) ||
      (l.sourceip||'').toLowerCase().includes(q) ||
      (l.username||'').toLowerCase().includes(q) ||
      (l.hostname||'').toLowerCase().includes(q)
    );
  }
  list.sort((a,b) => {
    let av = a[sortCol]||'', bv = b[sortCol]||'';
    if (sortCol==='threat_level') { av=a.threat_level; bv=b.threat_level; }
    if (av < bv) return sortDir; if (av > bv) return -sortDir; return 0;
  });
  filteredLogs = list;
  curPage = 1;
  renderLogTable();
  document.getElementById('log-count').textContent = `${list.length} events`;
}

function renderLogTable() {
  const tb = document.getElementById('log-table');
  const start = (curPage-1)*pageSize, end = start+pageSize;
  const page = filteredLogs.slice(start, end);
  if (!page.length) tb.innerHTML = '<tr><td colspan="7" class="empty-state">No events match filters</td></tr>';
  else tb.innerHTML = page.map(l => rowHtml(l)).join('');
  renderPagination();
}

function rowHtml(l) {
  const rc = l.threat_level>=3 ? 'r-red' : l.threat_level>=2 ? 'r-orange' : '';
  return `<tr class="lr ${rc}" data-log='${JSON.stringify(l).replace(/'/g,"&#39;")}'>
    <td class="col-time">${l.timestamp}</td>
    <td class="col-type"><span class="badge badge-${l.eventtype}">${l.eventtype}</span></td>
    <td class="col-host" title="${l.hostname}">${l.hostname}</td>
    <td class="col-user">${l.username}</td>
    <td class="col-ip">${l.sourceip}</td>
    <td class="col-msg" title="${escHtml(l.message)}">${escHtml(l.message)}</td>
    <td class="col-sev"><span class="sev-badge sev-${l.threat_level}">${l.threat_label}</span></td>
  </tr>`;
}

function escHtml(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function renderPagination() {
  const total = filteredLogs.length, pages = Math.ceil(total/pageSize)||1;
  const start = (curPage-1)*pageSize+1, end = Math.min(curPage*pageSize, total);
  document.getElementById('pg-info').textContent = `Showing ${total?start:0}–${end} of ${total}`;
  const c = document.getElementById('pg-btns');
  let html = `<button class="pg-btn" data-page="${curPage-1}" ${curPage<=1?'disabled':''}>‹ Prev</button>`;
  pageRange(curPage, pages).forEach(p => {
    if (p==='…') html += `<button class="pg-btn" disabled>…</button>`;
    else html += `<button class="pg-btn ${p===curPage?'cur':''}" data-page="${p}">${p}</button>`;
  });
  html += `<button class="pg-btn" data-page="${curPage+1}" ${curPage>=pages?'disabled':''}>Next ›</button>`;
  c.innerHTML = html;
}

function pageRange(cur, total) {
  if (total <= 7) return Array.from({length:total},(_,i)=>i+1);
  if (cur <= 4) return [1,2,3,4,5,'…',total];
  if (cur >= total-3) return [1,'…',total-4,total-3,total-2,total-1,total];
  return [1,'…',cur-1,cur,cur+1,'…',total];
}

function changePage(p) { const pages=Math.ceil(filteredLogs.length/pageSize)||1; if(p<1||p>pages)return; curPage=p; renderLogTable(); }
function filterLogs() { searchTerm=document.getElementById('log-search').value; applyFilters(); }
function setFilter(el, f) {
  document.querySelectorAll('.filter-row .chip[data-filter]').forEach(c=>c.classList.remove('active'));
  el.classList.add('active'); activeFilter=f; applyFilters();
}
function setSev(el, s) {
  if (activeSev===s) { el.classList.remove('active'); activeSev=null; }
  else { document.querySelectorAll('.filter-row .chip[data-sev]').forEach(c=>c.classList.remove('active')); el.classList.add('active'); activeSev=s; }
  applyFilters();
}
function sortTable(col) { if(sortCol===col) sortDir*=-1; else { sortCol=col; sortDir=-1; } applyFilters(); }

// DRAWER
function openDrawer(l) {
  const fields = [
    ['Log ID', l.logid], ['Timestamp', l.timestamp], ['Event Type', l.eventtype],
    ['Host', l.hostname], ['Username', l.username], ['Source IP', l.sourceip],
    ['Severity', l.threat_label], ['Status', l.threat_level>=1?'Anomaly':'Normal']
  ];
  document.getElementById('drawer-fields').innerHTML = fields.map(([k,v]) =>
    `<div><div class="dk">${k}</div><div class="dv">${escHtml(String(v))}</div></div>`
  ).join('');
  document.getElementById('drawer-raw').textContent = l.rawline || l.message || '—';
  const mitre = {{ mitre_map|tojson }};
  const techniques = mitre[l.eventtype] || [];
  document.getElementById('drawer-mitre').innerHTML = techniques.length
    ? techniques.map(t =>
        `<a class="mitre-chip" href="https://attack.mitre.org/techniques/${t.id.replace('.','/')}/" target="_blank" title="${t.tactic}">${t.id} — ${t.name}</a>`
      ).join('')
    : '<span style="font-family:\'IBM Plex Mono\',monospace;font-size:10px;color:var(--muted)">No MITRE mapping</span>';
  document.getElementById('drawer').classList.add('open');
}
function closeDrawer() { document.getElementById('drawer').classList.remove('open'); }

// CHARTS
const CC = { grid:'rgba(26,45,61,.6)', text:'#5a7080', accent:'#00d4aa', red:'#f85149', orange:'#e3a03a', blue:'#0ea5e9', purple:'#bc8cff', green:'#3fb950', cyan:'#79c0ff', yellow:'#d29922' };

function mkChart(id, cfg) {
  if (charts[id]) charts[id].destroy();
  const ctx = document.getElementById(id);
  if (!ctx) return;
  charts[id] = new Chart(ctx, cfg);
}

function buildTimelineChart(logs) {
  const now = new Date(), buckets = {};
  for (let i=59; i>=0; i--) {
    const k = new Date(now - i*60000);
    const label = k.toTimeString().slice(0,5);
    buckets[label] = {label, total:0, failed:0};
  }
  (logs||[]).forEach(l => {
    if (!l.timestamp) return;
    const t = l.timestamp.slice(11,16);
    if (buckets[t]) { buckets[t].total++; if(l.threat_level>=2) buckets[t].failed++; }
  });
  const vals = Object.values(buckets);
  mkChart('chart-timeline', { type:'line', data:{
    labels: vals.map(v=>v.label),
    datasets: [
      { label:'All Events', data:vals.map(v=>v.total), borderColor:CC.accent, backgroundColor:'rgba(0,212,170,.08)', tension:.3, pointRadius:0, fill:true },
      { label:'Threats', data:vals.map(v=>v.failed), borderColor:CC.red, backgroundColor:'rgba(248,81,73,.08)', tension:.3, pointRadius:0, fill:true }
    ]
  }, options: chartOpts() });
}

function buildEtypeChart(etypes) {
  if (!etypes||!etypes.length) return;
  mkChart('chart-etypes', { type:'doughnut', data:{
    labels: etypes.map(e=>e.name),
    datasets:[{ data:etypes.map(e=>e.count), backgroundColor:etypes.map(e=>e.color), borderWidth:0, hoverOffset:4 }]
  }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'right', labels:{ color:CC.text, font:{size:10}, boxWidth:10 } } } } });
}

function buildIPChart(topIps) {
  if (!topIps||!topIps.length) return;
  mkChart('chart-ips', { type:'bar', data:{
    labels: topIps.slice(0,8).map(([ip])=>ip),
    datasets:[{ label:'Failed Logins', data:topIps.slice(0,8).map(([,c])=>c), backgroundColor:'rgba(248,81,73,.7)', borderRadius:3 }]
  }, options:{ ...chartOpts(), indexAxis:'y' } });
}

function buildSevChart(logs) {
  const c = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  (logs||[]).forEach(l => { const m={3:'CRITICAL',2:'HIGH',1:'MEDIUM',0:'LOW'}; c[m[l.threat_level]||'LOW']++; });
  mkChart('chart-sev', { type:'bar', data:{
    labels:['CRITICAL','HIGH','MEDIUM','LOW'],
    datasets:[{ data:[c.CRITICAL,c.HIGH,c.MEDIUM,c.LOW], backgroundColor:[CC.red,CC.orange,'rgba(210,153,34,.7)',CC.green], borderRadius:3 }]
  }, options:chartOpts() });
}

function chartOpts() {
  return { responsive:true, maintainAspectRatio:false, plugins:{legend:{display:false}},
    scales:{ x:{ grid:{color:CC.grid}, ticks:{color:CC.text,font:{size:9}} }, y:{ grid:{color:CC.grid}, ticks:{color:CC.text,font:{size:9}} } } };
}

// ANALYTICS
async function buildAnalytics() {
  try {
    const r = await fetch('/api/stats'); const d = await r.json();
    setNum('an-total',     d.total_logs);
    setNum('an-failed',    d.failed_logins);
    setNum('an-auth',      d.auth_count);
    setNum('an-susp',      d.suspicious_count);
    setNum('an-sudo-count', d.sudo_total);

    const ipResp = await fetch('/api/top-ips');
    const ips = await ipResp.json();
    document.getElementById('an-ip-table').innerHTML = (ips||[]).map(([ip,count]) =>
      `<tr><td style="color:var(--accent)">${ip}</td><td>${count}</td>
       <td><span class="tag ${count>20?'tag-crit':count>10?'tag-high':'tag-med'}">${count>20?'CRITICAL':count>10?'HIGH':'MEDIUM'}</span></td>
       <td><button class="btn btn-red btn-sm" data-quick-block="${ip}">Block</button></td></tr>`
    ).join('') || '<tr><td colspan="4" class="empty-state">No attacker IPs</td></tr>';

    const sudoResp = await fetch('/api/sudo-users');
    const sudos = await sudoResp.json();
    document.getElementById('an-sudo-table').innerHTML = (sudos||[]).map(([u,c]) =>
      `<tr><td style="color:var(--blue)">${u}</td><td>${c}</td>
       <td><span class="tag ${c>10?'tag-high':'tag-med'}">${c>10?'HIGH':'MEDIUM'}</span></td></tr>`
    ).join('') || '<tr><td colspan="3" class="empty-state">No sudo data</td></tr>';

    // Timeline (reuse data from stats)
    buildAnTimelineChart(d.logs);

    const success = (d.logs||[]).filter(l=>l.threat_level===0).length;
    const failed  = (d.logs||[]).filter(l=>l.threat_level> 0).length;
    mkChart('an-chart-sf', { type:'pie', data:{
      labels:['Normal','Anomaly'],
      datasets:[{ data:[success,failed], backgroundColor:[CC.green,'rgba(248,81,73,.7)'], borderWidth:0 }]
    }, options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'right', labels:{color:CC.text,font:{size:10},boxWidth:10} } } } });

    const hm = new Array(24).fill(0);
    (d.logs||[]).forEach(l => { if(l.timestamp) { const h=parseInt(l.timestamp.slice(11,13)); if(!isNaN(h)) hm[h]++; } });
    const max = Math.max(...hm,1);
    document.getElementById('an-heatmap').innerHTML = hm.map((v,h) =>
      `<div title="${h}:00 — ${v} events" style="flex:1;height:${Math.max(4,v/max*80)}px;background:${v>0?'rgba(0,212,170,'+(0.2+0.8*v/max)+')':'var(--border)'};border-radius:2px 2px 0 0;cursor:default"></div>`
    ).join('');
  } catch(e) { console.error(e); }
}

function buildAnTimelineChart(logs) {
  const now = new Date(), buckets = {};
  for (let i=59; i>=0; i--) {
    const k = new Date(now - i*60000);
    const label = k.toTimeString().slice(0,5);
    buckets[label] = {label, failed:0};
  }
  (logs||[]).forEach(l => {
    if (!l.timestamp) return;
    const t = l.timestamp.slice(11,16);
    if (buckets[t] && l.threat_level > 0) buckets[t].failed++;
  });
  const vals = Object.values(buckets);
  mkChart('an-chart-tl', { type:'line', data:{
    labels: vals.map(v=>v.label),
    datasets:[{ label:'Failed Logins', data:vals.map(v=>v.failed), borderColor:CC.red, backgroundColor:'rgba(248,81,73,.1)', tension:.3, pointRadius:0, fill:true }]
  }, options:chartOpts() });
}

// FIM
let fimPaths = ['/etc/passwd','/etc/shadow','/etc/hosts','/etc/crontab','/etc/sudoers','/root/.bashrc'];
let fimBaseline = {};

function renderFimPaths() {
  document.getElementById('fim-paths').innerHTML = fimPaths.map((p,i) =>
    `<div class="path-item"><div style="display:flex;align-items:center;gap:8px"><div class="path-status"></div><span>${p}</span></div>
     <button class="btn btn-red btn-sm" data-remove-fim-idx="${i}">Remove</button></div>`
  ).join('') || '<div style="color:var(--muted);font-size:10px">No paths configured</div>';
}

function addFimPath() {
  const v = document.getElementById('fim-path-input').value.trim();
  if (!v) return;
  if (!fimPaths.includes(v)) { fimPaths.push(v); renderFimPaths(); toast('Path added','ok'); }
  document.getElementById('fim-path-input').value = '';
}

function removeFimPath(i) { fimPaths.splice(i,1); renderFimPaths(); }
function resetFimBaseline() { fimBaseline = {}; toast('Baseline cleared — next scan will establish new baseline','info'); }

async function runFim() {
  toast('Running FIM scan…','info');
  try {
    const r = await fetch('/api/fim', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({paths:fimPaths}) });
    const results = await r.json();
    let ok=0, mod=0, miss=0;
    const tb = document.getElementById('fim-results');
    tb.innerHTML = results.map(f => {
      const changed = fimBaseline[f.path] && fimBaseline[f.path] !== f.hash;
      const status = f.status!=='ok' ? 'ERROR' : changed ? 'MODIFIED' : fimBaseline[f.path] ? 'UNCHANGED' : 'NEW';
      if(status==='UNCHANGED') ok++; else if(status==='MODIFIED') mod++; else if(status==='ERROR') miss++;
      const cls = status==='MODIFIED'?'tag-high':status==='ERROR'?'tag-crit':status==='NEW'?'tag-info':'tag-low';
      if (!fimBaseline[f.path] && f.hash) fimBaseline[f.path] = f.hash;
      return `<tr>
        <td style="font-family:'IBM Plex Mono',monospace;color:var(--blue)">${f.path}</td>
        <td style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted)">${f.hash?f.hash.slice(0,20)+'…':'—'}</td>
        <td>${f.size?f.size+' B':'—'}</td>
        <td>${f.mtime?new Date(f.mtime*1000).toISOString().slice(0,19):'—'}</td>
        <td><span class="tag ${cls}">${status}</span></td>
      </tr>`;
    }).join('');
    setNum('fim-ok',ok); setNum('fim-mod',mod); setNum('fim-miss',miss);
    document.getElementById('fim-empty').style.display='none';
    toast(`FIM scan complete: ${results.length} files checked`,'ok');
  } catch(e) { toast('FIM scan failed: '+e.message,'err'); }
}

// SCA
async function runSca() {
  const prog = document.getElementById('sca-progress');
  const pb   = document.getElementById('sca-pb');
  prog.style.display = 'block';
  let pct = 0;
  const interval = setInterval(() => { pct = Math.min(pct+8,90); pb.style.width=pct+'%'; }, 300);
  try {
    const r = await fetch('/api/sca');
    scaChecksCache = await r.json();
    clearInterval(interval); pb.style.width='100%';
    setTimeout(() => prog.style.display='none', 600);
    renderScaResults(scaChecksCache);
    toast(`SCA complete: ${scaChecksCache.filter(c=>c.status==='PASS').length} pass, ${scaChecksCache.filter(c=>c.status==='FAIL').length} fail`,
          scaChecksCache.filter(c=>c.status==='FAIL').length > scaChecksCache.filter(c=>c.status==='PASS').length ? 'err' : 'ok');
  } catch(e) { clearInterval(interval); prog.style.display='none'; toast('SCA failed: '+e.message,'err'); }
}

function filterSca() {
  scaFilter = document.getElementById('sca-filter').value;
  if (scaChecksCache.length) renderScaResults(scaChecksCache);
}

function renderScaResults(checks) {
  const pass = checks.filter(c=>c.status==='PASS').length;
  const fail = checks.filter(c=>c.status==='FAIL').length;
  const crit = checks.filter(c=>c.status==='FAIL'&&c.severity==='CRITICAL').length;
  const score = Math.round(pass/(checks.length||1)*100);
  document.getElementById('sca-pass').textContent  = pass;
  document.getElementById('sca-fail').textContent  = fail;
  document.getElementById('sca-score').textContent = score + '%';
  document.getElementById('sca-crit').textContent  = crit;
  document.getElementById('sca-empty').style.display = 'none';

  let visible = checks;
  if (scaFilter === 'FAIL') visible = checks.filter(c=>c.status==='FAIL');
  else if (scaFilter === 'PASS') visible = checks.filter(c=>c.status==='PASS');
  else if (scaFilter === 'CRITICAL') visible = checks.filter(c=>c.severity==='CRITICAL');

  document.getElementById('sca-results').innerHTML = visible.map(c => `<tr>
    <td style="font-family:'IBM Plex Mono',monospace;color:var(--muted);white-space:nowrap">${c.id}</td>
    <td>${c.title}${c.detail?'<div style="font-size:9px;color:var(--muted);margin-top:2px">'+escHtml(c.detail)+'</div>':''}</td>
    <td style="font-size:9px;color:var(--muted);font-family:'IBM Plex Mono',monospace;white-space:nowrap">${(c.tags||'').replace(/,/g,'<br>')}</td>
    <td><span class="tag ${c.severity==='CRITICAL'?'tag-crit':c.severity==='HIGH'?'tag-high':c.severity==='MEDIUM'?'tag-med':'tag-low'}">${c.severity}</span></td>
    <td><span class="tag ${c.status==='PASS'?'tag-low':'tag-crit'}">${c.status}</span></td>
  </tr>`).join('');
}

// VULN
async function runVuln() {
  toast('Scanning packages…','info');
  try {
    const r = await fetch('/api/vuln');
    const vulns = await r.json();
    const crit = vulns.filter(v=>v.severity==='CRITICAL').length;
    const high = vulns.filter(v=>v.severity==='HIGH').length;
    const med  = vulns.filter(v=>v.severity==='MEDIUM').length;
    document.getElementById('vn-crit').textContent  = crit;
    document.getElementById('vn-high').textContent  = high;
    document.getElementById('vn-med').textContent   = med;
    document.getElementById('vn-total').textContent = vulns.length;
    const liveCount = vulns.filter(v=>v.source==='NVD-live').length;
    document.getElementById('vuln-source-badge').textContent =
      liveCount > 0 ? `${liveCount} from NVD live · ${vulns.length-liveCount} offline` : 'offline baseline';
    document.getElementById('vuln-empty').style.display = 'none';
    document.getElementById('vuln-results').innerHTML = vulns.length
      ? vulns.map(v => `<tr>
          <td style="font-family:'IBM Plex Mono',monospace;color:var(--blue)">${v.package}</td>
          <td style="font-family:'IBM Plex Mono',monospace;color:var(--orange)">${v.cve}</td>
          <td><span class="tag ${v.severity==='CRITICAL'?'tag-crit':v.severity==='HIGH'?'tag-high':v.severity==='MEDIUM'?'tag-med':'tag-low'}">${v.severity}</span></td>
          <td style="color:var(--muted);font-size:11px">${escHtml(v.description||'')}</td>
          <td><span class="tag ${v.source==='NVD-live'?'tag-info':'tag-low'}" style="font-size:8px">${v.source||'offline'}</span></td>
          <td><a href="https://nvd.nist.gov/vuln/detail/${v.cve}" target="_blank" style="color:var(--blue);font-family:'IBM Plex Mono',monospace;font-size:10px">NVD ↗</a></td>
        </tr>`)
        .join('')
      : '<tr><td colspan="6" class="empty-state" style="color:var(--green)">No known vulnerabilities detected</td></tr>';
    toast(`Vuln scan: ${vulns.length} findings (${crit} critical)`, crit>0?'err':'ok');
  } catch(e) { toast('Vuln scan failed: '+e.message,'err'); }
}

// MITRE ATT&CK
function buildMitreMatrix() {
  const mitreMap = {{ mitre_map|tojson }};
  const techniques = {}, tactics = {};
  allLogs.forEach(l => {
    const maps = mitreMap[l.eventtype] || [];
    maps.forEach(t => {
      techniques[t.id] = techniques[t.id] || { ...t, count:0 };
      techniques[t.id].count++;
      tactics[t.tactic] = (tactics[t.tactic]||0) + 1;
    });
  });

  document.getElementById('mitre-tactics').innerHTML = Object.entries(tactics)
    .sort((a,b)=>b[1]-a[1])
    .map(([t,c]) => `<span class="mitre-chip" style="font-size:11px;padding:5px 12px">${t} <strong>${c}</strong></span>`)
    .join('') || '<span style="color:var(--muted);font-size:11px">Waiting for log data…</span>';

  document.getElementById('mitre-cards').innerHTML = Object.values(techniques)
    .sort((a,b)=>b.count-a.count)
    .map(t => `<div class="mitre-card" data-mitre-url="https://attack.mitre.org/techniques/${t.id.replace('.','/').replace('.','/') }/">
      <div class="mitre-id">${t.id}</div>
      <div class="mitre-name">${t.name}</div>
      <div class="mitre-tactic">${t.tactic}</div>
      <div class="mitre-count">${t.count}</div>
    </div>`)
    .join('') || '<div class="empty-state" style="grid-column:1/-1">No MITRE techniques detected yet</div>';

  document.getElementById('mitre-tactic-list').innerHTML = Object.entries(tactics)
    .sort((a,b)=>b[1]-a[1])
    .map(([t,c]) => `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:12px">${t}</span>
      <span style="font-family:'IBM Plex Mono',monospace;font-size:20px;font-weight:600;color:var(--accent)">${c}</span>
    </div>`)
    .join('') || '<div style="color:var(--muted);font-size:11px">No data</div>';

  const tacticNames = Object.keys(tactics);
  const tacticCounts = Object.values(tactics);
  if (tacticNames.length) {
    mkChart('mitre-chart', { type:'radar', data:{
      labels: tacticNames,
      datasets:[{ label:'Activity', data:tacticCounts,
        backgroundColor:'rgba(0,212,170,.12)', borderColor:'rgba(0,212,170,.7)',
        pointBackgroundColor:'var(--accent)', pointRadius:4 }]
    }, options:{ responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{display:false} },
      scales:{ r:{ grid:{color:CC.grid}, ticks:{display:false}, pointLabels:{color:CC.text,font:{size:9}} } } } });
  }
}

// ACTIVE RESPONSE
let arLog = [];

function arLogEntry(msg, type='info') {
  const t = new Date().toTimeString().slice(0,8);
  const colors = {info:'var(--blue)', ok:'var(--green)', err:'var(--red)'};
  arLog.unshift(`<div style="color:${colors[type]||CC.text}">[ ${t} ] ${escHtml(msg)}</div>`);
  if (arLog.length > 100) arLog.pop();
  document.getElementById('ar-log').innerHTML = arLog.join('');
}

async function blockIP() {
  const ip = document.getElementById('ar-ip-input').value.trim();
  const reason = document.getElementById('ar-reason').value;
  if (!ip) { toast('Enter an IP address','err'); return; }
  try {
    const r = await fetch('/api/block-ip', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip,reason}) });
    const d = await r.json();
    if (d.success) {
      blockedIPs[ip] = { reason, time:new Date().toISOString() };
      renderBlockedTable(); renderSidebarBlocked();
      setNum('ar-blocked-count', Object.keys(blockedIPs).length);
      arLogEntry(`Blocked IP ${ip} — ${reason}`, 'ok');
      toast(`Blocked ${ip}`,'ok');
    } else toast(d.message,'err');
  } catch(e) { toast('Block failed: '+e.message,'err'); }
}

async function unblockIP() {
  const ip = document.getElementById('ar-ip-input').value.trim();
  if (!ip) { toast('Enter an IP to unblock','err'); return; }
  await unblockIPDirect(ip);
}

async function unblockIPDirect(ip) {
  try {
    await fetch('/api/unblock-ip', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip}) });
    delete blockedIPs[ip];
    renderBlockedTable(); renderSidebarBlocked();
    setNum('ar-blocked-count', Object.keys(blockedIPs).length);
    arLogEntry(`Unblocked IP ${ip}`,'ok');
    toast(`Unblocked ${ip}`,'ok');
  } catch(e) { toast('Unblock failed: '+e.message,'err'); }
}

function quickBlock(ip) { document.getElementById('ar-ip-input').value = ip; blockIP(); }

function renderBlockedTable() {
  const c = document.getElementById('ar-blocked-list');
  const empty = document.getElementById('ar-blocked-empty');
  const entries = Object.entries(blockedIPs);
  if (!entries.length) { c.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';
  c.innerHTML = entries.map(([ip,data]) =>
    `<tr><td style="color:var(--red);font-family:'IBM Plex Mono',monospace">${ip}</td>
     <td>${data.reason||'Manual'}</td>
     <td style="color:var(--muted)">${(data.time||'').slice(0,19)}</td>
     <td><button class="btn btn-sm" data-unblock-ip="${ip}">Unblock</button></td></tr>`
  ).join('');
}

function checkAutoResponse(d) {
  if (document.getElementById('ar-auto-brute').checked) {
    (d.top_ips||[]).forEach(([ip,count]) => {
      if (count > 10 && !blockedIPs[ip]) {
        blockedIPs[ip] = { reason:'Auto: Brute Force ('+count+' attempts)', time:new Date().toISOString() };
        autoResponseCount++;
        setNum('ar-auto', autoResponseCount);
        arLogEntry(`AUTO-BLOCK: ${ip} — ${count} failed logins`, 'err');
        toast(`Auto-blocked ${ip} (brute force)`,'err');
        renderBlockedTable(); renderSidebarBlocked();
        setNum('ar-blocked-count', Object.keys(blockedIPs).length);
      }
    });
  }
  setNum('ar-brute', d.brute_total);
}

function saveAutoRules() { toast('Auto-response rules saved','ok'); }

// PROCESS MANAGER
async function loadProcesses() {
  try {
    const r = await fetch('/api/processes');
    const procs = await r.json();
    if (!procs.length) { document.getElementById('proc-empty').style.display='block'; return; }
    document.getElementById('proc-empty').style.display='none';
    document.getElementById('proc-table-body').innerHTML = procs.map(p =>
      `<tr>
        <td style="font-family:'IBM Plex Mono',monospace;color:var(--muted)">${p.pid}</td>
        <td style="color:var(--blue)">${p.user}</td>
        <td>${p.cpu}</td>
        <td>${p.mem}</td>
        <td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px" title="${escHtml(p.cmd)}">${escHtml(p.cmd)}</td>
        <td><button class="btn btn-red btn-sm" data-kill-pid="${p.pid}" data-kill-name="${escHtml(p.cmd).slice(0,20)}">Kill</button></td>
      </tr>`
    ).join('');
    arLogEntry(`Process list refreshed: ${procs.length} processes`,'info');
  } catch(e) { toast('Process load failed: '+e.message,'err'); }
}

async function killProcess(pid, name) {
  if (!confirm(`Send SIGTERM to PID ${pid} (${name})?`)) return;
  try {
    const r = await fetch('/api/kill-process', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({pid}) });
    const d = await r.json();
    if (d.success) { arLogEntry(`Killed PID ${pid} (${name})`,'ok'); toast(`SIGTERM sent to PID ${pid}`,'ok'); loadProcesses(); }
    else toast(d.message,'err');
  } catch(e) { toast('Kill failed: '+e.message,'err'); }
}

// COMPLIANCE
async function runComplianceCheck() {
  toast('Running compliance checks…','info');
  try {
    const r = await fetch('/api/compliance', { method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({}) });
    const d = await r.json();
    if (d.error) { toast('Compliance error: '+d.error,'err'); return; }
    scaChecksCache = d.checks || [];
    renderComplianceScores(d.scores || d);
    toast('Compliance scores updated','ok');
  } catch(e) { toast('Compliance check failed: '+e.message,'err'); }
}

function renderComplianceScores(d) {
  const fwMap = {'PCI-DSS': 'pci', 'HIPAA': 'hipaa', 'NIST': 'nist'};
  for (const [fw, key] of Object.entries(fwMap)) {
    const info = d[fw];
    if (!info) continue;
    const scoreEl = document.getElementById(`comp-${key}-val`);
    const statusEl = document.getElementById(`comp-${key}-status`);
    const detailEl = document.getElementById(`comp-${key}-detail`);
    if (scoreEl) {
      scoreEl.textContent = info.score + '%';
      scoreEl.style.color = info.score>=80?'var(--green)':info.score>=50?'var(--yellow)':'var(--red)';
    }
    if (statusEl) statusEl.innerHTML = `<span class="comp-status ${info.status}">${info.status}</span>`;
    if (detailEl) detailEl.textContent = `${info.pass} pass · ${info.fail} fail · ${info.crit_fail} critical fails`;
  }
}

// ADMIN: DB Manager
async function loadDbs() {
  try {
    const r = await fetch('/api/databases');
    allDbs = await r.json();
    renderDbList(allDbs);
  } catch(e) { document.getElementById('db-list').innerHTML='<div style="color:var(--muted);font-size:10px">Could not connect to DB server</div>'; }
}

function renderDbList(dbs) {
  const curDb = '{{ current_db }}';
  document.getElementById('db-list').innerHTML = (dbs||[]).map(d =>
    `<div class="db-item ${d===curDb?'active-db':''}" data-select-db="${d}">
      <span class="db-name">${d}</span>
      ${d===curDb?'<span style="font-family:\'IBM Plex Mono\',monospace;font-size:9px;color:var(--accent)">ACTIVE</span>':''}
    </div>`
  ).join('') || '<div style="color:var(--muted);font-size:10px">No databases found</div>';
}

function filterDbs() {
  const q = document.getElementById('db-search-input').value.toLowerCase();
  renderDbList(allDbs.filter(d=>d.toLowerCase().includes(q)));
}

async function selectDb(name) {
  try {
    const r = await fetch('/api/switch-db', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({database:name}) });
    const d = await r.json();
    if (d.success) { toast('Switched to '+name,'ok'); loadDbs(); fetchStats(); }
    else toast(d.message,'err');
  } catch(e) { toast('Switch failed: '+e.message,'err'); }
}

async function createDb() {
  const name = document.getElementById('db-create-name').value.trim();
  if (!name) { toast('Enter a database name','err'); return; }
  try {
    const r = await fetch('/api/create-db', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({name}) });
    const d = await r.json();
    const el = document.getElementById('db-status');
    el.style.color = d.success?'var(--green)':'var(--red)';
    el.textContent = d.message;
    if (d.success) { loadDbs(); document.getElementById('db-create-name').value=''; }
    toast(d.message, d.success?'ok':'err');
  } catch(e) { toast('Create failed: '+e.message,'err'); }
}

// ADMIN: Log Paths
function renderLogPaths() {
  document.getElementById('log-paths').innerHTML = logPaths.map((p,i) =>
    `<div class="path-item">
      <div style="display:flex;align-items:center;gap:8px"><div class="path-status"></div><span>${p}</span></div>
      <button class="btn btn-red btn-sm" data-remove-log-idx="${i}">Remove</button>
    </div>`
  ).join('') || '<div style="color:var(--muted);font-size:10px">No paths configured</div>';
}

async function addLogPath() {
  const v = document.getElementById('log-path-input').value.trim();
  if (!v) return;
  try {
    const r = await fetch('/api/add-log-path', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path:v}) });
    const d = await r.json();
    if (d.success) { logPaths = d.paths; renderLogPaths(); toast('Path added: '+v,'ok'); }
    else toast(d.message,'err');
  } catch(e) { toast('Failed: '+e.message,'err'); }
  document.getElementById('log-path-input').value='';
}

async function removeLogPath(i) {
  const p = logPaths[i];
  try {
    const r = await fetch('/api/remove-log-path', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path:p}) });
    const d = await r.json();
    if (d.success) { logPaths = d.paths; renderLogPaths(); toast('Removed: '+p,'ok'); }
  } catch(e) { logPaths.splice(i,1); renderLogPaths(); }
}

// ADMIN: Inventory & Health
async function loadInventory() {
  try {
    const r = await fetch('/api/inventory');
    const d = await r.json();
    document.getElementById('sys-inv').innerHTML = `
      <table class="ip-table"><thead><tr><th>Component</th><th>Value</th></tr></thead><tbody>
        <tr><td>Hostname</td><td style="font-family:'IBM Plex Mono',monospace">${d.hostname||'—'}</td></tr>
        <tr><td>OS</td><td style="font-family:'IBM Plex Mono',monospace">${d.os||'—'}</td></tr>
        <tr><td>Platform</td><td style="font-family:'IBM Plex Mono',monospace">${d.platform||'—'}</td></tr>
        <tr><td>Python</td><td style="font-family:'IBM Plex Mono',monospace">${d.python||'—'}</td></tr>
        <tr><td>Monitored Paths</td><td style="font-family:'IBM Plex Mono',monospace">${d.log_paths||0}</td></tr>
        <tr><td>DB Config</td><td style="font-family:'IBM Plex Mono',monospace">${d.db_host||'—'}/${d.db_name||'—'}</td></tr>
      </tbody></table>`;
  } catch(e) { document.getElementById('sys-inv').innerHTML='<div class="empty-state">Inventory unavailable</div>'; }
}

async function loadHealth() {
  try {
    const r = await fetch('/health');
    const d = await r.json();
    document.getElementById('health-table').innerHTML = `
      <tr><td>Flask Server</td><td><span class="tag tag-low">RUNNING</span></td></tr>
      <tr><td>PostgreSQL</td><td><span class="tag ${d.db==='reachable'?'tag-low':'tag-crit'}">${(d.db||'unknown').toUpperCase()}</span></td></tr>
      <tr><td>Log Agent</td><td><span class="tag tag-low">ACTIVE</span></td></tr>
      <tr><td>API Endpoint</td><td><span class="tag tag-low">OK</span></td></tr>`;
  } catch(e) { document.getElementById('health-table').innerHTML='<tr><td colspan="2" class="empty-state">Health check failed</td></tr>'; }
}

// CSV IMPORT
async function importCSV(input) {
  const file = input.files[0];
  if (!file) return;
  const statusEl = document.getElementById('import-status');
  statusEl.textContent = 'Uploading…';
  statusEl.style.color = 'var(--muted)';
  const formData = new FormData();
  formData.append('file', file);
  try {
    const r = await fetch('/import/csv', { method:'POST', body: formData });
    const d = await r.json();
    if (d.imported !== undefined) {
      statusEl.textContent = `Imported ${d.imported} rows`;
      statusEl.style.color = 'var(--green)';
      toast(`CSV import: ${d.imported} rows added`,'ok');
      fetchStats();
    } else {
      statusEl.textContent = d.error || 'Import failed';
      statusEl.style.color = 'var(--red)';
      toast('Import failed: '+(d.error||'unknown'),'err');
    }
  } catch(e) {
    statusEl.textContent = 'Error: ' + e.message;
    statusEl.style.color = 'var(--red)';
    toast('Import error: '+e.message,'err');
  }
  input.value = '';
}

// UTILS
function toast(msg, type='info') {
  const c = document.getElementById('toast');
  const el = document.createElement('div');
  el.className = 'toast-msg '+type;
  el.innerHTML = `<span>${type==='ok'?'✓':type==='err'?'✕':'ℹ'}</span> ${escHtml(msg)}`;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

async function exportCSV() {
  window.open('/export/csv','_blank');
  toast('Downloading CSV…','info');
}

async function confirmClear() {
  if (!confirm('Delete ALL log events from the database? This cannot be undone.')) return;
  try {
    const r = await fetch('/clear-logs', {method:'POST'});
    const d = await r.json();
    if (d.status==='success') { toast('All logs cleared','ok'); fetchStats(); }
    else toast(d.message,'err');
  } catch(e) { toast('Clear failed: '+e.message,'err'); }
}
// ═══════════════════════════════════════════════════════════════════
// ASSET MANAGEMENT
// ═══════════════════════════════════════════════════════════════════
let allAssets = [];

async function loadAssets() {
  try {
    const r = await fetch('/api/assets');
    allAssets = await r.json();
    renderAssets(allAssets);
    // populate zone filter
    const zones = [...new Set(allAssets.map(a=>a.zone).filter(Boolean))];
    const sel = document.getElementById('ast-filter-zone');
    sel.innerHTML = '<option value="">All Zones</option>' +
      zones.map(z=>`<option>${z}</option>`).join('');
    // stats
    setNum('ast-total', allAssets.length);
    setNum('ast-ics', allAssets.filter(a=>a.is_ics).length);
    setNum('ast-highrisk', allAssets.filter(a=>a.threat_score>=70).length);
    setNum('ast-zones', zones.length);
  } catch(e) { toast('Asset load failed: '+e.message,'err'); }
}

function renderAssets(assets) {
  const tb = document.getElementById('ast-tbody');
  const empty = document.getElementById('ast-empty');
  if (!assets.length) { tb.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';
  const threatColor = s => s>=80?'var(--red)':s>=50?'var(--orange)':'var(--green)';
  tb.innerHTML = assets.map(a => `<tr>
    <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent)">${a.ip||'—'}</td>
    <td>${a.hostname||'—'}</td>
    <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted)">${a.mac||'—'}</td>
    <td>${a.vendor||'—'}</td>
    <td>${a.type||'—'}</td>
    <td style="font-size:10px">${a.os||'—'}</td>
    <td>${a.zone||'—'}</td>
    <td><span class="sev-badge sev-${a.criticality==='CRITICAL'?3:a.criticality==='HIGH'?2:a.criticality==='MEDIUM'?1:0}">${a.criticality||'—'}</span></td>
    <td>${a.ics_proto?`<span style="color:var(--blue);font-family:'IBM Plex Mono',monospace;font-size:9px">${a.ics_proto}</span>`:'—'}</td>
    <td><span style="color:${threatColor(a.threat_score||0)};font-family:'IBM Plex Mono',monospace">${a.threat_score||0}</span></td>
    <td style="font-size:10px;color:var(--muted)">${(a.last_seen||'').slice(0,16)}</td>
    <td><button class="btn btn-sm" data-edit-asset='${JSON.stringify(a)}'>Edit</button></td>
  </tr>`).join('');
}

function filterAssets() {
  const q = document.getElementById('ast-search').value.toLowerCase();
  const zone = document.getElementById('ast-filter-zone').value;
  const type = document.getElementById('ast-filter-type').value;
  let list = allAssets.filter(a => {
    const matchQ = !q || (a.ip||'').includes(q)||(a.hostname||'').toLowerCase().includes(q)||(a.vendor||'').toLowerCase().includes(q);
    const matchZ = !zone || a.zone===zone;
    const matchT = !type || (type==='ICS'?a.is_ics:(type==='IT'?!a.is_ics:true));
    return matchQ && matchZ && matchT;
  });
  renderAssets(list);
}

function openAssetModal(asset) {
  document.getElementById('ast-edit-id').value = asset.id;
  document.getElementById('ast-edit-crit').value = asset.criticality||'MEDIUM';
  document.getElementById('ast-edit-zone').value = asset.zone||'';
  document.getElementById('ast-edit-notes').value = asset.notes||'';
  document.getElementById('ast-modal').style.display='flex';
}

async function saveAsset() {
  const id    = document.getElementById('ast-edit-id').value;
  const crit  = document.getElementById('ast-edit-crit').value;
  const zone  = document.getElementById('ast-edit-zone').value;
  const notes = document.getElementById('ast-edit-notes').value;
  try {
    const r = await fetch('/api/assets/update', { method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({id, criticality:crit, zone, notes}) });
    const d = await r.json();
    if (d.ok) { toast('Asset updated','ok'); document.getElementById('ast-modal').style.display='none'; loadAssets(); }
    else toast(d.error,'err');
  } catch(e) { toast('Save failed: '+e.message,'err'); }
}

// ═══════════════════════════════════════════════════════════════════
// NETWORK ANALYSIS
// ═══════════════════════════════════════════════════════════════════
let allPackets = [];

async function loadInterfaces() {
  try {
    const r = await fetch('/api/capture/interfaces');
    const d = await r.json();
    const sel = document.getElementById('net-iface');
    sel.innerHTML = (d.interfaces||['eth0']).map(i=>`<option>${i}</option>`).join('');
  } catch(e) {}
}

async function startCapture() {
  const iface = document.getElementById('net-iface').value;
  try {
    const r = await fetch('/api/capture/start', { method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify({interface:iface}) });
    const d = await r.json();
    capLog(d.message||d.error);
    toast(d.message||'Capture started','ok');
    document.getElementById('net-status').textContent='RUNNING';
    document.getElementById('net-status').style.color='var(--green)';
  } catch(e) { toast('Start failed: '+e.message,'err'); }
}

async function stopCapture() {
  try {
    const r = await fetch('/api/capture/stop', { method:'POST' });
    const d = await r.json();
    capLog(d.message);
    toast('Capture stopped','info');
    document.getElementById('net-status').textContent='IDLE';
    document.getElementById('net-status').style.color='var(--muted)';
  } catch(e) { toast('Stop failed: '+e.message,'err'); }
}

async function refreshCaptureStats() {
  try {
    const r = await fetch('/api/capture/stats');
    const d = await r.json();
    setNum('net-pkts', d.packets_captured||0);
    document.getElementById('net-status').textContent = d.running?'RUNNING':'IDLE';
    document.getElementById('net-status').style.color = d.running?'var(--green)':'var(--muted)';
  } catch(e) {}
}

function capLog(msg) {
  const c = document.getElementById('capture-log');
  const t = new Date().toTimeString().slice(0,8);
  c.innerHTML = `<div>[${t}] ${escHtml(msg||'')}</div>` + c.innerHTML;
}

async function loadPackets() {
  try {
    const r = await fetch('/api/packets');
    allPackets = await r.json();
    renderPackets(allPackets);
    setNum('net-anomalies', allPackets.filter(p=>p.anomaly).length);
    setNum('net-ics-pkts', allPackets.filter(p=>p.ics_proto).length);
    setNum('net-pkts', allPackets.length);
  } catch(e) {}
}

function renderPackets(pkts) {
  const tb = document.getElementById('pkt-tbody');
  const empty = document.getElementById('pkt-empty');
  if (!pkts.length) { tb.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';
  tb.innerHTML = pkts.map(p => `<tr ${p.anomaly?'class="r-orange"':''}>
    <td style="font-size:10px;color:var(--muted)">${(p.time||'').slice(11,19)}</td>
    <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent)">${p.src_ip||'—'}</td>
    <td style="font-family:'IBM Plex Mono',monospace">${p.dst_ip||'—'}</td>
    <td style="color:var(--muted)">${p.src_port||''}</td>
    <td style="color:var(--muted)">${p.dst_port||''}</td>
    <td><span class="badge badge-SYS">${p.proto||'—'}</span></td>
    <td style="color:var(--muted)">${p.len||0}</td>
    <td style="font-family:'IBM Plex Mono',monospace;font-size:9px">${p.flags||''}</td>
    <td>${p.ics_proto?`<span style="color:var(--blue);font-size:9px">${p.ics_proto}</span>`:'—'}</td>
    <td style="font-size:9px">${p.ics_fc!=null?p.ics_fc:''}</td>
    <td>${p.anomaly?`<span style="color:var(--orange);font-size:9px" title="${escHtml(p.anomaly_reason||'')}">⚠</span>`:'—'}</td>
    <td style="color:${p.threat>=70?'var(--red)':p.threat>=40?'var(--orange)':'var(--green)'}">${p.threat||0}</td>
  </tr>`).join('');
}

function filterPackets() {
  const q = document.getElementById('pkt-filter').value.toLowerCase();
  const proto = document.getElementById('pkt-filter-proto').value;
  renderPackets(allPackets.filter(p => {
    const mq = !q||(p.src_ip||'').includes(q)||(p.dst_ip||'').includes(q);
    const mp = !proto||(p.proto===proto||p.ics_proto===proto);
    return mq && mp;
  }));
}

async function runHostScan() {
  const target = document.getElementById('net-scan-target').value.trim();
  if (!target) { toast('Enter a target','err'); return; }
  document.getElementById('scan-status').textContent = 'Scanning '+target+'…';
  document.getElementById('btn-host-scan').disabled=true;
  try {
    const r = await fetch('/api/network/scan', { method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify({target}) });
    const d = await r.json();
    if (d.error) { toast(d.error,'err'); } else {
      renderScanResults(d.hosts, [], target);
      toast(`Found ${d.count} host(s)`,'ok');
    }
  } catch(e) { toast('Scan failed: '+e.message,'err'); }
  document.getElementById('scan-status').textContent='';
  document.getElementById('btn-host-scan').disabled=false;
}

async function runPortScan() {
  const target = document.getElementById('net-scan-target').value.trim();
  const ports  = document.getElementById('net-scan-ports').value.trim()||'1-1024';
  if (!target) { toast('Enter a target','err'); return; }
  document.getElementById('scan-status').textContent = 'Port scanning '+target+':'+ports+'…';
  document.getElementById('btn-port-scan').disabled=true;
  try {
    const r = await fetch('/api/network/portscan', { method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify({target,ports}) });
    const d = await r.json();
    if (d.error) { toast(d.error,'err'); } else {
      renderScanResults([], d.ports, target);
      toast(`Found ${d.ports.length} open port(s)`,'ok');
    }
  } catch(e) { toast('Port scan failed: '+e.message,'err'); }
  document.getElementById('scan-status').textContent='';
  document.getElementById('btn-port-scan').disabled=false;
}

function renderScanResults(hosts, ports, target) {
  const panel = document.getElementById('scan-results-panel');
  const tb = document.getElementById('scan-results-tbody');
  const count = document.getElementById('scan-result-count');
  panel.style.display='block';
  if (hosts.length) {
    count.textContent = `${hosts.length} host(s) up — ${target}`;
    tb.innerHTML = hosts.map(h=>`<tr>
      <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent)">${h.ip}</td>
      <td>${h.hostname||'—'}</td>
      <td colspan="4"><span class="tag tag-low">UP</span></td>
    </tr>`).join('');
  } else if (ports.length) {
    count.textContent = `${ports.length} open port(s) — ${target}`;
    tb.innerHTML = ports.map(p=>`<tr>
      <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent)">${target}</td>
      <td>—</td>
      <td style="font-family:'IBM Plex Mono',monospace;color:var(--blue)">${p.port}</td>
      <td><span class="tag tag-low">${p.state}</span></td>
      <td>${p.service||'—'}</td>
      <td style="font-size:10px;color:var(--muted)">${p.version||''}</td>
    </tr>`).join('');
  } else {
    count.textContent = 'No results';
    tb.innerHTML = '<tr><td colspan="6" class="empty-state">No hosts/ports found</td></tr>';
  }
}

// ═══════════════════════════════════════════════════════════════════
// ICS / SCADA
// ═══════════════════════════════════════════════════════════════════
async function loadIcsRisk() {
  try {
    const r = await fetch('/api/ics/risk-assessment');
    const d = await r.json();
    if (d.error) return;
    document.getElementById('ics-risk-overall').textContent = d.overall+'%';
    const lvlEl = document.getElementById('ics-risk-level');
    const colors = {CRITICAL:'var(--red)',HIGH:'var(--orange)',MEDIUM:'var(--yellow)',LOW:'var(--green)'};
    lvlEl.textContent = d.risk_level;
    lvlEl.style.color = colors[d.risk_level]||'var(--text)';
    document.getElementById('ics-risk-avail').textContent  = (d.domains.Availability||0)+'%';
    document.getElementById('ics-risk-integ').textContent  = (d.domains.Integrity||0)+'%';
    document.getElementById('ics-risk-conf').textContent   = (d.domains.Confidentiality||0)+'%';
    document.getElementById('ics-risk-auth').textContent   = (d.domains.Authentication||0)+'%';
    document.getElementById('ics-risk-standards').textContent =
      'Standards: ' + (d.standards||[]).join(' · ');
  } catch(e) {}
}

async function loadSisRules() {
  try {
    const r = await fetch('/api/ics/sis-rules');
    const rules = await r.json();
    document.getElementById('sis-rule-count').textContent = rules.length+' rules';
    const sevColor = s=>s==='CRITICAL'?'var(--red)':s==='HIGH'?'var(--orange)':'var(--yellow)';
    const tb = document.getElementById('sis-rules-tbody');
    document.getElementById('sis-rules-empty').style.display='none';
    tb.innerHTML = rules.map(r=>`<tr>
      <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent);font-size:10px">${r.id}</td>
      <td style="font-size:11px">${r.name}</td>
      <td><span class="badge badge-SYS">${r.protocol}</span></td>
      <td style="font-size:10px;color:var(--muted)">${r.zone}</td>
      <td><span style="color:${sevColor(r.severity)};font-family:'IBM Plex Mono',monospace;font-size:9px">${r.severity}</span></td>
    </tr>`).join('');
  } catch(e) {}
}

async function loadSisEvents() {
  try {
    const r = await fetch('/api/ics/sis-events');
    const events = await r.json();
    const tb = document.getElementById('sis-events-tbody');
    const empty = document.getElementById('sis-events-empty');
    if (!events.length) { tb.innerHTML=''; empty.style.display='block'; return; }
    empty.style.display='none';
    const sevColor = s=>s==='CRITICAL'?'r-red':s==='HIGH'?'r-orange':'';
    tb.innerHTML = events.map(e=>`<tr class="${e.severity==='CRITICAL'?'r-red':e.severity==='HIGH'?'r-orange':''}">
      <td style="font-size:10px;color:var(--muted)">${(e.time||'').slice(0,16)}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--accent)">${e.rule_id}</td>
      <td><span style="color:${e.severity==='CRITICAL'?'var(--red)':'var(--orange)'};font-size:9px">${e.severity}</span></td>
      <td style="font-family:'IBM Plex Mono',monospace">${e.src_ip||'—'}</td>
      <td style="font-size:10px">${e.zone||'—'}</td>
      <td style="font-size:10px;color:var(--muted)" title="${escHtml(e.action||'')}">${escHtml((e.action||'').slice(0,40))}…</td>
    </tr>`).join('');
  } catch(e) {}
}

let allIcsEvents = [];
async function loadIcsEvents() {
  try {
    const r = await fetch('/api/ics/events');
    allIcsEvents = await r.json();
    renderIcsEvents(allIcsEvents);
  } catch(e) {}
}

function renderIcsEvents(events) {
  const tb = document.getElementById('ics-events-tbody');
  const empty = document.getElementById('ics-events-empty');
  if (!events.length) { tb.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';
  tb.innerHTML = events.map(e=>`<tr>
    <td style="font-size:10px;color:var(--muted)">${(e.time||'').slice(0,16)}</td>
    <td><span class="badge badge-${e.type}">${e.type}</span></td>
    <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent)">${e.src_ip||'—'}</td>
    <td style="font-family:'IBM Plex Mono',monospace">${e.dst_ip||'—'}</td>
    <td style="color:var(--muted)">${e.port||'—'}</td>
    <td><span class="sev-badge sev-${e.severity==='CRITICAL'?3:e.severity==='HIGH'?2:1}">${e.severity||'—'}</span></td>
    <td style="font-size:10px" title="${escHtml(e.message||'')}">${escHtml((e.message||'').slice(0,60))}</td>
    <td style="font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--blue)">${e.mitre||''}</td>
  </tr>`).join('');
}

function filterIcsEvents() {
  const proto = document.getElementById('ics-proto-filter').value;
  renderIcsEvents(allIcsEvents.filter(e=>!proto||e.type===proto));
}

async function loadIcsPackets() {
  try {
    const r = await fetch('/api/ics/packets');
    const pkts = await r.json();
    const tb = document.getElementById('ics-pkts-tbody');
    const empty = document.getElementById('ics-pkts-empty');
    if (!pkts.length) { tb.innerHTML=''; empty.style.display='block'; return; }
    empty.style.display='none';
    tb.innerHTML = pkts.map(p=>`<tr ${p.anomaly?'class="r-orange"':''}>
      <td style="font-size:10px;color:var(--muted)">${(p.time||'').slice(11,19)}</td>
      <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent)">${p.src_ip||'—'}</td>
      <td style="font-family:'IBM Plex Mono',monospace">${p.dst_ip||'—'}</td>
      <td><span style="color:var(--blue);font-size:9px">${p.proto||'—'}</span></td>
      <td style="color:var(--muted)">${p.fc!=null?p.fc:''}</td>
      <td style="font-size:10px">${p.fn||'—'}</td>
      <td style="font-family:'IBM Plex Mono',monospace;font-size:10px">${p.addr!=null?p.addr:'—'}</td>
      <td style="font-size:10px">${p.val||'—'}</td>
      <td style="color:${p.threat>=70?'var(--red)':p.threat>=40?'var(--orange)':'var(--green)'}">${p.threat||0}</td>
      <td>${p.anomaly?`<span style="color:var(--orange)" title="${escHtml(p.reason||'')}">⚠ YES</span>`:'—'}</td>
    </tr>`).join('');
  } catch(e) {}
}

// ═══════════════════════════════════════════════════════════════════
// HONEYPOT
// ═══════════════════════════════════════════════════════════════════
const HP_PORTS = {
  502:  {proto:'Modbus TCP',    device:'Siemens S7-300 PLC'},
  20000:{proto:'DNP3',          device:'SEL-351 Protection Relay'},
  102:  {proto:'S7/IEC104',     device:'Siemens S7-400'},
  44818:{proto:'EtherNet/IP',   device:'Allen-Bradley CompactLogix'},
  47808:{proto:'BACnet/IP',     device:'Johnson Controls BAS'},
};

async function loadHoneypotStats() {
  try {
    const r = await fetch('/api/honeypot/stats');
    const d = await r.json();
    setNum('hp-total', d.total||0);
    setNum('hp-ips', (d.top_ips||[]).length);
    if (d.proto_hits&&d.proto_hits.length) {
      document.getElementById('hp-top-proto').textContent = d.proto_hits[0][0];
    }
    // Port table
    const pb = document.getElementById('hp-port-table');
    const hitMap = {};
    (d.proto_hits||[]).forEach(([p,c])=>{ hitMap[p]=c; });
    pb.innerHTML = Object.entries(HP_PORTS).map(([port,info])=>`<tr>
      <td style="font-family:'IBM Plex Mono',monospace;color:var(--blue)">${port}</td>
      <td>${info.proto}</td>
      <td style="font-size:10px;color:var(--muted)">${info.device}</td>
      <td style="color:${hitMap[info.proto]>0?'var(--red)':'var(--muted)'}">${hitMap[info.proto]||0}</td>
    </tr>`).join('');
    // Attacker table
    const ab = document.getElementById('hp-attacker-table');
    const attackerEmpty = document.getElementById('hp-attacker-empty');
    if (!(d.top_ips||[]).length) { ab.innerHTML=''; attackerEmpty.style.display='block'; }
    else {
      attackerEmpty.style.display='none';
      ab.innerHTML = (d.top_ips||[]).map(([ip,count])=>`<tr>
        <td style="font-family:'IBM Plex Mono',monospace;color:var(--red)">${ip}</td>
        <td>${count}</td>
        <td><button class="btn btn-red btn-sm" data-quick-block="${ip}">Block</button></td>
      </tr>`).join('');
    }
  } catch(e) {}
}

let allHpEvents = [];
async function loadHoneypotEvents() {
  try {
    const r = await fetch('/api/honeypot/events');
    allHpEvents = await r.json();
    renderHpEvents(allHpEvents);
    if (allHpEvents.length) {
      document.getElementById('hp-last').textContent = (allHpEvents[0].time||'').slice(0,16);
    }
  } catch(e) {}
}

function renderHpEvents(events) {
  const tb = document.getElementById('hp-events-tbody');
  const empty = document.getElementById('hp-events-empty');
  if (!events.length) { tb.innerHTML=''; empty.style.display='block'; return; }
  empty.style.display='none';
  tb.innerHTML = events.map(e=>`<tr>
    <td style="font-size:10px;color:var(--muted)">${(e.time||'').slice(0,16)}</td>
    <td style="font-family:'IBM Plex Mono',monospace;color:var(--red)">${e.src_ip||'—'}</td>
    <td style="font-family:'IBM Plex Mono',monospace">${e.dst_ip||'—'}</td>
    <td style="color:var(--blue)">${e.port||'—'}</td>
    <td><span class="badge badge-SYS">${e.proto||'—'}</span></td>
    <td style="font-size:10px" title="${escHtml(e.message||'')}">${escHtml((e.message||'').slice(0,60))}</td>
    <td><span class="sev-badge sev-${e.severity==='CRITICAL'?3:e.severity==='HIGH'?2:1}">${e.severity||'INFO'}</span></td>
    <td><button class="btn btn-red btn-sm" data-quick-block="${e.src_ip}">Block</button></td>
  </tr>`).join('');
}

function filterHpEvents() {
  const port = document.getElementById('hp-proto-filter').value;
  renderHpEvents(allHpEvents.filter(e=>!port||String(e.port)===port));
}

</script>
</body>
</html>
"""
