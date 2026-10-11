"""PIF Admin Portal: live telemetry, scan history, a manual scan console and
the self-tuning agent console.

Reads every scan straight from the report.db the firewall writes (pif/report_db.py),
proxies manual scans to the local PIF API so the full HTTP behaviour
(auth, body limit, decision, quarantine) is exercised from the UI, and exposes
pif/agenticai_redteam.py state: cycle history, pending fixes with their
evidence and the human approve/reject gate.

Run:  .venv/Scripts/python.exe UI_PIF/pif_portal.py   (portal on http://127.0.0.1:8081)
The PIF API must be running for manual scans:  .venv/Scripts/python.exe scripts/main.py
"""

import configparser
import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
# The agent module uses project-relative paths (reports/, conf/, data/);
# anchor the portal process at the project root so it works from any cwd.
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))
DB_PATH = Path(os.getenv("PIF_REPORT_DB_PATH", str(PROJECT_ROOT / "data" / "report.db")))
PIF_API = os.getenv("PIF_URL", "http://127.0.0.1:8000")
PORTAL_PORT = int(os.getenv("PIF_PORTAL_PORT", "8081"))
FULL_CORPUS = Path("data/processed/eval_full.jsonl")
DEMO_CORPUS = Path("data/samples/redteam_demo/eval_demo.jsonl")

# Scheduled tune cycles: nightly, off-peak, and only when the cycle's INPUTS
# changed. Safe to automate because supervision lives at the human gate — a
# scheduled cycle writes only to reports/redteam/ and every proposal still
# waits for an explicit human approve/reject. The skip gate hashes file
# CONTENT (not size, not mtime) of everything that can invalidate a cycle's
# conclusion, mirroring the firewall's own _policy_fingerprint trick.
SCHEDULER_STATE_PATH = Path(os.getenv("PIF_SCHEDULER_STATE", str(PROJECT_ROOT / "reports" / "redteam" / "scheduler.json")))
SCHEDULER_FINGERPRINT_FILES = (
    PROJECT_ROOT / "conf" / "policy.ini",
    Path(os.getenv("PIF_POLICY_FILE", str(PROJECT_ROOT / "conf" / "policy-overrides.json"))),
    PROJECT_ROOT / "data" / "samples" / "redteam_demo" / "eval_demo.jsonl",
    PROJECT_ROOT / "data" / "processed" / "eval_full.jsonl",
)
SCHEDULER_CHECK_SECONDS = 30
DEFAULT_SCHEDULER_STATE = {
    "enabled": False,
    "hour": 2,               # local time anchor for the daily (24h) interval
    "interval_hours": 24,    # run every N hours; 24 = daily at the hour above
    "corpus": "demo",        # "demo" | "full"
    "last_run_date": None,   # YYYY-MM-DD of the last handled scheduled slot
    "last_run_ts": None,     # unix time of the last handled scheduled slot (interval mode)
    "last_fingerprint": None,# input hash at the last COMPLETED cycle
    "last_result": None,     # last outcome summary shown on the card
}

agent_cycle_lock = threading.Lock()
_scheduler_thread_started = False


def load_token() -> str:
    token = os.getenv("PIF_API_TOKEN", "")
    if not token:
        token_file = PROJECT_ROOT / ".pif-token"
        if token_file.is_file():
            token = token_file.read_text(encoding="utf-8").strip()
    return token


def connect_db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def db_available() -> bool:
    return DB_PATH.is_file()


JSON_COLUMNS = ("attacks", "attack_ids", "warnings", "quarantined", "file_names")


def decode_row(row: dict) -> dict:
    """SQLite stores list columns as JSON text; hand them to the UI as arrays."""
    for column in JSON_COLUMNS:
        value = row.get(column)
        if isinstance(value, str):
            try:
                row[column] = json.loads(value)
            except json.JSONDecodeError:
                row[column] = []
    return row


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PIF Admin Portal</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0' stop-color='%233E6BFF'/%3E%3Cstop offset='1' stop-color='%2318C7DE'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect x='1' y='1' width='46' height='46' rx='12' fill='url(%23g)'/%3E%3Cpath d='M9.8 36V13.2h4.2a5.2 5.2 0 0 1 0 10.4H9.8' fill='none' stroke='%23F2F6FF' stroke-width='3.4' stroke-linecap='round'/%3E%3Crect x='20.7' y='13.2' width='7.5' height='3.2' rx='1.6' fill='%23F2F6FF'/%3E%3Crect x='22.9' y='13.2' width='3.2' height='22.5' rx='1.6' fill='%23F2F6FF'/%3E%3Crect x='20.7' y='32.5' width='7.5' height='3.2' rx='1.6' fill='%23F2F6FF'/%3E%3Crect x='30.9' y='13.2' width='3.3' height='22.5' rx='1.4' fill='%23F2F6FF'/%3E%3Crect x='35' y='13.2' width='3.3' height='3.2' rx='.9' fill='%23F2F6FF'/%3E%3Crect x='39.1' y='13.2' width='2.3' height='3.2' rx='.9' fill='%23A9C9FF'/%3E%3Crect x='35' y='19.6' width='2.1' height='3.2' rx='.9' fill='%23A9C9FF'/%3E%3Crect x='37.9' y='19.6' width='3.5' height='3.2' rx='.9' fill='%23F2F6FF'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  /* ============ PIF enterprise design system ============ */
  :root { --bg:#070B15; --bg-main:#0A101D;
          --panel:#0E1626; --panel-2:#121C30; --panel-3:#16213A;
          --border:#1D2A45; --border-hi:#2C3E63;
          --text:#E9EFFA; --muted:#93A5C4; --faint:#64748F;
          --accent:#5B8AFF; --accent-2:#22D3EE;
          --ok:#34D399; --warn:#FBBF24; --orange:#FB923C; --bad:#F87171;
          --purple:#A78BFA; --pink:#F472B6;
          --grad:linear-gradient(135deg,#4E7DFF 0%,#22D3EE 100%);
          --radius:14px;
          --font:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
          --mono:'JetBrains Mono','Cascadia Code',Consolas,monospace;
          color-scheme:dark; }
  * { box-sizing:border-box; }
  ::selection { background:rgba(91,138,255,.35); }
  ::-webkit-scrollbar { width:9px; height:9px; }
  ::-webkit-scrollbar-thumb { background:#223051; border-radius:8px; border:2px solid var(--bg-main); }
  ::-webkit-scrollbar-track { background:transparent; }
  body { margin:0; font-family:var(--font); background:var(--bg); color:var(--text);
         display:flex; min-height:100vh; -webkit-font-smoothing:antialiased; }

  /* ---------- sidebar ---------- */
  nav { width:262px; flex-shrink:0; display:flex; flex-direction:column; gap:2px;
        background:linear-gradient(180deg,#0A1120 0%,#080D19 100%);
        border-right:1px solid var(--border); padding:20px 14px 16px;
        position:sticky; top:0; height:100vh; overflow-y:auto; }
  .brand { display:flex; align-items:center; gap:12px; padding:2px 8px 16px;
           border-bottom:1px solid var(--border); margin-bottom:12px; }
  .logo-mark { width:46px; height:46px; flex-shrink:0;
               filter:drop-shadow(0 6px 16px rgba(62,107,255,.4)); }
  .logo-cursor { animation:pif-blink 1.25s linear infinite; }
  @keyframes pif-blink { 0%,54% { opacity:1; } 55%,100% { opacity:0; } }
  .brand-name { font-size:19px; font-weight:800; letter-spacing:.14em; color:#fff; line-height:1.05; }
  .brand-name span { font-weight:600; letter-spacing:.02em; color:var(--muted); font-size:12px; }
  .brand-sub { font-size:8.5px; font-weight:700; letter-spacing:.13em; text-transform:uppercase;
               color:var(--faint); margin-top:4px; }
  .nav-label { font-size:9.5px; font-weight:700; letter-spacing:.15em; text-transform:uppercase;
               color:var(--faint); padding:14px 10px 6px; }
  nav button[data-view] { display:flex; align-items:center; gap:11px; width:100%; text-align:left;
               background:none; border:none; border-radius:10px; color:var(--muted);
               padding:9px 12px; font-size:13.5px; font-weight:500; cursor:pointer;
               font-family:var(--font); position:relative; transition:color .15s, background .15s; }
  nav button[data-view] svg { width:18px; height:18px; flex-shrink:0; opacity:.9; }
  nav button[data-view]:hover { color:var(--text); background:rgba(91,138,255,.07); }
  nav button[data-view].active { color:#fff; font-weight:600;
               background:linear-gradient(90deg,rgba(91,138,255,.18),rgba(34,211,238,.05)); }
  nav button[data-view].active::before { content:""; position:absolute; left:0; top:22%; bottom:22%;
               width:3px; border-radius:3px; background:linear-gradient(180deg,#5B8AFF,#22D3EE); }
  nav button[data-view].active svg { color:#8FB2FF; opacity:1; }
  .sysbox { margin:16px 4px 10px; padding:12px 13px; border:1px solid var(--border);
            border-radius:12px; background:rgba(10,17,32,.72); font-size:11.5px; color:var(--muted); }
  .sysbox-title { font-size:9px; font-weight:700; letter-spacing:.16em; text-transform:uppercase;
                  color:var(--faint); margin-bottom:8px; }
  .sysrow { display:flex; align-items:center; gap:8px; padding:3px 0; }
  .syslabel { flex:1; }
  .sysval { color:var(--faint); font-family:var(--mono); font-size:10px; }
  .dot { width:7px; height:7px; border-radius:50%; background:var(--faint); flex-shrink:0;
         box-shadow:0 0 0 3px rgba(255,255,255,.04); }
  .nav-foot { margin-top:auto; padding:14px 8px 2px; font-size:10.5px; color:var(--faint);
              display:flex; gap:7px; align-items:center; letter-spacing:.03em; }
  .nav-foot svg { width:14px; height:14px; flex-shrink:0; }

  /* ---------- main / page heads ---------- */
  main { flex:1; padding:28px 34px 56px; overflow-y:auto; max-height:100vh;
         background:radial-gradient(1100px 480px at 85% -12%, rgba(91,138,255,.10), transparent 55%),
                    radial-gradient(800px 380px at -5% -8%, rgba(34,211,238,.07), transparent 55%),
                    var(--bg-main); }
  .view { display:none; } .view.active { display:block; }
  h2 { margin:0; font-size:20px; font-weight:700; letter-spacing:-.01em; }
  .page-head { display:flex; align-items:flex-start; gap:14px; margin-bottom:20px; flex-wrap:wrap; }
  .ph-icon { width:42px; height:42px; border-radius:12px; display:flex; align-items:center;
             justify-content:center; flex-shrink:0; color:#8FB2FF;
             background:linear-gradient(135deg,rgba(91,138,255,.16),rgba(34,211,238,.07));
             border:1px solid rgba(91,138,255,.28); }
  .ph-icon svg { width:20px; height:20px; }
  .ph-sub { margin:5px 0 0; font-size:12.5px; color:var(--muted); line-height:1.55; max-width:820px; }
  .ph-actions { margin-left:auto; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }

  /* ---------- KPI cards ---------- */
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(152px,1fr));
           gap:12px; margin-bottom:20px; }
  .card { position:relative; overflow:hidden; padding:15px 17px; border-radius:var(--radius);
          background:linear-gradient(180deg,var(--panel-2) 0%,var(--panel) 100%);
          border:1px solid var(--border); transition:border-color .15s, transform .15s; }
  .card::after { content:""; position:absolute; inset:0 0 auto 0; height:2px; opacity:0;
                 background:var(--grad); transition:opacity .2s; }
  .card:hover { border-color:var(--border-hi); transform:translateY(-1px); }
  .card:hover::after { opacity:.75; }
  .card .num { font-size:26px; font-weight:700; letter-spacing:-.02em; font-variant-numeric:tabular-nums; }
  .card .lbl { font-size:10px; font-weight:600; letter-spacing:.1em; text-transform:uppercase;
               color:var(--faint); margin-top:5px; }

  /* ---------- tables ---------- */
  table { width:100%; border-collapse:collapse; background:var(--panel); font-size:12.5px;
          border:1px solid var(--border); border-radius:12px; overflow:hidden; }
  th, td { padding:10px 14px; text-align:left; border-bottom:1px solid rgba(29,42,69,.7); }
  th { background:var(--panel-2); color:var(--muted); font-weight:600; font-size:10.5px;
       letter-spacing:.08em; text-transform:uppercase; position:sticky; top:0; z-index:1; }
  tbody tr:last-child td { border-bottom:none; }
  tr.clickable, tr.row-clickable { cursor:pointer; }
  tr.clickable:hover, tr.row-clickable:hover { background:rgba(91,138,255,.06); }
  td.mono, .mono { font-family:var(--mono); font-size:11.5px; }

  /* ---------- badges / chips / tags ---------- */
  .badge { display:inline-flex; align-items:center; gap:6px; padding:2.5px 9px; border-radius:999px;
           font-size:10px; font-weight:700; letter-spacing:.08em; white-space:nowrap;
           background:color-mix(in srgb, var(--bc,#5B8AFF) 15%, transparent);
           color:color-mix(in srgb, var(--bc,#5B8AFF) 55%, #fff);
           box-shadow:inset 0 0 0 1px color-mix(in srgb, var(--bc,#5B8AFF) 38%, transparent); }
  .badge::before { content:""; width:5px; height:5px; border-radius:50%; background:currentColor; }
  .chip { display:inline-flex; align-items:center; background:rgba(18,28,48,.9);
          border:1px solid var(--border); border-radius:7px; padding:2px 9px; margin:1.5px;
          font-size:11px; color:#C6D4EC; font-family:var(--mono); }
  .tag { display:inline-block; padding:1px 8px; border-radius:6px; font-size:10px;
         font-weight:600; letter-spacing:.05em; border:1px solid var(--border); color:var(--muted); }
  .tag.custom { border-color:rgba(91,138,255,.5); color:#8FB2FF; background:rgba(91,138,255,.08); }

  /* ---------- controls ---------- */
  .toolbar { display:flex; gap:10px; margin-bottom:14px; align-items:center; flex-wrap:wrap; }
  select, input[type=text], input[type=search], textarea {
      background:#0A1220; color:var(--text); border:1px solid var(--border);
      border-radius:10px; padding:8px 12px; font-size:12.5px; font-family:var(--font);
      transition:border-color .15s, box-shadow .15s; }
  select:focus, input:focus, textarea:focus { outline:none; border-color:var(--accent);
      box-shadow:0 0 0 3px rgba(91,138,255,.16); }
  textarea { width:100%; min-height:120px; resize:vertical; line-height:1.6; font-size:13px; }
  button { font-family:var(--font); }
  button.primary { background:var(--grad); color:#061024; border:none; border-radius:10px;
                   padding:9px 18px; font-size:12.5px; font-weight:700; letter-spacing:.02em;
                   cursor:pointer; box-shadow:0 8px 22px -8px rgba(79,125,255,.55);
                   transition:filter .15s, transform .15s; }
  button.primary:hover { filter:brightness(1.12); transform:translateY(-1px); }
  button.primary:disabled { opacity:.55; cursor:wait; transform:none; }
  button.ghost { background:var(--panel-2); color:var(--text); border:1px solid var(--border);
                 border-radius:10px; padding:7px 14px; cursor:pointer; font-size:12px;
                 font-weight:600; transition:border-color .15s, background .15s; }
  button.ghost:hover { border-color:var(--border-hi); background:var(--panel-3); }
  button.ghost:disabled { opacity:.45; cursor:not-allowed; }
  input[type=file] { color:var(--muted); font-size:12px; }

  /* ---------- playground / verdict ---------- */
  .verdict { border-radius:var(--radius); padding:20px 24px; margin:18px 0;
             border:1px solid var(--border);
             background:linear-gradient(180deg,var(--panel-2),var(--panel)); }
  .verdict .big { font-size:22px; font-weight:800; letter-spacing:.08em; }
  .kv { display:grid; grid-template-columns:190px 1fr; gap:7px 16px; font-size:12.5px;
        margin-top:14px; }
  .kv .k { color:var(--faint); font-weight:600; font-size:10.5px; text-transform:uppercase;
           letter-spacing:.07em; padding-top:2px; }
  pre { background:#070D1A; border:1px solid var(--border); border-radius:12px; padding:14px 16px;
        font-size:11.5px; font-family:var(--mono); line-height:1.6; overflow:auto;
        max-height:420px; color:#C9D6EE; }
  details { margin-top:12px; } summary { cursor:pointer; color:var(--accent); font-weight:600; }
  .error-box { background:rgba(248,113,113,.08); border:1px solid rgba(248,113,113,.4);
               border-radius:10px; padding:12px 16px; margin:12px 0; color:#FCA5A5; font-size:12.5px; }
  .drop { border:1.5px dashed var(--border-hi); border-radius:var(--radius); padding:22px;
          text-align:center; color:var(--muted); margin-top:12px; background:rgba(14,22,38,.5);
          transition:border-color .15s, background .15s; }
  .drop:hover { border-color:var(--accent); background:rgba(91,138,255,.05); }
  .filelist { margin-top:8px; font-size:12px; color:var(--muted); }
  .filelist div { padding:2px 0; }
  .muted { color:var(--muted); font-size:11.5px; }

  /* ---------- modal ---------- */
  .modal-bg { display:none; position:fixed; inset:0; background:rgba(3,7,15,.74);
              backdrop-filter:blur(7px); z-index:50; align-items:flex-start;
              justify-content:center; overflow-y:auto; padding:48px 24px; }
  .modal-bg.open { display:flex; }
  .modal { background:linear-gradient(180deg,#121B30,#0D1524); border:1px solid var(--border-hi);
           border-radius:18px; width:min(1020px,100%); padding:24px 28px;
           box-shadow:0 40px 100px -20px rgba(0,0,0,.7); }
  .modal h3 { margin:0 0 6px; font-size:17px; }
  .modal .close { float:right; cursor:pointer; background:var(--panel-2); border:1px solid var(--border);
           color:var(--muted); width:30px; height:30px; border-radius:9px; font-size:15px;
           line-height:1; }
  .modal .close:hover { color:var(--text); border-color:var(--border-hi); }
  .tabs { display:flex; gap:2px; margin:16px 0; border-bottom:1px solid var(--border); }
  .tabs button { background:none; border:none; color:var(--muted); padding:8px 15px;
                 cursor:pointer; border-bottom:2px solid transparent; font-size:12.5px;
                 font-weight:600; transition:color .15s; }
  .tabs button:hover { color:var(--text); }
  .tabs button.active { color:#fff; border-bottom-color:var(--accent); }
  .tabpane { display:none; } .tabpane.active { display:block; }

  /* ---------- rules ---------- */
  .stage { background:var(--panel); border:1px solid var(--border); border-left:3px solid var(--accent);
           border-radius:12px; padding:14px 16px; margin-bottom:10px; }
  .stage .alias { font-size:9.5px; color:var(--faint); letter-spacing:.13em; font-weight:700;
                  text-transform:uppercase; }
  .stage .name { font-size:14px; font-weight:650; margin:3px 0 7px; }
  .stage p { margin:4px 0; font-size:12.5px; color:#C3D0E8; line-height:1.55; }
  .stage .inputs { color:var(--faint); font-size:11.5px; }
  .stage .arrow { text-align:center; color:var(--faint); font-size:15px; margin:2px 0 10px; }
  .state-on { color:var(--ok); font-weight:600; } .state-off { color:var(--bad); font-weight:600; }
  table.rules td, table.rules th { vertical-align:top; }
  .rule-id { font-weight:700; } .rule-cat { color:var(--muted); }
  .rule-off td { opacity:.42; }   /* disabled by a script — dimmed, no extra column */
  .rule-pat { font-family:var(--mono); font-size:10.5px; color:var(--faint);
              max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .switch { position:relative; width:38px; height:20px; display:inline-block; flex-shrink:0; }
  .switch input { opacity:0; width:0; height:0; }
  .switch span { position:absolute; inset:0; background:#1C2946; border-radius:11px; cursor:pointer;
                 transition:.18s; box-shadow:inset 0 0 0 1px rgba(255,255,255,.04); }
  .switch span:before { content:""; position:absolute; width:14px; height:14px; border-radius:50%;
                        background:#8FA3C4; top:3px; left:3px; transition:.18s; }
  .switch input:checked + span { background:linear-gradient(90deg,#3E6BFF,#22D3EE); }
  .switch input:checked + span:before { background:#fff; transform:translateX(18px); }

  /* ---------- approval card ---------- */
  .approve-card { background:linear-gradient(180deg,rgba(251,191,36,.05),rgba(14,22,38,.6));
                  border:1px solid rgba(251,191,36,.42); border-radius:var(--radius);
                  padding:18px 22px; margin:14px 0; }
  .approve-card h4 { margin:0 0 10px; font-size:14px; color:var(--warn); }
  .approve-card .q { display:grid; grid-template-columns:150px 1fr; gap:7px 14px; font-size:12.5px; }
  .approve-card .q .k { color:var(--warn); font-weight:700; font-size:10.5px;
                        text-transform:uppercase; letter-spacing:.06em; padding-top:2px; }
  .q-rule { background:#0A1220; border:1px solid var(--border); border-radius:10px;
            padding:9px 13px; margin:6px 0; font-size:12.5px; }
  textarea.why { width:100%; min-height:48px; margin-top:6px; }

  /* ---------- candidate proposal card ---------- */
  .cand-card { background:var(--panel); border:1px solid var(--border); border-left:3px solid var(--warn);
               border-radius:12px; padding:16px 20px; margin:12px 0; }
  .cand-head { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .cand-status { font-size:12px; color:var(--muted); margin-top:6px; }
  .subject { margin:12px 0 2px; }
  .stage-chip { display:inline-block; background:rgba(91,138,255,.1); border:1px solid rgba(91,138,255,.35);
                color:#8FB2FF; border-radius:7px; padding:1px 9px; font-size:10.5px; font-weight:600;
                margin-left:8px; vertical-align:2px; }
  .metrics { display:flex; gap:10px; flex-wrap:wrap; margin:12px 0 10px; }
  .metric { flex:1; min-width:180px; background:#0A1220; border:1px solid var(--border);
            border-radius:10px; padding:11px 14px; }
  .metric .mlbl { font-size:9.5px; letter-spacing:.1em; color:var(--faint); font-weight:700;
                  text-transform:uppercase; }
  .metric .mval { font-size:18px; font-weight:700; margin-top:4px; font-family:var(--mono); }
  .metric .msub { font-size:11px; color:var(--muted); margin-top:4px; line-height:1.45; }
  .cand-line { display:grid; grid-template-columns:120px 1fr; gap:6px 12px; font-size:12.5px; }
  .cand-line .k { color:var(--faint); font-weight:600; font-size:10.5px; text-transform:uppercase;
                  letter-spacing:.06em; padding-top:2px; }

  /* ---------- proposal hero / stepper / results ---------- */
  .hero { display:flex; align-items:center; gap:18px 26px; flex-wrap:wrap;
          background:linear-gradient(135deg,rgba(91,138,255,.10),rgba(34,211,238,.05) 70%,transparent),
                     var(--panel-2);
          border:1px solid var(--border-hi); border-radius:14px; padding:16px 22px; }
  .hero .h-sub { font-size:9.5px; letter-spacing:.14em; color:var(--faint); font-weight:700;
                 text-transform:uppercase; margin-bottom:3px; }
  .hero .h-id { font-size:20px; font-weight:800; font-family:var(--mono); line-height:1.1; }
  .wgroup { display:flex; align-items:center; gap:10px; }
  .wpill { text-align:center; background:#0A1220; border:1px solid var(--border);
           border-radius:12px; padding:7px 18px; min-width:86px; }
  .wpill .wv { font-size:21px; font-weight:800; font-family:var(--mono); font-variant-numeric:tabular-nums; }
  .wpill .wl { font-size:8.5px; letter-spacing:.13em; color:var(--faint); font-weight:700;
               text-transform:uppercase; margin-top:2px; }
  .wpill.proposed { border-color:rgba(251,191,36,.55);
                    box-shadow:inset 0 0 0 1px rgba(251,191,36,.18), 0 4px 14px -6px rgba(251,191,36,.35); }
  .warrow { color:var(--faint); font-size:19px; }
  .stepper { display:flex; margin:18px 2px 2px; }
  .stepper .st { flex:1; text-align:center; position:relative; }
  .stepper .st::before, .stepper .st::after { content:""; position:absolute; top:15px; height:2px;
        width:50%; background:var(--border); }
  .stepper .st::before { left:0; } .stepper .st::after { right:0; }
  .stepper .st:first-child::before, .stepper .st:last-child::after { display:none; }
  .stepper .st.finished::after { background:#2A9D74; }
  .st-dot { width:30px; height:30px; border-radius:50%; margin:0 auto 7px; position:relative; z-index:1;
            display:flex; align-items:center; justify-content:center; font-size:13px; font-weight:800;
            background:var(--panel-3); border:2px solid var(--border); color:var(--muted); }
  .st-dot.done { background:rgba(52,211,153,.14); border-color:#2A9D74; color:var(--ok); }
  .st-dot.active { background:rgba(251,191,36,.12); border-color:var(--warn); color:var(--warn);
                   box-shadow:0 0 0 4px rgba(251,191,36,.12); }
  .st-dot.fail { background:rgba(248,113,113,.12); border-color:var(--bad); color:var(--bad); }
  .st-dot.skip { background:var(--panel-2); border-color:var(--border); color:var(--faint); }
  .st-name { font-size:12px; font-weight:700; }
  .st-state { font-size:10px; letter-spacing:.06em; text-transform:uppercase; font-weight:700;
              margin-top:2px; }
  .st-state.done { color:var(--ok); } .st-state.active { color:var(--warn); }
  .st-state.fail { color:var(--bad); } .st-state.skip { color:var(--faint); }
  .sec-title { font-size:10px; font-weight:700; letter-spacing:.14em; text-transform:uppercase;
               color:var(--accent); margin:18px 0 8px; }
  .results { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin:10px 0; }
  .rcard { border:1px solid var(--border); border-radius:12px; padding:12px 16px; background:#0A1220;
           display:flex; gap:11px; align-items:flex-start; }
  .rcard .r-ico { font-size:17px; line-height:1.2; }
  .rcard.pass { border-color:rgba(52,211,153,.45); } .rcard.pass .r-ico { color:var(--ok); }
  .rcard.fail { border-color:rgba(248,113,113,.55); background:rgba(248,113,113,.06); }
  .rcard.fail .r-ico { color:var(--bad); }
  .rcard .r-title { font-weight:700; font-size:12.5px; }
  .rcard .r-sub { font-size:11.5px; color:var(--muted); margin-top:3px; line-height:1.5; }
  .decision-box { border:1px solid var(--border); border-radius:12px; padding:14px 18px;
                  background:var(--panel-2); margin-top:10px; }
  .decision-box.awaiting { border-color:rgba(251,191,36,.5);
                           background:linear-gradient(180deg,rgba(251,191,36,.06),var(--panel-2)); }
  .decision-box.ok { border-color:rgba(52,211,153,.5);
                     background:linear-gradient(180deg,rgba(52,211,153,.06),var(--panel-2)); }
  .decision-box.bad { border-color:rgba(248,113,113,.55);
                      background:linear-gradient(180deg,rgba(248,113,113,.07),var(--panel-2)); }
  .decision-box .d-head { display:flex; align-items:center; gap:9px; font-weight:700; font-size:13px; }
  .decision-box p { margin:7px 0 0; font-size:12.5px; color:#C3D0E8; line-height:1.55; }

  /* ---------- schedule popup ---------- */
  .sched-facts { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px;
                 margin-top:4px; }
  .sched-facts > div { background:#0A1220; border:1px solid var(--border); border-radius:10px;
                       padding:9px 13px; font-size:12.5px; }
  .sched-facts .k { font-size:9px; letter-spacing:.12em; text-transform:uppercase; color:var(--faint);
                    font-weight:700; margin-bottom:3px; }
  .sched-last { display:flex; gap:10px; align-items:center; flex-wrap:wrap; font-size:12px; margin-top:2px; }
  .sched-last .note { flex-basis:100%; color:var(--muted); font-size:11.5px; line-height:1.5; }
  .sched-form .sf-row { display:flex; align-items:center; justify-content:space-between; gap:14px;
                        padding:11px 0; border-bottom:1px solid var(--border); font-size:13px; }
  .sched-form .sf-row:last-of-type { border-bottom:none; }
  .sched-form .sf-hint { font-size:11.5px; color:var(--muted); line-height:1.55; margin:10px 0 0; }

  /* ---------- agentic AI avatar ---------- */
  .bot-avatar { width:104px; height:104px; }
  .bot-avatar svg { width:104px; height:104px; animation: botbob 3.4s ease-in-out infinite;
                    animation-play-state: paused; }
  .bot-avatar.working svg { animation-play-state: running; }
  .bot-avatar .orbit { transform-box: fill-box; transform-origin: center;
                       animation: orbitspin 22s linear infinite; animation-play-state: paused; }
  .bot-avatar .orbit.rev { animation: orbitspinrev 16s linear infinite; animation-play-state: paused; }
  .bot-avatar .core-pulse { animation: corepulse 3s ease-in-out infinite; animation-play-state: paused; }
  .bot-avatar.working .orbit { animation-duration: 6s; animation-play-state: running; }
  .bot-avatar.working .orbit.rev { animation-duration: 4.5s; animation-play-state: running; }
  .bot-avatar.working .core-pulse { animation-duration: 1.2s; animation-play-state: running; }
  .bot-avatar.working .bot-eye { animation: botblink 1.1s steps(2) infinite; }
  @keyframes botbob { 0%,100% { transform: translateY(0) rotate(0); } 50% { transform: translateY(-5px) rotate(1.2deg); } }
  @keyframes botblink { 0%,100% { ry: 5.5; } 50% { ry: 1.2; } }
  @keyframes orbitspin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  @keyframes orbitspinrev { from { transform: rotate(0deg); } to { transform: rotate(-360deg); } }
  @keyframes corepulse { 0%,100% { opacity: .55; } 50% { opacity: 1; } }
  .bot-caption { font-size:12px; color:var(--muted); margin-top:4px; text-align:center; max-width:150px; }

  /* ---------- agent mission / pipeline visuals ---------- */
  .mission { background:linear-gradient(135deg,rgba(91,138,255,.07),rgba(34,211,238,.04) 60%,transparent),
             var(--panel); border:1px solid var(--border); border-radius:var(--radius);
             padding:16px 20px; margin-bottom:16px; }
  .mission h3 { margin:0 0 6px; font-size:13px; color:var(--text); }
  .mission p { margin:0; font-size:12.5px; color:var(--muted); line-height:1.6; }
  .loop { display:flex; gap:0; align-items:stretch; margin:16px 0 18px; flex-wrap:wrap; }
  .loop-node { flex:1; min-width:118px; background:var(--panel); border:1px solid var(--border);
               border-radius:12px; padding:12px; text-align:center; position:relative; }
  .loop-node .ln-num { font-size:9px; letter-spacing:.14em; color:var(--accent); font-weight:700;
                       text-transform:uppercase; }
  .loop-node .ln-name { font-size:14px; font-weight:700; margin:3px 0 5px; }
  .loop-node .ln-desc { font-size:10.5px; color:var(--muted); line-height:1.45; }
  .loop-arrow { display:flex; align-items:center; padding:0 7px; color:var(--faint); font-size:17px; }
  .loop-node.human { border-color:rgba(251,191,36,.55);
                     background:linear-gradient(180deg,rgba(251,191,36,.07),var(--panel)); }
  .loop-node.human .ln-num { color:var(--warn); }
  .row-clickable { cursor:pointer; } .row-clickable:hover { background:rgba(91,138,255,.06); }
  .action-icon { display:inline-flex; width:30px; height:30px; border-radius:9px; align-items:center;
                 justify-content:center; font-size:14px; background:var(--panel-2);
                 border:1px solid var(--border); }
</style>
</head>
<body>
<nav>
  <div class="brand">
    <svg class="logo-mark" viewBox="0 0 48 48" role="img" aria-label="PIF logo">
      <defs>
        <linearGradient id="pifGrad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#3E6BFF"/><stop offset=".55" stop-color="#4F7CFF"/>
          <stop offset="1" stop-color="#18C7DE"/>
        </linearGradient>
        <radialGradient id="pifSheen" cx=".28" cy=".1" r=".95">
          <stop offset="0" stop-color="#ffffff" stop-opacity=".3"/>
          <stop offset=".55" stop-color="#ffffff" stop-opacity="0"/>
        </radialGradient>
      </defs>
      <rect x="1.5" y="1.5" width="45" height="45" rx="12.5" fill="url(#pifGrad)"/>
      <rect x="1.5" y="1.5" width="45" height="45" rx="12.5" fill="url(#pifSheen)"/>
      <rect x="2.4" y="2.4" width="43.2" height="43.2" rx="11.6" fill="none"
            stroke="#ffffff" stroke-opacity=".22" stroke-width="1.1"/>
      <!-- P — the prompt: its bowl holds a live terminal cursor -->
      <path d="M8.3 35.6V13.2h4.2a5.2 5.2 0 0 1 0 10.4h-4.2" fill="none" stroke="#F2F6FF"
            stroke-width="3.3" stroke-linecap="round" stroke-linejoin="round"/>
      <rect class="logo-cursor" x="11.6" y="16" width="2.9" height="4.7" rx="1" fill="#0B1B4D"/>
      <!-- I — sentence validation: proofreader's check above the stem -->
      <rect x="20.7" y="13.2" width="7.5" height="3.1" rx="1.55" fill="#F2F6FF"/>
      <rect x="22.85" y="13.2" width="3.2" height="22.4" rx="1.6" fill="#F2F6FF"/>
      <rect x="20.7" y="32.5" width="7.5" height="3.1" rx="1.55" fill="#F2F6FF"/>
      <path d="M25.7 8.9l2.1 2.3 4-4.6" fill="none" stroke="#3DE8A8" stroke-width="2.5"
            stroke-linecap="round" stroke-linejoin="round"/>
      <!-- F — the firewall: staggered brick arms -->
      <rect x="30.9" y="13.2" width="3.3" height="22.4" rx="1.4" fill="#F2F6FF"/>
      <rect x="35" y="13.2" width="3.3" height="3.1" rx=".9" fill="#F2F6FF"/>
      <rect x="39.1" y="13.2" width="2.3" height="3.1" rx=".9" fill="#A9C9FF"/>
      <rect x="35" y="19.5" width="2.1" height="3.1" rx=".9" fill="#A9C9FF"/>
      <rect x="37.9" y="19.5" width="3.5" height="3.1" rx=".9" fill="#F2F6FF"/>
    </svg>
    <div class="brand-text">
      <div class="brand-name">PIF <span>Admin</span></div>
      <div class="brand-sub">Prompt Injection Firewall</div>
    </div>
  </div>
  <div class="nav-label">Monitor</div>
  <button data-view="dashboard" class="active">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2.5-6.5L14 18.5 16.5 12H21"/></svg>
    <span>Dashboard &middot; Live</span></button>
  <button data-view="history">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3.2 2.2"/></svg>
    <span>Scan History</span></button>
  <button data-view="attackstats">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 20h18"/><rect x="5" y="12" width="3.4" height="8"/><rect x="10.3" y="8" width="3.4" height="12"/><rect x="15.6" y="4.5" width="3.4" height="15.5"/></svg>
    <span>Attack Stats</span></button>
  <div class="nav-label">Investigate</div>
  <button data-view="playground">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2.8v6.4L4.7 17.5a2.1 2.1 0 0 0 1.8 3.2h11a2.1 2.1 0 0 0 1.8-3.2L14 9.2V2.8"/><path d="M8.3 2.8h7.4"/><path d="M7.2 14.2h9.6"/></svg>
    <span>Manual Scan</span></button>
  <div class="nav-label">Configure</div>
  <button data-view="rules">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7.2h8.6M17.4 7.2H20"/><circle cx="15" cy="7.2" r="2.1"/><path d="M4 16.8h2.6M11.4 16.8H20"/><circle cx="9" cy="16.8" r="2.1"/></svg>
    <span>Rules &amp; Engines</span></button>
  <div class="nav-label">Automate</div>
  <button data-view="agent">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5.5" y="5.5" width="13" height="13" rx="2.5"/><rect x="9.8" y="9.8" width="4.4" height="4.4" rx="1"/><path d="M9.5 2.5v3M14.5 2.5v3M9.5 18.5v3M14.5 18.5v3M2.5 9.5h3M2.5 14.5h3M18.5 9.5h3M18.5 14.5h3"/></svg>
    <span>Agent Actions</span></button>
  <div class="nav-label">Configure</div>
  <button data-view="settings">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.1-1.55 1.7 1.7 0 0 0-1.88.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.55-1.1 1.7 1.7 0 0 0-.34-1.88l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.01a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.88-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.01a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.55 1z"/></svg>
    Settings</button>
  <div class="sysbox">
    <div class="sysbox-title">System</div>
    <div class="sysrow"><span class="dot" id="db-dot"></span><span class="syslabel">report.db</span><span class="sysval" id="db-size"></span></div>
    <div class="sysrow"><span class="dot" id="api-dot"></span><span class="syslabel">PIF API</span><span class="sysval">:8000</span></div>
  </div>
  <div class="nav-foot">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7.2 2.9v5.3c0 4.6-3.1 8.5-7.2 9.9-4.1-1.4-7.2-5.3-7.2-9.9V5.9L12 3z"/><path d="M9 11.8l2.2 2.2 4-4.4"/></svg>
    <span>PIF v3.0 &middot; Admin Console</span>
  </div>
</nav>
<main>

<section class="view active" id="view-dashboard">
  <div class="page-head">
    <div class="ph-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2.5-6.5L14 18.5 16.5 12H21"/></svg></div>
    <div class="ph-text">
      <h2>Live Telemetry</h2>
      <div class="ph-sub">Real-time decisions telemetry (new scans appear automatically).<br>Source: <span class="mono">report.db</span></div>
    </div>
    <div class="ph-actions">
      <button class="ghost" id="pause-btn">Pause</button>
      <button class="ghost" onclick="loadStats()">Refresh</button>
    </div>
  </div>
  <div class="cards" id="stat-cards"></div>
  <table id="live-table">
    <thead><tr><th>#</th><th>Time (UTC)</th><th>Decision</th><th>Risk</th>
    <th>Attacks</th><th>Attachments</th><th>Prompt</th></tr></thead>
    <tbody></tbody>
  </table>

  <div class="card" style="margin-top:16px" id="benchmarks-card">
    <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
      <span>Independent benchmarks &middot; attacks we did not write</span>
      <button class="ghost" style="padding:4px 10px;font-size:11px" onclick="loadBenchmarks()">Refresh</button>
    </div>
    <div id="benchmarks-body" class="muted" style="font-size:12px;padding:8px 2px">Loading…</div>
  </div>
</section>

<section class="view" id="view-history">
  <div class="page-head">
    <div class="ph-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3.2 2.2"/></svg></div>
    <div class="ph-text">
      <h2>Scan History</h2>
      <div class="ph-sub">Every scan recorded by the firewall — filter, search and open the full evidence trail.</div>
    </div>
  </div>
  <div class="toolbar">
    <select id="f-decision">
      <option value="">All decisions</option>
      <option>allow</option><option>sanitize</option><option>isolate</option>
      <option>block</option><option>error</option>
    </select>
    <input type="search" id="f-search" placeholder="Search scan_id or prompt..." style="width:280px">
    <button class="primary" onclick="loadHistory(0)">Apply</button>
    <span class="muted" id="h-count"></span>
    <span style="flex:1"></span>
    <label class="muted">Rows per page
      <select id="f-per-page" onchange="perPage = parseInt(this.value, 10); loadHistory(0)">
        <option>20</option><option selected>50</option><option>100</option><option>200</option>
        <option>500</option><option>1000</option><option>2000</option>
      </select></label>
    <button class="ghost" id="prev-btn" onclick="loadHistory(offset-perPage)">&laquo; Prev</button>
    <button class="ghost" id="next-btn" onclick="loadHistory(offset+perPage)">Next &raquo;</button>
  </div>
  <table id="history-table">
    <thead><tr><th>Time (UTC)</th><th>Scan ID</th><th>Decision</th><th>Risk</th><th>Level</th>
    <th>Scan Time</th><th>Findings</th><th>Attachments</th><th>Session</th><th>Prompt</th></tr></thead>
    <tbody></tbody>
  </table>
</section>

<section class="view" id="view-playground">
  <div class="page-head">
    <div class="ph-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2.8v6.4L4.7 17.5a2.1 2.1 0 0 0 1.8 3.2h11a2.1 2.1 0 0 0 1.8-3.2L14 9.2V2.8"/><path d="M8.3 2.8h7.4"/><path d="M7.2 14.2h9.6"/></svg></div>
    <div class="ph-text">
      <h2>Manual Scan</h2>
      <div class="ph-sub">Admin Manual Prompt Verification Tab – PIF API (POST /v1/scan)</div>
    </div>
  </div>
  <textarea id="pg-prompt" placeholder="Type the user prompt to scan..."></textarea>
  <div class="drop">
    <input type="file" id="pg-files" multiple>
    <div class="muted" style="margin-top:6px">One or more attachments (pdf, docx, html, json, md, txt, images...)</div>
  </div>
  <div class="filelist" id="pg-filelist"></div>
  <div class="toolbar" style="margin-top:14px">
    <button class="primary" id="pg-send" onclick="sendPlayground()">Send to Firewall</button>
    <span class="muted" id="pg-status"></span>
  </div>
  <div id="pg-result"></div>
</section>

<section class="view" id="view-rules">
  <div class="page-head">
    <div class="ph-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7.2h8.6M17.4 7.2H20"/><circle cx="15" cy="7.2" r="2.1"/><path d="M4 16.8h2.6M11.4 16.8H20"/><circle cx="9" cy="16.8" r="2.1"/></svg></div>
    <div class="ph-text">
      <h2>Rules &amp; Engines</h2>
      <div class="ph-sub">View all detection rules used by the firewall. Rules are managed through
      scripts and configuration files. Changes are applied automatically without restarting the
      firewall. Click any rule to view its details, purpose, detection pattern, and scan history.
      This page is read-only.</div>
    </div>
    <div class="ph-actions">
      <button class="ghost" onclick="loadRules()">Refresh</button>
    </div>
  </div>
  <div class="toolbar" style="margin-top:6px">
    <span class="muted" id="rules-count"></span>
  </div>
  <table class="rules" id="rules-table">
    <thead><tr><th>ID</th><th>Category</th><th>Sev</th><th>Weight</th><th>Rule</th></tr></thead>
    <tbody></tbody>
  </table>
</section>

<section class="view" id="view-agent">
  <div style="display:flex;gap:18px;align-items:flex-start">
    <div>
      <div class="bot-avatar" id="bot-avatar">
        <!-- mech bot: plastic shading via gradients; 'paused' stops the idle bob until the agent works -->
        <svg viewBox="0 0 100 100" aria-label="agentic AI avatar">
          <defs>
            <radialGradient id="aiGlow" cx=".5" cy=".5" r=".5">
              <stop offset="0" stop-color="#3E6BFF" stop-opacity=".45"></stop>
              <stop offset=".55" stop-color="#3E6BFF" stop-opacity=".14"></stop>
              <stop offset="1" stop-color="#3E6BFF" stop-opacity="0"></stop>
            </radialGradient>
            <linearGradient id="aiCore" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stop-color="#5B8CFF"></stop><stop offset=".5" stop-color="#3E6BFF"></stop>
              <stop offset="1" stop-color="#22D3EE"></stop>
            </linearGradient>
            <radialGradient id="aiCoreGloss" cx=".32" cy=".25" r=".75">
              <stop offset="0" stop-color="#ffffff" stop-opacity=".5"></stop>
              <stop offset=".45" stop-color="#ffffff" stop-opacity=".06"></stop>
              <stop offset="1" stop-color="#ffffff" stop-opacity="0"></stop>
            </radialGradient>
          </defs>

          <!-- soft ambient glow -->
          <circle cx="50" cy="50" r="46" fill="url(#aiGlow)"></circle>

          <!-- outer orbit: dashed ring + two satellites -->
          <g class="orbit">
            <ellipse cx="50" cy="50" rx="42" ry="17" fill="none" stroke="#5B8CFF" stroke-opacity=".45" stroke-width="1.4" stroke-dasharray="5 6" transform="rotate(-18 50 50)"></ellipse>
            <circle cx="90" cy="38" r="3.4" fill="#22D3EE"></circle>
            <circle cx="90" cy="38" r="6" fill="#22D3EE" opacity=".25"></circle>
            <circle cx="12" cy="63" r="2.6" fill="#8B5CF6"></circle>
          </g>

          <!-- inner orbit: solid ring + one satellite, counter-rotating -->
          <g class="orbit rev">
            <ellipse cx="50" cy="50" rx="30" ry="30" fill="none" stroke="#A9C9FF" stroke-opacity=".35" stroke-width="1.2"></ellipse>
            <circle cx="50" cy="20" r="2.8" fill="#A9C9FF"></circle>
            <circle cx="50" cy="20" r="5" fill="#A9C9FF" opacity=".2"></circle>
          </g>

          <!-- neural spokes: core to orbit anchors -->
          <g stroke="#5B8CFF" stroke-opacity=".4" stroke-width="1.1">
            <line x1="50" y1="50" x2="86" y2="30"></line>
            <line x1="50" y1="50" x2="20" y2="72"></line>
            <line x1="50" y1="50" x2="50" y2="22"></line>
          </g>

          <!-- pulsing halo + core -->
          <circle class="core-pulse" cx="50" cy="50" r="21" fill="#3E6BFF" opacity=".4"></circle>
          <circle cx="50" cy="50" r="16.5" fill="url(#aiCore)" stroke="#1c2129" stroke-opacity=".6" stroke-width="1.6"></circle>
          <circle cx="50" cy="50" r="16.5" fill="url(#aiCoreGloss)"></circle>

          <!-- the AI eye -->
          <circle class="bot-eye" cx="50" cy="50" r="5.5" fill="#EAF2FF"></circle>
          <circle cx="50" cy="50" r="2.2" fill="#3E6BFF"></circle>
        </svg>
      </div>
      <div class="bot-caption" id="bot-caption">Agent paused<br>Awaiting your decision</div>
    </div>
    <div style="flex:1">
      <h2>Self-Tuning Agent <span class="muted" style="font-weight:400;font-size:14px">pif/agenticai_redteam.py — supervised autonomous maintenance</span></h2>
      <div class="mission">
        <h3>Purpose</h3>
        <p>The Self-Tuning Agent analyzes firewall decisions to identify cases where safe content is
           incorrectly blocked. It tests potential fixes using a separate test environment and suggests
           rule-weight adjustments for approval. The agent cannot directly modify production rules;
           <b style="color:#FBBF24">all changes require human approval.</b></p>
      </div>
    </div>
    <div style="margin-left:auto;display:flex;gap:10px;align-items:center;padding-top:6px;flex-shrink:0">
      <span class="badge" id="sched-btn-status" style="--bc:#8CA0BF">—</span>
      <button class="ghost" onclick="showScheduleModal()">⏰ Schedule</button>
    </div>
  </div>

  <div class="loop">
    <div class="loop-node"><div class="ln-num">1 · Perceive</div><div class="ln-name">Measure</div>
      <div class="ln-desc">scan benign + attack samples with the live firewall; read rule analytics</div></div>
    <div class="loop-arrow">→</div>
    <div class="loop-node"><div class="ln-num">2 · Plan</div><div class="ln-name">Target</div>
      <div class="ln-desc">rank Stage-1 rules that actually blocked benign records (decision-level FP)</div></div>
    <div class="loop-arrow">→</div>
    <div class="loop-node"><div class="ln-num">3 · Act</div><div class="ln-name">Shadow</div>
      <div class="ln-desc">re-scan only affected records on a copy of the firewall with a lower weight</div></div>
    <div class="loop-arrow">→</div>
    <div class="loop-node"><div class="ln-num">4 · Verify</div><div class="ln-name">Gate</div>
      <div class="ln-desc">two gates: no benign regression, no attack newly allowed</div></div>
    <div class="loop-arrow">→</div>
    <div class="loop-node human"><div class="ln-num">5 · Human gate</div><div class="ln-name">You</div>
      <div class="ln-desc">approve merges to production · reject is remembered forever</div></div>
  </div>

  <div class="cards" id="agent-cards"></div>
  <div id="agent-prerun"></div>
  <div class="toolbar">
    <select id="agent-corpus">
      <option value="demo">Demo corpus (fast, redteam_demo)</option>
      <option value="full">Full held-out corpus (data/processed/eval_full.jsonl)</option>
    </select>
    <button class="primary" id="agent-tune-btn" onclick="showTunePlan()">Run Tune Cycle</button>
    <span class="muted" id="agent-status"></span>
    <span style="flex:1"></span>
    <button class="ghost" onclick="loadAgent()">Refresh</button>
  </div>
  <div id="agent-policy"></div>
  <h3 style="margin:20px 0 10px;font-size:15px">Agent actions <span class="muted">(click any action for full context — proposals, verdicts, attempts)</span></h3>
  <div class="muted" style="margin:-4px 0 12px;font-size:12px;line-height:1.9">
    <div>· <b style="color:#FBBF24;display:inline-block;width:92px">PENDING</b> = proposal parked in reports/redteam/pending_overrides.json, production untouched</div>
    <div>· <b style="color:#34D399;display:inline-block;width:92px">APPROVED</b> = re-verified and merged into conf/policy-overrides.json</div>
    <div>· <b style="color:#F87171;display:inline-block;width:92px">ROLLBACK</b> = approved but verification failed, file change auto-reverted</div>
    <div>· <b style="color:#8CA0BF;display:inline-block;width:92px">REJECTED</b> = declined, never re-proposed</div>
  </div>
  <table id="agent-actions-table">
    <thead><tr><th></th><th>Action</th><th>Rule</th><th>Stage</th><th>Change</th>
    <th>Benign blocked</th><th>Status</th><th>When</th></tr></thead>
    <tbody></tbody>
  </table>
  <h3 style="margin:20px 0 10px;font-size:15px">Cycle history</h3>
  <table id="agent-cycles">
    <thead><tr><th>Cycle</th><th>Targets</th><th>Rule</th><th>Victims</th>
    <th>Ladder attempts</th><th>Pending / Outcome</th></tr></thead>
    <tbody></tbody>
  </table>
  <details style="margin-top:16px"><summary>Failed hypotheses (never retried)</summary>
    <div id="agent-failed"></div>
  </details>
</section>

<section class="view" id="view-attackstats">
  <div class="page-head">
    <div class="ph-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 20h18"/><rect x="5" y="12" width="3.4" height="8"/><rect x="10.3" y="8" width="3.4" height="12"/><rect x="15.6" y="4.5" width="3.4" height="15.5"/></svg></div>
    <div class="ph-text">
      <h2>Attack Stats</h2>
      <div class="ph-sub">Attack patterns for a selected date/time range: types, frequency, and when they occur. Data comes from the live report.db — every scan the firewall has recorded.</div>
    </div>
  </div>
  <div class="toolbar" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:6px 0 12px">
    <label class="muted" style="font-size:11px">From <input type="date" id="stats-from" class="mono" style="background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:5px 8px;font-size:12px"></label>
    <label class="muted" style="font-size:11px">To <input type="date" id="stats-to" class="mono" style="background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:5px 8px;font-size:12px"></label>
    <button class="ghost" style="padding:5px 12px;font-size:11px" onclick="loadAttackStats()">Apply</button>
    <button class="ghost" style="padding:5px 12px;font-size:11px" onclick="statsPreset(1)">24h</button>
    <button class="ghost" style="padding:5px 12px;font-size:11px" onclick="statsPreset(7)">7d</button>
    <button class="ghost" style="padding:5px 12px;font-size:11px" onclick="statsPreset(30)">30d</button>
    <button class="ghost" style="padding:5px 12px;font-size:11px" onclick="statsPreset(0)">All time</button>
    <span class="muted" id="attackstats-status" style="font-size:11px"></span>
  </div>
  <div id="attackstats-summary" style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px"></div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;align-items:start">
    <div class="card"><div class="card-title">Attacks by type</div><div id="chart-categories"></div></div>
    <div class="card"><div class="card-title">Attacks by hour of day</div><div id="chart-hours"></div></div>
    <div class="card"><div class="card-title">Scans per day (by decision)</div><div id="chart-days"></div></div>
    <div class="card"><div class="card-title">Top fired rules</div><div id="chart-rules"></div></div>
    <div class="card"><div class="card-title">Attacks by source channel</div><div id="chart-sources"></div></div>
    <div class="card"><div class="card-title">Attacks by file type</div><div id="chart-filetypes"></div></div>
  </div>
</section>

<section class="view" id="view-settings">
  <div class="page-head">
    <div class="ph-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.1-1.55 1.7 1.7 0 0 0-1.88.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.55-1.1 1.7 1.7 0 0 0-.34-1.88l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.01a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.88-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.01a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.55 1z"/></svg></div>
    <div class="ph-text">
      <h2>Settings</h2>
      
    </div>
    <div class="ph-actions">
      <button class="ghost" onclick="loadSettings()">Refresh</button>
    </div>
  </div>
  <div class="toolbar" style="margin-top:6px">
    <span class="muted" id="settings-status"></span>
  </div>
  <div id="settings-groups"></div>
</section>

</main>

<div class="modal-bg" id="modal-bg" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <button class="close" onclick="closeModal()">&times;</button>
    <h3 id="m-title"></h3>
    <div class="muted mono" id="m-sub"></div>
    <div class="tabs" id="m-tabs"></div>
    <div id="m-body"></div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const badge = d => `<span class="badge" style="--bc:${{
  allow:"#34D399",sanitize:"#FBBF24",isolate:"#FB923C",block:"#F87171",error:"#8CA0BF"}[d]||"#8CA0BF"}">${esc(d).toUpperCase()}</span>`;
const short = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + "…" : s; };

let lastId = 0, paused = false, offset = 0, perPage = 50;

function switchView(name) {
  const btn = document.querySelector(`nav button[data-view="${name}"]`);
  if (!btn) return false;
  document.querySelectorAll("nav button[data-view]").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  $("view-" + name).classList.add("active");
  if (name === "history") loadHistory(offset);
  if (name === "attackstats") loadAttackStats();
  if (name === "dashboard") { loadStats(); loadBenchmarks(); }
  if (name === "rules") loadRules();
  if (name === "agent") loadAgent();
  if (name === "settings") loadSettings();
  return true;
}
document.querySelectorAll("nav button[data-view]").forEach(btn => btn.onclick = () => {
  switchView(btn.dataset.view);
  history.replaceState(null, "", "#" + btn.dataset.view);
});
/* survive reloads: the active view lives in the URL hash (e.g. /#agent) */
if (!switchView(location.hash.replace("#", ""))) switchView("dashboard");

/* Generic modal: any view (scan, agent action) builds tabs + panes itself. */
let modalTabs = [];
function openModal(title, sub, tabs) {
  modalTabs = tabs;   // [{id, label, html}]
  $("m-title").innerHTML = title;
  $("m-sub").innerHTML = sub || "";
  $("m-tabs").innerHTML = tabs.map((t, i) =>
    `<button class="${i === 0 ? "active" : ""}" data-pane="${t.id}" onclick="switchTab(this)">${esc(t.label)}</button>`).join("");
  $("m-body").innerHTML = tabs.map((t, i) =>
    `<div class="tabpane ${i === 0 ? "active" : ""}" id="${t.id}">${t.html}</div>`).join("");
  $("modal-bg").classList.add("open");
}
function switchTab(btn) {
  $("m-tabs").querySelectorAll("button").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  $("m-body").querySelectorAll(".tabpane").forEach(p => p.classList.remove("active"));
  $(btn.dataset.pane).classList.add("active");
}

async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || ("HTTP " + response.status));
  return body;
}


/* ---------------- Attack Stats page (v6.3) ---------------- */
function svgBarChart(rows, options) {
  const max = Math.max(1, ...rows.map(r => r.value));
  const targetH = (options && options.targetH) || rows.length * 29 + 6;
  const gap = 7;
  const barH = Math.max(14, Math.min(44, targetH / rows.length - gap));
  const labelW = 150, valueW = 46;
  const height = rows.length * (barH + gap) + 6;
  const width = 560;
  const bars = rows.map((r, i) => {
    const w = Math.max(2, Math.round((width - labelW - valueW) * r.value / max));
    const y = i * (barH + gap) + 4;
    const color = r.color || "#5B8AFF";
    return `<text x="${labelW - 8}" y="${y + barH / 2 + 4}" text-anchor="end" font-size="11" fill="#9aa7b8">${esc(String(r.label).slice(0, 26))}</text>` +
           `<rect x="${labelW}" y="${y}" width="${w}" height="${barH}" rx="4" fill="${color}" opacity=".85"></rect>` +
           `<text x="${labelW + w + 6}" y="${y + barH / 2 + 4}" font-size="11" fill="#cdd7e3">${r.value}</text>`;
  }).join("");
  return `<svg viewBox="0 0 ${width} ${height}" style="width:100%;height:auto">${bars}</svg>`;
}

function svgColumnChart(columns, options) {
  const max = Math.max(1, ...columns.map(c => c.total));
  const plotH = (options && options.plotH) || 150;
  const height = (options && options.totalH) || plotH + 40;
  const width = 560;
  const colW = Math.min(64, Math.floor((width - 40) / Math.max(columns.length, 1)) - 6);
  const labelStep = Math.max(1, Math.ceil(columns.length / 12));
  const bars = columns.map((c, i) => {
    const x = 30 + i * (colW + 6);
    let y = plotH;
    const segs = c.segments.map(s => {
      const h = Math.round(plotH * s.value / max);
      y -= h;
      return `<rect x="${x}" y="${y}" width="${colW}" height="${h}" fill="${s.color}" opacity=".88"></rect>`;
    }).join("");
    const label = (i % labelStep === 0 || i === columns.length - 1)
      ? `<text x="${x + colW / 2}" y="${plotH + 14}" text-anchor="middle" font-size="9" fill="#9aa7b8">${esc(c.label)}</text>` : "";
    return segs + label + (c.total ? `<text x="${x + colW / 2}" y="${y - 4}" text-anchor="middle" font-size="9" fill="#cdd7e3">${c.total}</text>` : "");
  }).join("");
  return `<svg viewBox="0 0 ${width} ${height + 20}" style="width:100%;height:auto">
    <line x1="28" y1="${plotH}" x2="${width - 8}" y2="${plotH}" stroke="rgba(255,255,255,.15)"></line>${bars}</svg>`;
}

const ATTACK_COLORS = {
  instruction_override: "#5B8AFF", role_change: "#8B5CF6", secret_extraction: "#22D3EE",
  tool_abuse: "#F59E0B", credential_theft: "#F87171", context_poisoning: "#A78BFA",
  multi_step_jailbreak: "#F472B6", encoded_instruction: "#34D399", indirect_injection: "#FB923C",
};

async function loadAttackStats() {
  const status = $("attackstats-status");
  const from = $("stats-from").value, to = $("stats-to").value;
  try {
    const params = new URLSearchParams();
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const data = await api("/api/stats/range" + (params.toString() ? "?" + params.toString() : ""));
    const t = data.totals;
    $("attackstats-summary").innerHTML = [
      ["Total scans", t.total, ""], ["Blocked", t.blocked, "#F87171"], ["Sanitized", t.sanitized, "#FBBF24"],
      ["Isolated", t.isolated, "#FB923C"], ["Allowed", t.allowed, "#34D399"],
      ["Avg risk", t.avg_risk ?? "—", "#5B8AFF"], ["Max risk", t.max_risk ?? "—", "#F87171"],
    ].map(([lbl, num, color]) =>
      `<div class="card" style="min-width:110px;text-align:center;padding:10px 14px">
         <div class="num" style="color:${color || "var(--text)"}">${num ?? 0}</div><div class="lbl">${lbl}</div></div>`).join("");

    const catRows = data.by_category.map(row => ({
      label: row.category.replace(/_/g, " "),
      value: row.hits,
      color: ATTACK_COLORS[row.category] || "#5B8AFF",
    }));
    $("chart-categories").innerHTML = catRows.length
      ? svgBarChart(catRows)
      : '<p class="muted" style="padding:8px">No attacks recorded in this range.</p>';

    const hourMap = Object.fromEntries(data.by_hour.map(r => [r.hour, r.hits]));
    const hourCols = Array.from({ length: 24 }, (_, h) => ({
      label: String(h).padStart(2, "0"),
      total: hourMap[h] || 0,
      segments: [{ value: hourMap[h] || 0, color: "#5B8AFF" }],
    }));
    $("chart-hours").innerHTML = data.by_hour.length ? svgColumnChart(hourCols, { plotH: 240, totalH: 264 }) : '<p class="muted" style="padding:8px">No attacks recorded in this range.</p>';

    const dayCols = data.by_day.map(d => ({
      label: d.day.slice(5),
      total: d.total,
      segments: [
        { value: d.blocked, color: "#F87171" },
        { value: d.sanitized, color: "#FBBF24" },
        { value: d.isolated, color: "#FB923C" },
        { value: d.allowed, color: "#34D399" },
      ],
    }));
    $("chart-days").innerHTML = dayCols.length ? svgColumnChart(dayCols, { plotH: 240, totalH: 296 }) : '<p class="muted" style="padding:8px">No scans recorded in this range.</p>';

    $("chart-rules").innerHTML = data.top_rules.length
      ? `<table><thead><tr><th>Rule</th><th>Category</th><th>Hits</th></tr></thead><tbody>` +
        data.top_rules.map(r => `<tr><td class="mono">${esc(r.rule_id)}</td><td>${esc(r.category || "")}</td><td>${r.hits}</td></tr>`).join("") +
        `</tbody></table>`
      : '<p class="muted" style="padding:8px">No rules fired in this range.</p>';

    const FILETYPE_LABELS = {
      pdf: "PDF", docx: "Word (DOCX)", eml: "Email (EML)", html: "HTML",
      png: "Image (PNG)", jpg: "Image (JPG)", jpeg: "Image (JPEG)", webp: "Image (WebP)",
      gif: "Image (GIF)", json: "JSON", md: "Markdown", txt: "Text",
    };
    const sourceRows = data.by_source.map(row => ({
      label: (row.src || "unknown").replace(/_/g, " "),
      value: row.hits,
      color: row.src === "user" ? "#F87171" : row.src === "ocr" ? "#22D3EE" : "#5B8AFF",
    }));
    $("chart-sources").innerHTML = sourceRows.length
      ? svgBarChart(sourceRows, { targetH: 300 })
      : '<p class="muted" style="padding:8px">No findings in this range.</p>';

    const fileTypeRows = data.by_filetype.map(row => ({
      label: FILETYPE_LABELS[row.filetype] || row.filetype,
      value: row.hits,
      color: ["pdf", "docx", "eml"].includes(row.filetype) ? "#F59E0B"
           : ["png", "jpg", "jpeg", "webp", "gif"].includes(row.filetype) ? "#22D3EE"
           : "#5B8AFF",
    }));
    $("chart-filetypes").innerHTML = fileTypeRows.length
      ? svgBarChart(fileTypeRows, { targetH: 300 })
      : '<p class="muted" style="padding:8px">No file-based attacks in this range.</p>';

    status.textContent = `${t.total} scans · ${data.by_category.reduce((n, r) => n + r.hits, 0)} attack findings in range`;
  } catch (e) {
    status.innerHTML = `<span class="error-box" style="display:block">Cannot load attack stats: ${esc(e.message)}</span>`;
  }
}

function statsPreset(days) {
  const to = new Date();
  const from = new Date(to.getTime() - (days || 3650) * 86400000);
  $("stats-to").value = to.toISOString().slice(0, 10);
  if (days) $("stats-from").value = from.toISOString().slice(0, 10);
  else $("stats-from").value = "";
  loadAttackStats();
}

/* ---------------- Independent benchmarks card (v6.3) ---------------- */
async function loadBenchmarks() {
  const body = $("benchmarks-body");
  if (!body) return;
  try {
    const data = await api("/api/benchmarks");
    let html = "";
    if (data.ablation && data.ablation.columns && data.ablation.columns.length) {
      html += `<table style="margin:6px 0 10px"><thead><tr><th>Defense layer</th><th>Independent recall</th><th>Benign FPR</th></tr></thead><tbody>` +
        data.ablation.columns.map(c =>
          `<tr><td>${esc(c.config)}</td><td><b>${c.aggregate.recall ?? "—"}</b></td><td>${c.aggregate.fpr ?? "—"}</td></tr>`).join("") +
        `</tbody></table>`;
      if (data.ablation.judge_column && String(data.ablation.judge_column).indexOf("unavailable") === 0) {
        html += `<div class="muted" style="font-size:10.5px;margin-bottom:8px">LLM-judge column: ${esc(data.ablation.judge_column)}</div>`;
      }
    }
    if (data.public && data.public.datasets && Object.keys(data.public.datasets).length) {
      html += `<table><thead><tr><th>Frozen public dataset</th><th>Rows</th><th>Recall</th><th>Benign FPR</th></tr></thead><tbody>` +
        Object.entries(data.public.datasets).map(([slug, e]) =>
          `<tr><td class="mono" style="font-size:11px">${esc(slug)}</td><td>${e.samples}</td>` +
          `<td>${e.attack_recall ?? "—"}</td><td>${e.benign_fpr ?? "—"}</td></tr>`).join("") +
        `</tbody></table>`;
      const frozen = Object.values(data.public.freeze_manifest || {});
      if (frozen.length) {
        html += `<div class="muted" style="font-size:10.5px;margin-top:6px">splits sha256-frozen ${esc(frozen[0].frozen_at)} · every miss published in reports/evaluation_public_misses.json</div>`;
      }
    }
    if (data.internal) {
      const gate = data.internal.release_gate;
      html += `<div class="muted" style="font-size:10.5px;margin-top:8px">Internal regression corpus (self-authored, circular by construction): recall ${data.internal.attack_recall ?? "—"} / FPR ${data.internal.benign_fpr ?? "—"} — release gate ${gate ? "passed" : "not passed"}.</div>`;
    }
    if (!html) html = "No benchmark reports found — run scripts/build_public_eval.py and scripts/ablation.py.";
    body.innerHTML = html;
  } catch (e) {
    body.innerHTML = `<span class="error-box" style="display:block">Cannot load benchmarks: ${esc(e.message)}</span>`;
  }
}

/* Showcase badges (v6.3): make the invisible defenses visible — behavioral
   detonation evidence and hidden-channel forensics on every finding row. */
function findingBadges(f) {
  let html = "";
  const locator = f.locator || "";
  if ((f.rule_id || "") === "DETONATION-001") {
    const evidence = f.evidence || "";
    const signals = evidence.match(/signals=\[([^\]]*)\]/);
    const decoy = evidence.match(/decoy=(\w+)/);
    html += `<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:5px;align-items:center">` +
      `<span class="badge" style="--bc:#22D3EE;font-size:9px">BEHAVIORAL · decoy detonation</span>` +
      (decoy ? `<span class="muted" style="font-size:9px">decoy: ${esc(decoy[1])}</span>` : "") +
      `</div>`;
    if (signals && signals[1]) {
      html += `<div class="mono" style="font-size:9.5px;color:#67E8F9;margin-top:2px">observed: ${esc(signals[1].split(",").join(" · "))}</div>`;
    }
  }
  if (/^(hidden_css:|comment:|pdf_white:|pdf_tiny:|pdf_offpage:|pdf_render_diff:|docx_hidden:|ocr_faint:)/.test(locator)) {
    html += `<div style="margin-top:4px"><span class="badge" style="--bc:#F59E0B;font-size:9px">HIDDEN CHANNEL · extracted by forensics</span></div>`;
  }
  return html;
}

async function loadStats() {
  try {
    const stats = await api("/api/stats");
    const cards = [
      ["Total Scans", stats.total, ""],
      ["Allowed", stats.by_decision.allow || 0, "#34D399"],
      ["Sanitized", stats.by_decision.sanitize || 0, "#FBBF24"],
      ["Isolated", stats.by_decision.isolate || 0, "#FB923C"],
      ["Blocked", stats.by_decision.block || 0, "#F87171"],
      ["Findings", stats.findings, "#5B8AFF"],
    ];
    $("stat-cards").innerHTML = cards.map(([lbl, num, color]) =>
      `<div class="card"><div class="num"${color ? ` style="color:${color}"` : ""}>${num ?? 0}</div>
       <div class="lbl">${lbl}</div></div>`).join("");
  } catch (e) { $("stat-cards").innerHTML = `<div class="error-box">report.db unavailable: ${esc(e.message)}</div>`; }
}

function liveRow(r) {
  const prompt = r.user_prompt || "(no prompt)";
  const shown = r.malicious === 1
    ? `<span style="color:#F87171" title="malicious prompt">${esc(short(prompt, 90))}</span>`
    : esc(short(prompt, 90));
  return `<tr class="clickable" onclick="showScan('${r.scan_id}')">
    <td>${r.id}</td><td class="mono">${esc(short(r.ts, 19))}</td><td>${badge(r.decision)}</td>
    <td>${r.risk ?? "—"}</td>
    <td>${(r.attacks || []).map(a => `<span class="chip">${esc(a)}</span>`).join("") || "—"}</td>
    <td>${r.file_count || 0}</td><td>${shown}</td></tr>`;
}

async function pollLive() {
  if (paused) return;
  try {
    const data = await api("/api/live?after_id=" + lastId);
    if (data.rows.length) {
      lastId = data.rows[0].id;   // rows come newest-first
      const tbody = $("live-table").querySelector("tbody");
      tbody.insertAdjacentHTML("afterbegin", data.rows.map(liveRow).join(""));
      while (tbody.rows.length > 200) tbody.deleteRow(-1);
    }
  } catch (e) { /* db not created yet — retry next tick */ }
}

$("pause-btn").onclick = () => {
  paused = !paused;
  $("pause-btn").textContent = paused ? "Resume" : "Pause";
};

async function initLive() {
  try {
    const data = await api("/api/live?after_id=0&limit=25");
    if (data.rows.length) {
      lastId = data.rows[0].id;
      $("live-table").querySelector("tbody").innerHTML = data.rows.map(liveRow).join("");
    }
  } catch (e) {}
}

async function loadHistory(newOffset) {
  offset = Math.max(0, newOffset === undefined ? offset : newOffset);
  const decision = $("f-decision").value;
  const search = $("f-search").value.trim();
  const params = new URLSearchParams({ limit: String(perPage), offset: String(offset) });
  if (decision) params.set("decision", decision);
  if (search) params.set("search", search);
  try {
    const data = await api("/api/scans?" + params);
    $("history-table").querySelector("tbody").innerHTML = data.rows.map(r =>
      `<tr class="clickable" onclick="showScan('${r.scan_id}')">
       <td class="mono">${esc(short(r.ts, 19))}</td><td class="mono">${esc(short(r.scan_id, 13))}…</td>
       <td>${badge(r.decision)}</td><td>${r.risk ?? "—"}</td><td>${esc(r.risk_level || "")}</td>
       <td class="mono">${r.duration_ms != null ? Math.round(r.duration_ms) + " ms" : "—"}</td>
       <td>${r.finding_count}</td><td>${r.file_count || 0}</td>
       <td class="mono">${esc(short(r.session_id || "—", 12))}</td>
       <td>${r.malicious === 1
          ? `<span style="color:#F87171" title="malicious prompt">${esc(short(r.user_prompt, 70))}</span>`
          : esc(short(r.user_prompt, 70))}</td></tr>`).join("")
      || '<tr><td colspan="10" class="muted">No scans match.</td></tr>';
    $("h-count").textContent = `${data.total} total, showing ${offset + 1}–${offset + data.rows.length}`;
    $("prev-btn").disabled = offset === 0;
    $("next-btn").disabled = offset + perPage >= data.total;
  } catch (e) {
    $("history-table").querySelector("tbody").innerHTML =
      `<tr><td colspan="10" class="error-box">report.db unavailable: ${esc(e.message)}</td></tr>`;
  }
}

async function showScan(scanId) {
  try {
    const row = await api("/api/scans/" + scanId);
    const kv = [
      ["Status", esc(row.status || "")], ["Malicious", row.malicious === null ? "—" : row.malicious],
      ["Risk", `${row.risk ?? "—"} (${esc(row.risk_level || "")})`],
      ["Attacks", (row.attacks || []).map(a => `<span class="chip">${esc(a)}</span>`).join("") || "—"],
      ["Warnings", (row.warnings || []).join(", ") || "—"],
      ["Quarantined", (row.quarantined || []).join(", ") || "—"],
      ["Attachments", esc((row.file_names || []).join(", ") || "none")],
      ["Prompt chars", row.prompt_chars], ["Scan Time", row.duration_ms ? row.duration_ms + " ms" : "—"],
      ["Detector", `${esc(row.detector_version || "")} · ${esc(row.coverage || "")}`],
    ];
    const badPrompt = row.malicious === 1 || row.decision === "block";
    const promptText = (row.user_prompt || "").trim();
    // Sanitized output (v6.3): what the firewall actually forwarded downstream
    // after span redaction + survivor spotlighting — shown beside the flagged
    // prompt so the neutralization is visible, not just the detection.
    let forwarded = "";
    try {
      const result = JSON.parse(row.result_json || "{}");
      forwarded = (result.safe_content || [])
        .filter(segment => segment.source_id === "user")
        .map(segment => segment.text)
        .join("\\n");
    } catch (e) { /* malformed result_json — skip the block */ }
    const sanitizedBlock = row.decision === "sanitize" && forwarded
      ? `<div style="margin-top:14px">
           <div class="muted" style="margin-bottom:6px;color:#34D399">✓ sanitized prompt — forwarded downstream (spotlighted)</div>
           <pre style="border-color:rgba(52,211,153,.45);background:rgba(52,211,153,.07);color:#6EE7B7">${esc(forwarded)}</pre>
         </div>`
      : "";
    const summaryHtml = `<div class="kv">${kv.map(([k, v]) =>
      `<div class="k">${k}</div><div>${v}</div>`).join("")}</div>
      <div style="margin-top:16px">
        <div class="muted" style="margin-bottom:6px">${badPrompt && promptText ? "⚠ malicious prompt" : "prompt"}</div>
        <pre${badPrompt && promptText ? ' style="border-color:rgba(248,113,113,.45);background:rgba(248,113,113,.07);color:#FCA5A5"' : ""}>${esc(promptText || "(no prompt submitted)")}</pre>
      </div>${sanitizedBlock}`;
    const findingsHtml = row.findings.length ? `<table><thead><tr>
      <th>Category</th><th>ID</th><th>Rule</th><th>Source</th><th>Layer</th><th>Severity</th>
      <th>Evidence</th></tr></thead><tbody>${row.findings.map(f =>
      `<tr><td>${esc(f.category)}${findingBadges(f)}</td><td>${f.category_id}</td><td class="mono">${esc(f.rule_id || "—")}</td>
       <td class="mono">${esc(f.source_id)}${/^(hidden_css:|comment:|pdf_white:|pdf_tiny:|pdf_offpage:|pdf_render_diff:|docx_hidden:|ocr_faint:)/.test(f.locator || "") ? `<div class="muted" style="font-size:9px">${esc(f.locator)}</div>` : ""}</td><td>${esc(f.layer)}</td><td>${f.severity}</td>
       <td class="mono">${esc(short(f.evidence, 120))}</td></tr>`).join("")}</tbody></table>`
      : '<p class="muted">No findings recorded for this scan.</p>';
    try { await getPolicyData(); } catch (e) { /* rule details degrade gracefully */ }
    openModal(
      `${badge(row.decision)} <span class="mono" style="font-size:14px">${esc(row.scan_id)}</span>`,
      `${esc(row.ts)}  ·  owner=${esc(row.owner || "?")}  ·  request_id=${esc(row.request_id || "—")}`,
      [
        { id: "p-summary", label: "Summary", html: summaryHtml },
        { id: "p-findings", label: "Findings", html: findingsHtml },
        { id: "p-request", label: "Request JSON",
          html: `<pre>${esc(JSON.stringify(JSON.parse(row.request_json || "{}"), null, 2))}</pre>` },
        { id: "p-result", label: "Result JSON",
          html: `<pre>${esc(JSON.stringify(JSON.parse(row.result_json || "{}"), null, 2))}</pre>` },
      ],
    );
  } catch (e) { alert("Failed to load scan: " + e.message); }
}

function closeModal() { $("modal-bg").classList.remove("open"); }
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

$("pg-files").addEventListener("change", () => {
  $("pg-filelist").innerHTML = [...$("pg-files").files]
    .map(f => `<div>📎 ${esc(f.name)} <span class="mono">(${f.size} bytes)</span></div>`).join("");
});

function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result.split(",", 2)[1]);
    reader.onerror = () => reject(new Error("Cannot read " + file.name));
    reader.readAsDataURL(file);
  });
}

async function sendPlayground() {
  const button = $("pg-send"), status = $("pg-status");
  button.disabled = true; status.textContent = "Scanning...";
  $("pg-result").innerHTML = "";
  try {
    const files = [];
    for (const file of $("pg-files").files) {
      files.push({ name: file.name, type: file.type || "application/octet-stream",
                   data_base64: await readAsBase64(file) });
    }
    const data = await api("/api/validate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: $("pg-prompt").value, files }),
    });
    renderPlayground(data);
    // the firewall writes duration + timestamp to report.db before the API responds
    if (data.result && data.result.scan_id) {
      try {
        const row = await api("/api/scans/" + data.result.scan_id);
        if (document.getElementById("pg-scantime"))
          document.getElementById("pg-scantime").textContent =
            row.duration_ms != null ? row.duration_ms + " ms" : "—";
        if (document.getElementById("pg-scannedat"))
          document.getElementById("pg-scannedat").textContent =
            row.ts ? row.ts.replace("T", " ").slice(0, 19) + " UTC" : "—";
      } catch (e) { /* scan row not readable yet */ }
    }
    status.textContent = "Done.";
    setTimeout(pollLive, 600);   // the new scan should surface in the live feed
  } catch (e) {
    $("pg-result").innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
    status.textContent = "";
  } finally { button.disabled = false; }
}

function renderPlayground(data) {
  const r = data.result;
  if (!r) {
    $("pg-result").innerHTML = `<div class="error-box">PIF API returned HTTP ${data.http_status}
      ${data.detail ? "— " + esc(JSON.stringify(data.detail)) : ""}</div>`;
    return;
  }
  const color = { allow:"#34D399", sanitize:"#FBBF24", isolate:"#FB923C", block:"#F87171" }[r.decision] || "#8CA0BF";
  const findings = r.findings || [];
  $("pg-result").innerHTML = `
    <div class="verdict" style="border-left:5px solid ${color}">
      <div class="big" style="color:${color}">${esc(r.decision).toUpperCase()}</div>
      <div class="kv">
        <div class="k">Scan ID</div><div class="mono">${esc(r.scan_id)}</div>
        <div class="k">Scan Time</div><div id="pg-scantime">…</div>
        <div class="k">Scanned At</div><div id="pg-scannedat" class="mono">…</div>
        <div class="k">Status / Malicious</div><div>${esc(r.status)} / ${r.malicious === null ? "—" : r.malicious}</div>
        <div class="k">Risk</div><div>${r.risk ?? "—"} (${esc(r.risk_level)})</div>
        <div class="k">Attacks</div><div>${(r.attacks || []).map(a =>
            `<span class="chip">${esc(a)} <span class="muted">(#${(r.attack_ids||[]).join(",#")})</span></span>`).join("") || "none"}</div>
        <div class="k">Warnings</div><div>${(r.warnings || []).join(", ") || "—"}</div>
        <div class="k">Quarantined</div><div>${(r.quarantined || []).join(", ") || "—"}</div>
        <div class="k">Coverage</div><div>${esc(r.coverage)}</div>
        <div class="k">Submitted prompt</div><div${r.malicious === true ? ' style="color:#F87171"' : ""}>${esc(short($("pg-prompt").value, 400)) || "(none)"}</div>
      </div>
    </div>
    ${findings.length ? `<table><thead><tr><th>Category</th><th>Rule</th><th>Source</th>
      <th>Layer</th><th>Severity</th><th>Evidence</th></tr></thead><tbody>${findings.map(f =>
      `<tr><td>${esc(f.category)}${findingBadges(f)}</td><td class="mono">${esc(f.rule_id || "—")}</td>
       <td class="mono">${esc(f.source_id)}${/^(hidden_css:|comment:|pdf_white:|pdf_tiny:|pdf_offpage:|pdf_render_diff:|docx_hidden:|ocr_faint:)/.test(f.locator || "") ? `<div class="muted" style="font-size:9px">${esc(f.locator)}</div>` : ""}</td><td>${esc(f.layer)}</td><td>${f.severity}</td>
       <td class="mono">${esc(short(f.evidence, 140))}</td></tr>`).join("")}</tbody></table>`
      : '<p class="muted">No findings — input passed clean.</p>'}
    ${(r.safe_content || []).length ? `<details open><summary>Safe content handed downstream (${r.safe_content.length} segments)</summary>
      <pre>${esc(r.safe_content.map(s => "[" + s.source + "] " + s.text).join("\\n---\\n"))}</pre></details>` : ""}
    <details><summary>Raw response JSON</summary><pre>${esc(JSON.stringify(r, null, 2))}</pre></details>`;
}

async function pollStatus() {
  try {
    const health = await api("/api/health");
    $("api-dot").style.background = health.api_ready ? "#34D399" : "#FBBF24";
    $("db-dot").style.background = health.db ? "#34D399" : "#F87171";
    $("db-size").textContent = health.db_size_mb ? `(${health.db_size_mb} MB)` : "(no data yet)";
  } catch (e) { $("api-dot").style.background = "#F87171"; }
}

/* ---------- Self-Tuning Agent console ---------- */

const STATUS_COLOR = { pending:"#FBBF24", approved:"#34D399", rejected:"#8CA0BF", rollback:"#F87171" };

function agentCards(data) {
  const pending = data.pending.filter(p => p.status === "pending").length;
  const by = s => data.pending.filter(p => p.status === s).length;
  return [
    ["Cycles Run", data.cycles.length, "#5B8AFF"],
    ["Awaiting You", pending, "#FBBF24"],
    ["Approved", by("approved"), "#34D399"],
    ["Rolled Back", by("rollback"), "#F87171"],
    ["Rejected", by("rejected"), "#8CA0BF"],
    ["Failed Hypotheses", data.failed_hypotheses.length, "#8CA0BF"],
  ];
}

function candidateCard(p) {
  const ev = p.evidence || {};
  const pending = p.status === "pending";
  const rule = policyData ? (policyData.rules || []).find(r => r.id === p.rule_id) : null;
  const stageKey = String(p.rule_id || "").startsWith("FUZZY-") ? "stage3_fuzzy" : "stage1_rules";
  const stage = (policyData && policyData.stages && policyData.stages[stageKey]) || STAGE_FALLBACK[stageKey];
  const newWeight = p.override && p.override.weight != null ? p.override.weight : null;
  const currentWeight = rule ? rule.weight : null;
  const severity = rule ? rule.severity : null;
  const eff = w => (severity != null && w != null) ? (severity * w).toFixed(2) : "—";
  const lostProtection = (ev.lost_protection || []).length;
  const newVictims = (ev.new_benign_victims || []).length;
  const border = STATUS_COLOR[p.status] || "#8CA0BF";
  const belowThreshold = severity != null && newWeight != null && severity * newWeight < 0.5;
  const catId = rule && policyData?.categories ? (policyData.categories[rule.category] ?? "?") : "?";
  const weightUnchanged = currentWeight != null && newWeight != null && Number(currentWeight) === Number(newWeight);

  /* Per-status presentation: chip, one-line summary, stepper states, decision box. */
  const view = {
    pending: {
      chip: ["Awaiting approval", "#FBBF24"],
      line: "Production is untouched — the change only goes live if you approve it below.",
      steps: [["done", "check"], ["done", "check"], ["active", "wait"]],
      box: "awaiting",
    },
    approved: {
      chip: ["Approved & live", "#34D399"],
      line: "Re-verified after your approval and merged — effective from the next scan.",
      steps: [["done", "check"], ["done", "check"], ["done", "check"]],
      box: "ok",
    },
    rollback: {
      chip: ["Reverted", "#F87171"],
      line: "Approved, but the final safety check failed — the change was rolled back automatically.",
      steps: [["done", "check"], ["fail", "cross"], ["fail", "cross"]],
      box: "bad",
    },
    rejected: {
      chip: ["Rejected", "#8CA0BF"],
      line: "You declined this change — the agent will not propose it again.",
      steps: [["done", "check"], ["done", "check"], ["skip", "cross"]],
      box: "muted",
    },
  }[p.status] || { chip: ["Unknown", "#8CA0BF"], line: "", steps: [["skip", "dot"], ["skip", "dot"], ["skip", "dot"]], box: "muted" };
  const stepMark = { check: "✔", cross: "✘", wait: "…", dot: "3" };
  const stepState = { done: "done", active: "awaiting you", fail: "failed", skip: "closed" };
  const stepper = [["Analysis", "1"], ["Safety testing", "2"], ["Your decision", "3"]]
    .map(([name, n], i) => {
      const [state, mark] = view.steps[i];
      return `<div class="st ${state === "done" ? "finished" : ""}">
        <div class="st-dot ${state}">${stepMark[mark] || n}</div>
        <div class="st-name">${name}</div>
        <div class="st-state ${state}">${stepState[state]}</div></div>`;
    }).join("");
  const sameWeightNote = weightUnchanged
    ? '<p class="muted" style="margin-top:6px">The rule already runs at the proposed weight (an earlier approved change set it) — approving keeps it there and records your sign-off.</p>'
    : "";

  return `<div class="cand-card" style="border-left-color:${border}">

    <div class="hero">
      <div>
        <div class="h-sub">Rule weight adjustment</div>
        <div class="h-id">${esc(p.rule_id)}</div>
        ${rule ? `<div class="muted" style="font-size:11.5px;margin-top:3px;max-width:280px">${esc(rule.reason)}</div>` : ""}
      </div>
      <div class="wgroup">
        <div class="wpill"><div class="wv">${currentWeight ?? "?"}</div><div class="wl">Current weight</div></div>
        <span class="warrow">→</span>
        <div class="wpill proposed"><div class="wv" style="color:#FCD34D">${newWeight ?? "?"}</div><div class="wl">Proposed weight</div></div>
        <div class="muted" style="font-size:11px;max-width:150px;line-height:1.5">effective severity<br><b class="mono">${eff(currentWeight)} → ${eff(newWeight)}</b></div>
      </div>
      <span style="flex:1"></span>
      <span class="badge" style="--bc:${view.chip[1]};font-size:11px">${esc(view.chip[0])}</span>
    </div>
    ${sameWeightNote}

    <div class="stepper">${stepper}</div>

    <div class="sec-title">What the agent found</div>
    <p style="margin:0;font-size:12.5px;color:#C3D0E8;line-height:1.6">The firewall checks every prompt and attachment against its detection rules. When a rule matches, it adds to the risk score using the rule's severity × weight. The agent measured that <b class="mono">${esc(p.rule_id)}</b> was pushing safe content over the blocking line: it wrongly blocked
      <b style="color:#FCA5A5">${ev.false_positives_before ?? "?"} safe prompt${ev.false_positives_before === 1 ? "" : "s"}</b> on the test dataset, and the proposed weight removes all of them.</p>
    <div class="metrics">
      <div class="metric"><div class="mlbl">Safe prompts wrongly blocked</div>
        <div class="mval" style="color:#34D399">${ev.false_positives_before ?? "?"} → ${ev.false_positives_after ?? "?"}</div>
        <div class="msub">before → after the proposed change, measured on the test dataset</div></div>
    </div>

    <div class="sec-title">Safety testing — separate environment, same rules</div>
    <p style="margin:0;font-size:12.5px;color:#C3D0E8;line-height:1.6">The change was replayed on a copy of the firewall (never production) against the test dataset
      <span class="mono">${esc(p.corpus || "—")}</span>. It must pass both checks below:</p>
    <div class="results">
      <div class="rcard ${newVictims ? "fail" : "pass"}">
        <span class="r-ico">${newVictims ? "✘" : "✔"}</span>
        <div><div class="r-title">No new false positives</div>
        <div class="r-sub">${newVictims
          ? `FAILED — ${newVictims} safe prompt(s) would still be wrongly blocked.`
          : "Passed — no safe content is blocked by the proposed weight."}</div></div>
      </div>
      <div class="rcard ${lostProtection ? "fail" : "pass"}">
        <span class="r-ico">${lostProtection ? "✘" : "✔"}</span>
        <div><div class="r-title">No loss of protection</div>
        <div class="r-sub">${lostProtection
          ? `FAILED — ${lostProtection} attack(s) would no longer be caught.`
          : "Passed — every attack the firewall catches today stays caught."}</div></div>
      </div>
    </div>
    ${belowThreshold ? '<p class="muted" style="margin:2px 0 0;font-size:11.5px">At the proposed weight, matches are still logged but no longer push a decision on their own.</p>' : ""}

    <div class="sec-title">Your decision</div>
    <div class="decision-box ${view.box}">
      <div class="d-head">${pending ? "⏳ This change is waiting for you" : view.box === "ok" ? "✅ Approved — live from the next scan" : view.box === "bad" ? "⛔ Approved, then reverted" : "🚫 Rejected"}${p.rollback_reason ? ` <span style="color:#FCA5A5;font-weight:400">— ${esc(p.rollback_reason)}</span>` : ""}</div>
      <p>${pending
        ? "Approving re-runs both safety checks, then saves the weight change to the firewall's override file. The rule's pattern, category, and severity are never touched. If the final checks fail, the change rolls back automatically."
        : p.status === "approved"
          ? "Both safety checks passed again after approval, and the weight change was saved to the firewall's override file."
          : p.status === "rollback"
            ? "The post-approval safety check failed, so the change was automatically reverted — production is back to its previous state."
            : "The proposal is closed permanently and remembered so the agent never re-proposes it."}</p>
      ${pending ? `<div class="toolbar" style="margin-top:12px;flex-wrap:wrap">
        <select id="scope-${esc(p.id)}">
          <option value="candidate">Verify on candidate's corpus (recorded evidence scope)</option>
          <option value="full">Verify on FULL held-out corpus (strictest)</option>
        </select>
        <input type="text" id="why-${esc(p.id)}" placeholder="Decision note — required to approve, stored in the audit record" style="flex:1;min-width:260px">
        <button class="primary" onclick="decide('${esc(p.id)}','approve')">✔ Approve → Production</button>
        <button class="ghost" onclick="decide('${esc(p.id)}','reject')">✖ Reject</button>
      </div>` : ""}
    </div>

    <details>
      <summary>Technical details (rule ID, stage, files)</summary>
      <div class="cand-line" style="margin-top:10px">
        <div class="k">Proposal ID</div><div class="mono">${esc(p.id)}</div>
        <div class="k">Rule</div><div class="mono">${esc(p.rule_id)}${rule ? ` — ${esc(rule.reason)} · ${esc(rule.category)} #${catId} · base severity ${rule.severity}` : " (built-in Stage-1 pattern detection; details need the PIF API)"}</div>
        <div class="k">Stage</div><div>${esc(stage.label)}${stage.alias ? ` · ${esc(stage.alias)}` : ""} · ${stage.scope === "per_view" ? "Per View" : "Per Scan"}</div>
        <div class="k">What happens on approval</div><div>writes <span class="mono">[rules:${esc(p.rule_id)}] weight=${newWeight ?? "?"}</span> to
          <span class="mono">conf/policy-overrides.json</span>${p.policy_file ? ` · merged: <span class="mono">${esc(p.policy_file)}</span>` : ""}</div>
        ${p.decision_reason ? `<div class="k">Decision note</div><div class="muted">“${esc(p.decision_reason)}”</div>` : ""}
        <div class="k">Agent JSON</div><div class="muted">see the "Agent JSON" tab of this window for the full machine-readable record</div>
      </div>
    </details>
  </div>`;
}

let agentState = null;   // last /api/agent payload, reused by the action modal
let agentDataSeq = 0;

async function loadAgent() {
  let data;
  try {
    data = await api("/api/agent");
  } catch (e) {
    $("agent-cards").innerHTML = `<div class="error-box">agent state unavailable: ${esc(e.message)}</div>`;
    return;
  }
  agentState = data; agentDataSeq++;
  // Rule details (reason/category/current weight) for the action views;
  // they degrade to stage facts alone when the PIF API is down.
  try { await getPolicyData(); } catch (e) {}
  $("agent-cards").innerHTML = agentCards(data).map(([lbl, num, color]) =>
      `<div class="card"><div class="num" style="color:${color}">${num ?? 0}</div><div class="lbl">${lbl}</div></div>`).join("");
  const pol = data.policy || {};
  const overrides = Object.entries(pol.rules || {});
  $("agent-policy").innerHTML = overrides.length
    ? `<div class="chip" style="border-color:rgba(52,211,153,.5);color:#6EE7B7">production overrides active: ${esc(pol.path)} → ${overrides.map(([r, v]) => esc(r) + " " + esc(JSON.stringify(v))).join(", ")}</div>`
    : `<div class="chip">production policy: unchanged (no approved overrides)</div>`;
  // Actions table: every agent action (any status), newest first, clickable.
  const rows = data.pending.slice().reverse();
  $("agent-actions-table").querySelector("tbody").innerHTML = rows.map(p => {
    const ev = p.evidence || {};
    const stageKey = String(p.rule_id || "").startsWith("FUZZY-") ? "stage3_fuzzy" : "stage1_rules";
    const stage = (policyData && policyData.stages && policyData.stages[stageKey]) || STAGE_FALLBACK[stageKey];
    const weight = p.override && p.override.weight != null ? p.override.weight : "—";
    return `<tr class="row-clickable" onclick="showAction('${esc(p.id)}')">
      <td><span class="action-icon">🔧</span></td>
      <td class="mono">${esc(p.id)}</td>
      <td class="mono">${esc(p.rule_id)}</td>
      <td><span class="stage-chip" style="margin-left:0">${esc(stage.alias || stage.label)} · ${esc(stage.scope === "per_scan" ? "Per Scan" : "Per View")}</span></td>
      <td class="mono">weight → ${esc(weight)}</td>
      <td>${ev.false_positives_before ?? "—"} → ${ev.false_positives_after ?? "—"}</td>
      <td><span class="badge" style="--bc:${STATUS_COLOR[p.status] || "#8CA0BF"}">${esc(p.status).toUpperCase()}</span></td>
      <td class="mono">${esc(short(p.created || "—", 19))}</td></tr>`;
  }).join("")
    || '<tr><td colspan="8" class="muted">No agent actions yet — run a tune cycle to generate proposals.</td></tr>';
  $("agent-cycles").querySelector("tbody").innerHTML = data.cycles.slice().reverse().map(c =>
    (c.candidates || []).length ? c.candidates.map(cand =>
      `<tr><td>#${c.cycle}</td><td>${(c.targets || []).map(t => `<span class="chip">${esc(t)}</span>`).join("") || "—"}</td>
       <td class="mono">${esc(cand.rule_id || "—")}</td><td>${cand.victims ?? 0}</td>
       <td class="mono">${(cand.attempts || []).map(a => `${a.weight}:${a.verdict}`).join(" → ") || esc(cand.note || "—")}</td>
       <td>${cand.pending_id ? `<span class="chip" style="cursor:pointer" onclick="showAction('${esc(cand.pending_id)}')">${esc(cand.pending_id)}</span>` : esc(cand.note || "no candidate")}</td></tr>`).join("")
    : `<tr><td>#${c.cycle}</td><td colspan="5" class="muted">${esc(c.note || "no targets")}</td></tr>`).join("")
    || '<tr><td colspan="6" class="muted">No cycles yet — press "Run Tune Cycle".</td></tr>';
  $("agent-failed").innerHTML = data.failed_hypotheses.length
    ? `<table><thead><tr><th>Rule</th><th>Weight</th><th>Why</th></tr></thead><tbody>${data.failed_hypotheses.map(f =>
        `<tr><td class="mono">${esc(f.rule_id)}</td><td>${f.weight ?? "—"}</td><td class="muted">${esc(f.reason)}</td></tr>`).join("")}</tbody></table>`
    : '<p class="muted">None — every attempted hypothesis is still open.</p>';
  loadScheduler();
}

/* ---------- Nightly scheduler: schedule + content-hash skip gate ---------- */
let schedulerState = null;

async function loadScheduler() {
  try { schedulerState = await api("/api/agent/scheduler"); }
  catch (e) { schedulerState = null; }
  renderScheduler();
}

function renderScheduler() {
  /* The whole schedule section lives in the popup opened by the header
     "⏰ Schedule" button; on the page we only mirror the enabled/disabled
     state in the chip next to that button. */
  const chip = $("sched-btn-status");
  if (!chip) return;
  const s = (schedulerState && schedulerState.state) || {};
  const statusChip = s.enabled ? ["Enabled", "#34D399"] : ["Disabled", "#8CA0BF"];
  chip.textContent = statusChip[0];
  chip.style.setProperty("--bc", statusChip[1]);
}

/* Schedule popup: status, facts, last run and the form — one place, opened
   from the header button. */
function showScheduleModal() {
  const s = (schedulerState && schedulerState.state) || {};
  const daily = Number(s.interval_hours ?? 24) === 24;
  const statusChip = s.enabled ? ["Enabled", "#34D399"] : ["Disabled", "#8CA0BF"];
  const last = s.last_result;
  const lastColor = { completed:"#34D399", skipped:"#8CA0BF", error:"#F87171", busy:"#FBBF24" }[String(last && last.outcome || "").toLowerCase()] || "#8CA0BF";
  const lastHtml = last ? `
    <div class="sched-last">
      <span class="badge" style="--bc:${lastColor}">${esc(String(last.outcome || "?").toUpperCase())}</span>
      <span class="mono">${esc(last.when || "")}</span>
      <span class="muted">${esc(last.trigger || "")}${last.seconds != null ? ` · ${last.seconds}s` : ""}${last.candidates_queued ? ` · <b style="color:#FBBF24">${last.candidates_queued} candidate(s) queued</b>` : ""}</span>
      ${last.note ? `<div class="note">${esc(last.note)}</div>` : ""}
      ${last.error ? `<div class="note" style="color:#F87171">${esc(last.error)}</div>` : ""}
    </div>`
    : '<p class="muted" style="font-size:12px;margin:4px 0 0">Never run yet.</p>';
  openModal("⏰ Schedule automatic analysis",
    "One supervised analysis per slot — every proposal still waits for your approval.",
    [
      { id: "p-sched", label: "Schedule", html: `
        <div class="sched-last" style="margin:2px 0 12px">
          <span class="badge" style="--bc:${statusChip[1]}">${statusChip[0]}</span>
          <span class="muted" style="font-size:12.5px;line-height:1.55">Let the agent run its analysis automatically. Every finding lands in the
          queue for you to approve or reject — <b style="color:#FBBF24">nothing is ever approved automatically</b>,
          and unchanged inputs are skipped.</span>
        </div>
        <div class="sched-facts">
          <div><div class="k">Runs</div><div>${daily
            ? `Daily at <b class="mono">${String(s.hour ?? 2).padStart(2, "0")}:00</b>`
            : `Every <b class="mono">${esc(String(s.interval_hours ?? 24))} h</b>`}</div></div>
          <div><div class="k">Dataset</div><div>${s.corpus === "full" ? "Full held-out corpus" : "Demo corpus (fast)"}</div></div>
          <div><div class="k">Next run</div><div class="mono">${s.enabled ? esc((schedulerState && schedulerState.next_run) || "shortly") : "—"}</div></div>
          <div><div class="k">Inputs</div><div>${(schedulerState && schedulerState.config_changed)
            ? '<b style="color:#FBBF24">changed — next run analyzes</b>'
            : "unchanged since last cycle"}</div></div>
        </div>
        ${schedulerState && schedulerState.running ? '<div style="font-size:12px;margin-top:10px"><b style="color:#FBBF24">⏳ A cycle is running right now…</b></div>' : ""}
        <div class="sec-title" style="margin:14px 0 4px">Last run</div>
        ${lastHtml}
        <div class="sched-form" style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">
          <label class="sf-row"><span>Run every</span>
            <select id="sched-interval" onchange="document.getElementById('sched-hour-row').style.display=this.value==='24'?'':'none'">
              <option value="6" ${!daily && Number(s.interval_hours) === 6 ? "selected" : ""}>6 hours</option>
              <option value="12" ${!daily && Number(s.interval_hours) === 12 ? "selected" : ""}>12 hours</option>
              <option value="24" ${daily ? "selected" : ""}>24 hours (daily)</option>
            </select></label>
          <label class="sf-row" id="sched-hour-row" style="display:${daily ? "" : "none"}"><span>Daily time (local, 0–23)</span>
            <input type="number" id="sched-hour" min="0" max="23" value="${s.hour ?? 2}" class="mono" style="width:90px"></label>
          <label class="sf-row"><span>Dataset to analyze</span>
            <select id="sched-corpus">
              <option value="demo" ${s.corpus !== "full" ? "selected" : ""}>Demo corpus (fast)</option>
              <option value="full" ${s.corpus === "full" ? "selected" : ""}>Full held-out corpus (strictest)</option>
            </select></label>
          <p class="sf-hint">A scheduled run re-checks only what changed since the last completed
          analysis — unchanged inputs are skipped. It can only write to the agent's own report area;
          every proposed change waits in the queue for an explicit approve or reject.</p>
        </div>
        <div class="toolbar" style="margin-top:16px">
          <button class="${s.enabled ? "ghost" : "primary"}" onclick="toggleSchedulerFromModal()">${s.enabled ? "⏸ Disable" : "▶ Enable"}</button>
          <button class="ghost" onclick="closeModal();runScheduledNow()" ${schedulerState && schedulerState.running ? "disabled" : ""}>Run now</button>
          <span style="flex:1"></span>
          <button class="primary" onclick="saveScheduler()">Save schedule</button>
          <button class="ghost" onclick="closeModal()">Cancel</button>
        </div>` },
    ]);
}

async function toggleSchedulerFromModal() {
  const s = (schedulerState && schedulerState.state) || {};
  await setScheduler({ enabled: !s.enabled });
  showScheduleModal();
}

async function setScheduler(patch) {
  try { schedulerState = await api("/api/agent/scheduler", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  }); }
  catch (e) { alert("Scheduler update failed: " + e.message); }
  renderScheduler();
}

function saveScheduler() {
  const patch = {
    interval_hours: parseInt($("sched-interval").value, 10),
    corpus: $("sched-corpus").value,
  };
  const hourEl = $("sched-hour");
  if (hourEl) patch.hour = parseInt(hourEl.value, 10);
  setScheduler(patch);
  closeModal();
}

async function runScheduledNow(button) {
  if (button) button.disabled = true;
  const status = $("agent-status");
  botWorking("Agent working — PERCEIVE → PLAN → ACT → VERIFY…");
  status.textContent = "Running one analysis cycle now…";
  try {
    const data = await api("/api/agent/scheduler/run", { method: "POST" });
    const r = data.result || {};
    status.textContent = r.outcome === "completed"
      ? ((r.candidates_queued || 0)
          ? `Cycle #${r.cycle} done — ${r.candidates_queued} candidate(s) queued for your decision below.`
          : (r.note || "Cycle done — nothing to fix."))
      : `Cycle ${r.outcome}: ${r.note || r.error || ""}`;
  } catch (e) { status.textContent = ""; alert("Run failed: " + e.message); }
  finally { if (button) button.disabled = false; botPaused(); loadAgent(); }
}

/* Agent action detail modal — same click-through pattern as the scan detail. */
function showAction(candidateId) {
  const p = agentState && (agentState.pending || []).find(x => x.id === candidateId);
  if (!p) { alert("Action details unavailable — refresh the page."); return; }
  const ev = p.evidence || {};
  const stageKey = String(p.rule_id || "").startsWith("FUZZY-") ? "stage3_fuzzy" : "stage1_rules";
  const stage = (policyData && policyData.stages && policyData.stages[stageKey]) || STAGE_FALLBACK[stageKey];
  // Ladder attempts recorded for this candidate in the cycle history
  let attempts = [];
  for (const c of (agentState.cycles || []))
    for (const cand of (c.candidates || []))
      if (cand.pending_id === p.id || (cand.rule_id === p.rule_id && cand.attempts)) attempts = cand.attempts || attempts;
  const attemptsHtml = attempts.length
    ? `<table><thead><tr><th>Step</th><th>Weight tried</th><th>Verdict</th><th>FP before → after</th>
       <th>New benign victims</th><th>Lost attack protection</th><th>Duration</th></tr></thead><tbody>
       ${attempts.map((a, i) => `<tr>
         <td>#${i + 1}</td><td class="mono">${a.weight}</td>
         <td>${a.verdict === "accepted" ? '<span class="state-on">accepted</span>' : '<span class="state-off">rejected</span>'}</td>
         <td class="mono">${a.false_positives_before ?? "—"} → ${a.false_positives_after ?? "—"}</td>
         <td>${(a.new_benign_victims || []).length || "—"}</td>
         <td>${(a.lost_protection || []).length || "—"}</td>
         <td class="mono">${a.seconds ?? "—"} s</td></tr>`).join("")}</tbody></table>
       <p class="muted">Least-invasive first: the ladder stops at the first weight that passes BOTH gates
       (no benign record newly mishandled, no attack record newly allowed).</p>`
    : '<p class="muted">No ladder attempts recorded for this action.</p>';
  openModal(
    `${actionChip("update_rule")} <span class="mono" style="font-size:14px">${esc(p.id)}</span>
     <span class="badge" style="--bc:${STATUS_COLOR[p.status] || "#8CA0BF"}">${esc(p.status).toUpperCase()}</span>`,
    `${esc(p.rule_id)} · ${esc(stage.label)} · proposed ${esc(p.created || "—")}`,
    [
      { id: "pa-overview", label: "Action", html: candidateCard(p) },
      { id: "pa-attempts", label: "Attempts", html: attemptsHtml },
      { id: "pa-json", label: "Agent JSON",
        html: `<pre>${esc(JSON.stringify(p, null, 2))}</pre>` },
    ],
  );
}

/* Pre-run gate: explain exactly what the agent WILL do before it runs. */
function showTunePlan() {
  const corpus = $("agent-corpus").value === "demo"
    ? "demo corpus (data/samples/redteam_demo/eval_demo.jsonl — fast)"
    : "FULL held-out corpus (data/processed/eval_full.jsonl — strictest)";
  $("agent-prerun").innerHTML = `
    <div class="approve-card">
      <h4>⚠ Read before running — this is exactly what the agent will do</h4>
      <div style="margin:-4px 0 10px">${actionChip("update_rule")}
        <span class="muted">the only kind of change a tune cycle can ever propose</span></div>
      <div class="q">
        <div class="k">The loop</div>
        <div>Run ONE supervised self-tuning loop:
          <b>PERCEIVE</b> scan benign + attack samples with the current firewall →
          <b>PLAN</b> pick the rules whose matches blocked benign records →
          <b>ACT</b> re-scan exactly those records on a shadow firewall with a lower rule
          weight (least-invasive ladder 0.75 → 0.35) →
          <b>VERIFY</b> both gates (no benign regression, no attack newly allowed) →
          queue the first passing candidate per rule as a card below.</div>
        <div class="k">Rules affected</div>
        <div>Only existing <b>Rule A</b> detections (RULE-###, Stage 1 · Per View) that caused a
          <b>decision-level false positive</b> — a benign record that was actually
          blocked/sanitized/isolated. Rule B (semantic), fuzzy matching and Rule C (context)
          are never modified; they only re-run as part of verification.</div>
        <div class="k">Stage</div>
        <div>Stage 1 — Rule patterns (Per View). Every candidate is re-verified through the
          <b>whole 4-stage pipeline</b> (Rule A → Rule B/Semantic → Fuzzy → Rule C/Context)
          on a shadow copy of the firewall before it reaches you.</div>
        <div class="k">Effect</div>
        <div><b style="color:#34D399">Nothing in production.</b> The agent may only write to
          <span class="mono">reports/redteam/</span> (its memory + the pending queue).
          A proposal becomes real only when you press <b>Approve → Production</b> on its card,
          which re-verifies both gates and then writes <span class="mono">conf/policy-overrides.json</span>.</div>
        <div class="k">Justification</div>
        <div>Closes the false-positive feedback loop: benign content blocked by an over-eager
          rule is measured, a minimal weight correction is proven safe on real data, and you
          make the call.</div>
        <div class="k">Corpus</div><div class="mono">${esc(corpus)}</div>
      </div>
      <div class="toolbar" style="margin-top:10px">
        <button class="primary" onclick="runTune()">▶ Run cycle now</button>
        <button class="ghost" onclick="document.getElementById('agent-prerun').innerHTML=''">Cancel</button>
      </div>
    </div>`;
  $("agent-prerun").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function botWorking(text) {
  $("bot-avatar").classList.add("working");
  $("bot-caption").textContent = text;
}
function botPaused() {
  $("bot-avatar").classList.remove("working");
  $("bot-caption").innerHTML = "Agent paused<br>Awaiting your decision";
}

async function runTune() {
  const button = $("agent-tune-btn"), status = $("agent-status");
  $("agent-prerun").innerHTML = "";
  button.disabled = true;
  botWorking("Agent working — PERCEIVE → PLAN → ACT → VERIFY…");
  status.textContent = "Agent working: PERCEIVE baseline → PLAN Stage-1 rule targets → ACT on shadow firewall → VERIFY both gates…";
  try {
    const data = await api("/api/agent/tune", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ corpus: $("agent-corpus").value }),
    });
    const cands = (data.summary.candidates || []);
    status.textContent = cands.length
      ? `Cycle #${data.summary.cycle} done — ${cands.filter(c => c.pending_id).length} candidate(s) queued for your decision below.`
      : data.summary.note || "Cycle done — nothing to fix.";
  } catch (e) { status.textContent = ""; alert("Tune cycle failed: " + e.message); }
  finally { button.disabled = false; botPaused(); loadAgent(); }
}

async function decide(candidateId, action) {
  const status = $("agent-status");
  const whyEl = document.getElementById("why-" + candidateId);
  const reason = whyEl ? whyEl.value.trim() : "";
  if (action === "approve" && !reason) {
    alert("State WHY you approve — the reason is stored in the audit record.");
    return;
  }
  const scopeEl = document.getElementById("scope-" + candidateId);
  if (action === "approve") botWorking("Re-verifying both gates before merging…");
  status.textContent = action === "approve"
    ? "Re-verifying both gates before merging (this re-scans the corpus)…"
    : "Recording rejection…";
  try {
    const data = await api("/api/agent/" + action, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ candidate_id: candidateId, scope: scopeEl ? scopeEl.value : "candidate", reason }),
    });
    const entry = data.entry || {};
    if (entry.status === "approved") status.textContent = `✅ ${candidateId} approved and verified — merged into ${entry.policy_file}`;
    else if (entry.status === "rollback") status.textContent = `⛔ ${candidateId} ROLLED BACK: ${entry.rollback_reason}`;
    else status.textContent = `${candidateId} → ${entry.status}`;
  } catch (e) { status.textContent = ""; alert("Decision failed: " + e.message); }
  finally { botPaused(); await loadAgent(); }
  // Keep the detail modal open, now showing the post-decision state.
  if ($("modal-bg").classList.contains("open") && (agentState?.pending || []).some(x => x.id === candidateId)) {
    showAction(candidateId);
  }
}

/* ---------- Rules & Engines (live policy registry) ---------- */

let policyData = null;

/* Action-type taxonomy: EVERY action the UI or the agent takes declares
   exactly one of these, so the approver never has to infer the kind of
   change from logs or field names. */
const ACTION_TYPE = {
  add_rule:    ["ADDING A NEW RULE", "#5B8AFF"],
  update_rule: ["UPDATING AN EXISTING RULE", "#FBBF24"],
  delete_rule: ["DELETING A CUSTOM RULE", "#F87171"],
  apply_rule:  ["APPLYING A RULE (scan-time)", "#34D399"],
  semantic:    ["SEMANTIC ANALYSIS (ML classifier)", "#A78BFA"],
  fuzzy:       ["FUZZY MATCHING (typo-tolerant)", "#FB923C"],
  context:     ["CONTEXT / SESSION ANALYSIS", "#F472B6"],
  engine:      ["TOGGLING A WHOLE STAGE", "#8CA0BF"],
};
const actionChip = t => {
  const [label, color] = ACTION_TYPE[t] || ["UNKNOWN ACTION", "#8CA0BF"];
  return `<span class="badge" style="--bc:${color};font-size:11px;letter-spacing:.5px">${label}</span>`;
};


/* ---------------- Settings page (v6.3) ---------------- */
async function loadSettings() {
  const status = $("settings-status");
  try {
    const data = await api("/api/settings");
    const container = $("settings-groups");
    container.innerHTML = "";
    for (const group of data.groups) {
      const card = document.createElement("div");
      card.className = "card";
      card.style.marginBottom = "14px";
      const badge = group.restart_required
        ? `<span class="badge" style="--bc:#F59E0B;font-size:10px">restart to apply</span>`
        : `<span class="badge" style="--bc:#34D399;font-size:10px">hot-reload</span>`;
      card.innerHTML = `<div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          <span>${esc(group.group)}</span> ${badge}</div>`;
      for (const item of group.items) {
        const row = document.createElement("div");
        row.style.cssText = "display:grid;grid-template-columns:300px 1fr 210px 90px;gap:10px;align-items:center;padding:7px 4px;border-bottom:1px solid rgba(255,255,255,.05)";
        const srcBadge = item.source === "default"
          ? `<span class="muted" style="font-size:10px">code default</span>`
          : `<span class="mono" style="font-size:10px;white-space:nowrap">${esc(item.source)}</span>`;
        row.innerHTML = `
          <div><div class="mono" style="font-size:12px">${esc(item.key)}</div>
               <div class="muted" style="font-size:10px;line-height:1.3">${esc(item.description || "")}</div>
               <div style="margin-top:2px">${item.write_only ? `<span class="muted" style="font-size:9px">write-only</span>` : srcBadge}</div></div>
          <div class="muted" style="font-size:10px">${item.write_only ? "value hidden (write-only)" : "current: " + esc(item.value)}${item.env ? " · env " + esc(item.env) : ""}</div>
          <input class="mono" data-key="${esc(item.key)}" placeholder="${esc(item.write_only ? "enter new token" : item.value)}"
                 style="background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.12);border-radius:6px;color:var(--text);padding:6px 8px;font-size:12px;width:100%" />
          <div style="display:flex;gap:6px;align-items:center">
            <button class="ghost" style="padding:5px 10px;font-size:11px" onclick="saveSetting('${esc(item.key)}', this)">Save</button>
          </div>`;
        card.appendChild(row);
      }
      container.appendChild(card);
    }
    status.textContent = `${data.groups.reduce((n, g) => n + g.items.length, 0)} settings — policy groups hot-reload; core groups apply on PIF API restart`;
  } catch (e) {
    status.innerHTML = `<span class="error-box" style="display:block">Cannot load settings: ${esc(e.message)}</span>`;
  }
}

async function saveSetting(key, button) {
  const input = document.querySelector(`input[data-key="${key}"]`);
  if (!input || !input.value.trim()) return;
  const original = button.textContent;
  button.textContent = "...";
  try {
    const result = await api("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key: key, value: input.value.trim() }),
    });
    const note = result.hot_reload ? "applied (hot-reload)" : result.restart_required ? "stored — restart the PIF API to apply" : "applied";
    button.textContent = "saved";
    const status = $("settings-status");
    status.innerHTML = `<span style="color:#34D399">${esc(key)}: ${esc(result.note || note)}</span>`;
    input.value = "";
  } catch (e) {
    button.textContent = original;
    const status = $("settings-status");
    status.innerHTML = `<span class="error-box" style="display:block">${esc(key)}: ${esc(e.message)}</span>`;
  }
}

/* Stage facts that stay true even when the PIF API is down (card fallback). */
const STAGE_FALLBACK = {
  stage1_rules: { label: "Stage 1 — Rule patterns", alias: "Rule A", scope: "per_view" },
  stage2_semantic: { label: "Stage 2 — Semantic classifier", alias: "Rule B / Semantic", scope: "per_view" },
  stage3_fuzzy: { label: "Stage 3 — Fuzzy matching", alias: "Fuzzy Matching", scope: "per_view" },
  stage4_context: { label: "Stage 4 — Context analysis", alias: "Rule C / Context", scope: "per_scan" },
};
async function getPolicyData() {
  // Always re-fetch: policy is managed by scripts (conf/policy.ini) and the
  // firewall hot-reloads it, so the UI must never show a stale snapshot.
  policyData = await api("/api/policy");
  return policyData;
}

async function loadRules() {
  try {
    const data = await getPolicyData();
    // Strictly five columns: ID, Category, Sev, Weight, Rule. Disabled rules
    // (tuned off by a script) are dimmed — no extra column, no extra data.
    // Every row is click-through: showRule() opens the detection's full card.
    const rows = data.rules.map(rule => `
      <tr class="clickable${rule.enabled === false ? " rule-off" : ""}" onclick="showRule('${esc(rule.id)}')" title="open detection details">
        <td><span class="rule-id mono">${esc(rule.id)}</span></td>
        <td class="rule-cat">${esc(rule.category)}</td>
        <td>${rule.severity}</td>
        <td>${rule.weight}</td>
        <td><div class="rule-pat" title="${esc(rule.pattern)}">${esc(rule.pattern)}</div></td>
      </tr>`).join("");
    $("rules-table").querySelector("tbody").innerHTML = rows;
    const disabled = data.rules.filter(r => r.enabled === false).length;
    $("rules-count").textContent =
      `${data.rules.length} detections${disabled ? ` · ${disabled} disabled` : ""} — live from the firewall (read-only; managed by scripts/policy.py) · click a row for details`;
  } catch (e) {
    $("rules-count").innerHTML = `<span class="error-box" style="display:block">Cannot read /v1/policy: ${esc(e.message)}</span>`;
  }
}

/* Detection detail modal — same click-through pattern as the scan rows.
   Tab 1 is the registry card (facts, why it exists, its pattern, where it
   runs); tab 2 lists the scans where this detection actually fired. */
async function showRule(ruleId) {
  let rule, stage, engines, categories;
  try {
    const data = await getPolicyData();
    rule = (data.rules || []).find(r => r.id === ruleId);
    if (!rule) throw new Error("not in the live policy — was it just retuned?");
    stage = (data.stages || {})[rule.stage] || STAGE_FALLBACK[rule.stage] || {};
    engines = data.engines || {};
    categories = data.categories || {};
  } catch (e) { alert("Failed to load detection: " + e.message); return; }
  const on = rule.enabled !== false;
  const engineKey = { stage1_rules: "rule_engine", stage2_semantic: "semantic_engine",
                      stage4_context: "context_engine" }[rule.stage];
  const catId = categories[rule.category];
  const perMatch = Math.round(rule.severity * rule.weight * 100) / 100;
  const kv = [
    ["Detection ID", `<span class="mono">${esc(rule.id)}</span>`],
    ["Attack category", `${esc(rule.category)}${catId != null ? ` <span class="muted">· category id ${catId}</span>` : ""}`],
    ["Runs in", `${esc(stage.label || rule.stage)}${stage.alias ? ` <span class="muted">· ${esc(stage.alias)}</span>` : ""}
      <span class="muted">· ${rule.stage === "stage4_context" ? "per scan" : "per view"}</span>`],
    ["Severity", `${rule.severity}`],
    ["Weight", `${rule.weight}`],
    ["Contribution per match", `${perMatch} <span class="muted">· severity × weight, fused into the risk score</span>`],
    ...(engineKey ? [["Engine toggle", engines[engineKey]
      ? '<span class="state-on">ON</span>' : '<span class="state-off">OFF</span>']] : []),
    ["Status", on ? '<span class="state-on">Enabled</span>'
                  : '<span class="state-off">Disabled — tuned off by a script</span>'],
    ["Origin", rule.built_in ? "Built-in registry rule (pif/detection)" : "Custom rule"],
  ];
  const overview = `
    <div class="kv">${kv.map(([k, v]) => `<div class="k">${k}</div><div>${v}</div>`).join("")}</div>
    ${stage.what ? `<div class="stage" style="margin-top:16px">
      <div class="alias">${esc(stage.alias || "")} · where it runs</div>
      <div class="name">${esc(stage.label || "")}</div>
      <p>${esc(stage.what)}</p>
      ${stage.inputs ? `<p class="inputs">inputs: ${esc(stage.inputs)}</p>` : ""}
    </div>` : ""}
    <div style="margin-top:16px">
      <div class="muted" style="margin-bottom:6px">why this detection exists</div>
      <p style="margin:0;font-size:13px;line-height:1.6;color:#C3D0E8">${esc(rule.reason)}</p>
    </div>
    <div style="margin-top:16px">
      <div class="muted" style="margin-bottom:6px">pattern (regex / phrase)</div>
      <pre>${esc(rule.pattern)}</pre>
    </div>`;
  openModal(
    `<span class="mono" style="font-size:14px">${esc(rule.id)}</span>${on ? "" : ' <span class="state-off" style="font-size:12px">disabled</span>'}`,
    `${esc(rule.category)} · severity ${rule.severity} · weight ${rule.weight} · ${esc(stage.label || rule.stage)}`,
    [
      { id: "p-rule", label: "Overview", html: overview },
      { id: "p-hits", label: "Recent hits", html: '<p class="muted">loading…</p>' },
    ],
  );
  loadRuleHits(rule.id);
}

async function loadRuleHits(ruleId) {
  const pane = $("p-hits");
  if (!pane) return;
  pane.dataset.rule = ruleId;   // only the latest clicked rule may write here
  try {
    const data = await api("/api/rule_hits?rule_id=" + encodeURIComponent(ruleId));
    if (pane.dataset.rule !== ruleId || !pane.isConnected) return;
    if (!data.hits.length) {
      pane.innerHTML = `<p class="muted">report.db has no scan in which this detection fired
        (${data.total} recorded hits). Send a matching prompt from the Playground and reopen this card.</p>`;
      return;
    }
    pane.innerHTML = `
      <p class="muted" style="margin-top:0">${data.total} recorded hit${data.total === 1 ? "" : "s"} in
      report.db — showing the latest ${data.hits.length}. Click a row to open the full scan.</p>
      <table><thead><tr><th>Time</th><th>Decision</th><th>Risk</th><th>Source</th><th>Layer</th>
        <th>Evidence</th><th>Prompt</th></tr></thead><tbody>${data.hits.map(h => `
        <tr class="clickable" onclick="showScan('${esc(h.scan_id)}')">
          <td class="mono">${esc(short(h.ts, 19))}</td>
          <td>${badge(h.decision || "error")}</td>
          <td>${h.risk ?? "—"}</td>
          <td class="mono">${esc(h.source_id || "—")}</td>
          <td>${esc(h.layer || "—")}</td>
          <td class="mono" title="${esc(h.evidence)}">${esc(short(h.evidence, 90))}</td>
          <td>${h.malicious === 1
            ? `<span style="color:#F87171">${esc(h.user_prompt)}</span>`
            : esc(h.user_prompt || "—")}</td>
        </tr>`).join("")}</tbody></table>`;
  } catch (e) {
    if (pane.dataset.rule === ruleId && pane.isConnected)
      pane.innerHTML = `<div class="error-box">Cannot read hits from report.db: ${esc(e.message)}</div>`;
  }
}
/* The tab is a live view: while it is open, re-read the firewall every few
   seconds so a script edit to conf/policy.ini appears without a refresh. */
setInterval(() => { if ($("view-rules").classList.contains("active")) loadRules(); }, 4000);


initLive();
setInterval(pollLive, 2000);
pollStatus();
setInterval(pollStatus, 5000);
loadStats();
</script>
</body>
</html>
"""


def agent_module():
    """Import the agent lazily so the portal boots without the ML stack."""
    import pif.agenticai_redteam as agent

    return agent


def policy_override_state() -> dict:
    """What the human gate has actually merged into production config."""
    path = Path(os.getenv("PIF_POLICY_FILE", "conf/policy-overrides.json"))
    document = {}
    if path.is_file():
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            document = {}
    return {"path": str(path), "exists": path.is_file(), "rules": document.get("rules", {})}


def agent_status_payload() -> dict:
    agent = agent_module()
    memory = agent.load_memory()
    pending = agent.load_pending()
    last_cycle = None
    if agent.FINDINGS_PATH.is_file():
        try:
            last_cycle = json.loads(agent.FINDINGS_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            last_cycle = None
    return {
        "cycles": memory.get("cycles", []),
        "failed_hypotheses": memory.get("failed_hypotheses", []),
        "pending": pending.get("pending", []),
        "last_cycle": last_cycle,
        "policy": policy_override_state(),
    }


# --------------------------------------------------------------- scheduler

def _read_json_file(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json_file(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_scheduler_state() -> dict:
    state = dict(DEFAULT_SCHEDULER_STATE)
    state.update(_read_json_file(SCHEDULER_STATE_PATH, {}))
    try:
        state["hour"] = min(23, max(0, int(state.get("hour", 2))))
    except (TypeError, ValueError):
        state["hour"] = 2
    try:
        state["interval_hours"] = min(168, max(1, int(state.get("interval_hours", 24))))
    except (TypeError, ValueError):
        state["interval_hours"] = 24
    if state.get("corpus") not in ("demo", "full"):
        state["corpus"] = "demo"
    state["enabled"] = bool(state.get("enabled"))
    return state


def config_fingerprint() -> str:
    """Content digest of every input that can invalidate a cycle's verdict:
    policy INI, the approved-overrides JSON, and both corpora. Content, not
    size or mtime — same rationale as Firewall._policy_fingerprint."""
    digest = hashlib.sha256()
    for path in SCHEDULER_FINGERPRINT_FILES:
        digest.update(str(path).encode("utf-8"))
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<missing>")
    return digest.hexdigest()


def _record_cycle_result(trigger, outcome, *, summary=None, error=None, seconds=None,
                         fingerprint=None, note=None) -> dict:
    result = {
        "when": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "trigger": trigger,
        "outcome": outcome,
        "seconds": round(seconds, 1) if seconds is not None else None,
    }
    if summary is not None:
        result["cycle"] = summary.get("cycle")
        result["targets"] = summary.get("targets", [])
        result["candidates_queued"] = sum(
            1 for candidate in summary.get("candidates", []) if candidate.get("pending_id")
        )
        if summary.get("note"):
            result["note"] = summary["note"]
    if error is not None:
        result["error"] = error
    if note is not None:
        result["note"] = note
    state = load_scheduler_state()
    state["last_result"] = result
    state["last_run_date"] = datetime.now().strftime("%Y-%m-%d")
    state["last_run_ts"] = time.time()
    if fingerprint is not None:
        state["last_fingerprint"] = fingerprint
    _write_json_file(SCHEDULER_STATE_PATH, state)
    return result


def run_tune_cycle_task(trigger: str, corpus: Path | None = None, force: bool = False) -> dict:
    """One tune cycle shared by the manual endpoint and the nightly scheduler.
    force=False (scheduled) skips when the hashed inputs are unchanged since
    the last COMPLETED cycle; the fingerprint is only remembered on success,
    so a failed or errored cycle is retried at the next slot. Serialised with
    agent_cycle_lock: two concurrent cycles would corrupt the agent's
    read-modify-write JSON stores."""
    state = load_scheduler_state()
    if not force and state.get("last_fingerprint") == config_fingerprint():
        return _record_cycle_result(
            trigger, "skipped",
            note="inputs unchanged since the last completed cycle — nothing to re-check",
        )
    if not agent_cycle_lock.acquire(blocking=False):
        return {
            "when": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "trigger": trigger, "outcome": "busy",
            "note": "another tune cycle is already running",
        }
    started = time.perf_counter()
    fingerprint = config_fingerprint()
    agent = agent_module()
    corpus_path = corpus or (DEMO_CORPUS if state.get("corpus", "demo") == "demo" else FULL_CORPUS)
    try:
        agent_instance = agent.RedTeamAgent(corpus_path=corpus_path)
        summary = agent_instance.run_tune_cycle()
    except Exception as error:
        return _record_cycle_result(
            trigger, "error", error=f"{type(error).__name__}: {error}",
            seconds=time.perf_counter() - started,
        )
    finally:
        agent_cycle_lock.release()
    return _record_cycle_result(
        trigger, "completed", summary=summary,
        seconds=time.perf_counter() - started, fingerprint=fingerprint,
    )


def scheduler_next_run(state: dict):
    """When the enabled scheduler would fire next, as a datetime (or None if
    the interval mode has never run and the next tick will trigger it)."""
    if not state.get("enabled"):
        return None
    interval = int(state.get("interval_hours", 24))
    now = datetime.now()
    if interval == 24:
        slot = now.replace(hour=int(state.get("hour", 2)), minute=0, second=0, microsecond=0)
        if now < slot:
            return slot
        if state.get("last_run_date") == now.strftime("%Y-%m-%d"):
            return slot + timedelta(days=1)
        return now  # slot passed today, not yet handled: catch-up run
    last_ts = state.get("last_run_ts")
    if not last_ts:
        return None  # never ran: the loop fires on its next check
    return datetime.fromtimestamp(float(last_ts) + interval * 3600)


def _scheduler_due(state: dict) -> bool:
    """Is the enabled scheduler's slot reached? Daily mode anchors at the set
    hour (with one catch-up run per day); every other interval fires N hours
    after the previous handled slot."""
    interval = int(state.get("interval_hours", 24))
    if interval == 24:
        now = datetime.now()
        slot = now.replace(hour=int(state.get("hour", 2)), minute=0, second=0, microsecond=0)
        return now >= slot and state.get("last_run_date") != now.strftime("%Y-%m-%d")
    last_ts = state.get("last_run_ts")
    if not last_ts:
        return True  # first enable: run on the next check, then every N hours
    return time.time() >= float(last_ts) + interval * 3600


def scheduler_status_payload() -> dict:
    state = load_scheduler_state()
    next_run = scheduler_next_run(state)
    return {
        "state": state,
        "next_run": next_run.isoformat(timespec="seconds") if next_run else None,
        "config_changed": state.get("last_fingerprint") != config_fingerprint(),
        "running": agent_cycle_lock.locked(),
    }


def _scheduler_loop() -> None:
    while True:
        try:
            state = load_scheduler_state()
            if state.get("enabled") and _scheduler_due(state):
                run_tune_cycle_task("schedule")
        except Exception:
            pass  # never let the scheduler thread die; retry on the next tick
        time.sleep(SCHEDULER_CHECK_SECONDS)


def start_scheduler() -> None:
    global _scheduler_thread_started
    if _scheduler_thread_started:
        return
    _scheduler_thread_started = True
    threading.Thread(target=_scheduler_loop, name="pif-tune-scheduler", daemon=True).start()


# ------------------------------------------------------------------ settings

# Human-readable documentation for every configurable setting. Keys map to
# Settings dataclass fields (pif.ini [pif] section), plus the policy.ini
# sections that the firewall hot-reloads.
SETTING_DOCS = {
    "api_token": "API bearer token (write-only: set a new value, never displayed). Stored in .pif-token.",
    "rules_only": "Run without the ML classifier (degraded coverage, rules only).",
    "model_path": "Path to the checksummed classifier artifact.",
    "max_bytes": "Maximum total decoded attachment bytes per request.",
    "max_chars": "Maximum aggregate extracted text characters per request.",
    "parser_timeout": "Hard deadline (seconds) for one parser worker process.",
    "ocr_enabled": "Extract text from images/scanned PDFs via Tesseract (missing executable fails closed).",
    "session_ttl": "Session idle lifetime in seconds.",
    "max_sessions": "Maximum concurrent sessions.",
    "log_dir": "Directory for all rotating log streams.",
    "log_level": "Log verbosity: DEBUG / INFO / WARNING / ERROR / CRITICAL.",
    "log_max_bytes": "Maximum size of one log file before rotation.",
    "log_backup_count": "Rotated log backups kept per stream.",
    "log_console": "Mirror log lines to stderr.",
    "log_content": "Include bounded content previews in logs (controlled local data only).",
    "log_content_max_chars": "Per-preview character cap (0 = unlimited).",
    "log_simple": "Attach the human-readable PIL_SMOD.log narrative stream.",
    "log_script_details": "Include script/function/line attribution in log events.",
    "log_scan_id": "Include the scan correlation id in log events.",
    "block_threshold": "Fused risk at or above which content is blocked.",
    "hard_block_threshold": "Fused risk at or above which blocking skips the sanitize path.",
    "sanitize_threshold": "Fused risk at or above which content is sanitized/isolated.",
    "quarantine_enabled": "Store blocked attachments in the quarantine directory.",
    "quarantine_dir": "Quarantine storage directory.",
    "report_db_enabled": "Record every scan in the SQLite report database (feeds this portal).",
    "report_db_path": "SQLite report database path.",
    "pdf_max_pages": "Maximum PDF pages processed before rejection.",
    "zip_entry_limit": "Maximum entries in an archive (DOCX container).",
    "docx_max_uncompressed_bytes": "Maximum uncompressed DOCX payload (zip-bomb guard).",
    "zip_expansion_limit": "Maximum ZIP compression ratio (expansion-bomb guard).",
    "image_pixel_limit": "Maximum image pixels (decompression-bomb guard).",
    "attachment_max_depth": "Maximum nested attachment depth (archive-in-archive).",
    "max_extracted_segments": "Maximum extracted text segments per request.",
    "policy_file": "Path of the policy INI the firewall hot-reloads.",
}

# pif.ini [pif] keys that map to Settings fields (restart required after edit,
# because the running firewall loads them at startup).
PIF_INI_KEYS = {key for key in SETTING_DOCS if key not in {"api_token"}}

# policy.ini keys (dotted section.key) — these are HOT-RELOADED by the
# running firewall, no restart required.
POLICY_INI_KEYS = {
    "thresholds.sanitize": "Fused risk at or above which content is sanitized/isolated.",
    "thresholds.block": "Fused risk at or above which content is blocked.",
    "thresholds.hard_block": "Fused risk at or above which blocking skips the sanitize path.",
    "actions.allow": "Whether the allow decision is available.",
    "actions.sanitize": "Whether the sanitize decision (span redaction) is available.",
    "actions.block": "Whether blocking is available (falls back to isolate when false).",
    "actions.partial_block": "Whether exact-segment removal is available for external content.",
    "actions.quarantine": "Whether blocked attachments are quarantined.",
    "actions.spotlight": "Wrap sanitized survivors in [PIF-SANITIZED] markers.",
    "detection.rule_engine": "Master switch for the rule/fuzzy/custom-rule layers.",
    "detection.semantic_engine": "Master switch for the ML classifier layer.",
    "detection.context_engine": "Master switch for cross-turn/context analysis.",
    "detection.risk_correlation": "Master switch for decision fusion.",
    "llm_judge.enabled": "Gray-band LLM judge (self-disables without an API key).",
    "llm_judge.model": "Judge model name (OpenAI-compatible endpoint).",
    "llm_judge.api_base": "Judge API base URL.",
    "llm_judge.api_key_env": "Environment variable holding the judge API key.",
    "llm_judge.min_risk": "Minimum fused risk for the judge to review content.",
    "llm_judge.timeout": "Judge request timeout in seconds.",
    "detonation.enabled": "Behavioral detonation chamber (offline emulator decoy).",
    "detonation.decoy": "Decoy type: emulator (offline) or llm (paraphrase-resistant).",
    "detonation.min_risk": "Minimum fused risk for detonation (0.0 = every unblocked scan).",
    "detonation.server_secret_env": "Env variable holding the canary HMAC secret.",
}

_ENV_KEYS = {
    "rules_only": "PIF_RULES_ONLY",
    "model_path": "PIF_MODEL_PATH",
    "ocr_enabled": "PIF_OCR",
    "log_dir": "PIF_LOG_DIR",
    "log_level": "PIF_LOG_LEVEL",
    "log_max_bytes": "PIF_LOG_MAX_BYTES",
    "log_backup_count": "PIF_LOG_BACKUP_COUNT",
    "log_console": "PIF_LOG_CONSOLE",
    "log_content": "PIF_LOG_CONTENT",
    "log_content_max_chars": "PIF_LOG_CONTENT_MAX_CHARS",
    "log_simple": "PIF_LOG_SIMPLE",
    "log_script_details": "PIF_LOG_SCRIPT_DETAILS",
    "log_scan_id": "PIF_LOG_SCAN_ID",
    "block_threshold": "PIF_BLOCK_THRESHOLD",
    "hard_block_threshold": "PIF_HARD_BLOCK_THRESHOLD",
    "sanitize_threshold": "PIF_SANITIZE_THRESHOLD",
    "quarantine_enabled": "PIF_QUARANTINE",
    "quarantine_dir": "PIF_QUARANTINE_DIR",
    "report_db_enabled": "PIF_REPORT_DB",
    "report_db_path": "PIF_REPORT_DB_PATH",
    "pdf_max_pages": "PIF_PDF_MAX_PAGES",
    "zip_entry_limit": "PIF_ZIP_ENTRY_LIMIT",
    "docx_max_uncompressed_bytes": "PIF_DOCX_MAX_UNCOMPRESSED_BYTES",
    "zip_expansion_limit": "PIF_ZIP_EXPANSION_LIMIT",
    "image_pixel_limit": "PIF_IMAGE_PIXEL_LIMIT",
    "attachment_max_depth": "PIF_ATTACHMENT_MAX_DEPTH",
    "max_extracted_segments": "PIF_MAX_EXTRACTED_SEGMENTS",
}

SETTING_GROUPS = {
    "Decision thresholds": ("block_threshold", "hard_block_threshold", "sanitize_threshold"),
    "File formats & limits": (
        "max_bytes", "max_chars", "pdf_max_pages", "zip_entry_limit",
        "docx_max_uncompressed_bytes", "zip_expansion_limit", "image_pixel_limit",
        "attachment_max_depth", "max_extracted_segments", "parser_timeout", "ocr_enabled",
    ),
    "Sessions": ("session_ttl", "max_sessions"),
    "Quarantine & reports": ("quarantine_enabled", "quarantine_dir", "report_db_enabled", "report_db_path"),
    "Logging & privacy": (
        "log_dir", "log_level", "log_max_bytes", "log_backup_count", "log_console",
        "log_content", "log_content_max_chars", "log_simple", "log_script_details", "log_scan_id",
    ),
    "Runtime & model": ("rules_only", "model_path", "api_token", "policy_file"),
}

POLICY_GROUP = {
    "Decision thresholds (hot-reload)": ("thresholds.sanitize", "thresholds.block", "thresholds.hard_block"),
    "Actions (hot-reload)": ("actions.allow", "actions.sanitize", "actions.block", "actions.partial_block", "actions.quarantine", "actions.spotlight"),
    "Detection engines (hot-reload)": ("detection.rule_engine", "detection.semantic_engine", "detection.context_engine", "detection.risk_correlation"),
    "LLM judge (hot-reload)": ("llm_judge.enabled", "llm_judge.model", "llm_judge.api_base", "llm_judge.api_key_env", "llm_judge.min_risk", "llm_judge.timeout"),
    "Detonation chamber (hot-reload)": ("detonation.enabled", "detonation.decoy", "detonation.min_risk", "detonation.server_secret_env"),
}


def _settings_catalog() -> dict:
    """Every configurable setting: current value, declared default, where it
    is set (ini / env / code default), its documentation, and how changes
    apply (hot-reload for policy.ini, restart for pif.ini)."""
    import dataclasses

    from pif.settings import Settings

    fields = {f.name: f for f in dataclasses.fields(Settings)}
    current = Settings.load()
    parser = configparser.ConfigParser()
    parser.read(Path("conf/pif.ini"), encoding="utf-8")
    ini_keys = set(parser["pif"].keys()) if parser.has_section("pif") else set()

    groups = []
    for group_name, keys in SETTING_GROUPS.items():
        items = []
        for key in keys:
            if key not in fields:
                continue
            field = fields[key]
            raw_value = getattr(current, key)
            if key == "api_token":
                display = "configured" if raw_value else "not set"
            else:
                display = str(raw_value)
            source = "default"
            if key in ini_keys:
                source = "conf/pif.ini"
            elif key in _ENV_KEYS and os.getenv(_ENV_KEYS[key]):
                source = "env:" + _ENV_KEYS[key]
            items.append({
                "key": key,
                "value": display,
                "default": "write-only" if key == "api_token" else str(field.default),
                "type": "path" if "path" in str(field.type) or "Path" in str(field.type) else str(field.type),
                "source": source,
                "env": _ENV_KEYS.get(key, ""),
                "description": SETTING_DOCS.get(key, ""),
                "write_only": key == "api_token",
                "restart_required": True,
            })
        groups.append({"group": group_name, "restart_required": True, "items": items})

    policy_parser = configparser.ConfigParser()
    policy_parser.read(Path("conf/policy.ini"), encoding="utf-8")
    for group_name, keys in POLICY_GROUP.items():
        items = []
        for dotted in keys:
            section, _, key = dotted.partition(".")
            value = policy_parser.get(section, key) if policy_parser.has_option(section, key) else ""
            items.append({
                "key": dotted,
                "value": value,
                "default": "",
                "type": "bool" if value.lower() in {"true", "false"} else "str",
                "source": "conf/policy.ini [" + section + "]",
                "env": "",
                "description": POLICY_INI_KEYS.get(dotted, ""),
                "write_only": False,
                "restart_required": False,
            })
        groups.append({"group": group_name, "restart_required": False, "items": items})
    return {"groups": groups}


def _set_ini_key(path: Path, section: str, key: str, value: str) -> None:
    """Update one key in an INI file while PRESERVING comments and ordering:
    a targeted edit of the key line inside its section, inserting after the
    section header when absent, appending the section when missing."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    out, in_section, replaced, section_found = [], False, False, False
    section_header = "[" + section + "]"
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_section and not replaced:
                out.append(key + " = " + value)  # key was absent: insert before next section
                replaced = True
            in_section = stripped == section_header
            section_found = section_found or in_section
            out.append(line)
            continue
        if in_section and "=" in stripped and stripped.split("=")[0].strip() == key:
            out.append(key + " = " + value)
            replaced = True
            continue
        out.append(line)
    if not section_found:
        if out and out[-1].strip():
            out.append("")
        out.append(section_header)
        out.append(key + " = " + value)
    elif not replaced:
        out.append(key + " = " + value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def _coerce(value: str, current_type: str):
    if current_type in ("bool", "<class 'bool'>"):
        lowered = value.strip().lower()
        if lowered not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
            raise ValueError("expected a boolean, got " + repr(value))
        return lowered in {"true", "1", "yes", "on"}
    if current_type in ("int", "<class 'int'>"):
        return int(value)
    if current_type in ("float", "<class 'float'>"):
        return float(value)
    return value


def create_app() -> FastAPI:
    app = FastAPI(title="PIF Admin Portal", docs_url=None, redoc_url=None)

    @app.get("/")
    def index():
        return HTMLResponse(PAGE)

    @app.get("/api/health")
    def health():
        db_size = DB_PATH.stat().st_size / (1024 * 1024) if db_available() else 0
        api_ready = False
        token = load_token()
        if token:
            try:
                with httpx.Client(trust_env=False, timeout=3) as client:
                    response = client.get(PIF_API.rstrip("/") + "/ready",
                                          headers={"Authorization": f"Bearer {token}"})
                    api_ready = response.status_code == 200
            except httpx.HTTPError:
                api_ready = False
        return {"db": db_available(), "db_size_mb": round(db_size, 2), "api_ready": api_ready}

    @app.get("/api/stats")
    def stats():
        if not db_available():
            return JSONResponse({"error": "report.db not found — run a scan first"}, status_code=503)
        with connect_db() as connection:
            total = connection.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
            by_decision = {
                row["decision"]: row["n"]
                for row in connection.execute("SELECT decision, COUNT(*) AS n FROM scans GROUP BY decision")
            }
            findings = connection.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
            attacks = {
                row["category"]: row["n"]
                for row in connection.execute(
                    "SELECT category, COUNT(*) AS n FROM findings GROUP BY category ORDER BY n DESC"
                )
            }
        return {"total": total, "by_decision": by_decision, "findings": findings, "by_attack": attacks}

    def query_scans(where: str, params: tuple, limit: int, offset: int):
        with connect_db() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) AS n FROM scans {where}", params
            ).fetchone()["n"]
            rows = connection.execute(
                f"SELECT * FROM scans {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
        return total, [decode_row(dict(row)) for row in rows]

    @app.get("/api/scans")
    def scans(limit: int = 50, offset: int = 0, decision: str = "", search: str = ""):
        if not db_available():
            return JSONResponse({"error": "report.db not found — run a scan first"}, status_code=503)
        limit = max(1, min(limit, 2000))   # page sizes the history dropdown offers
        clauses, params = [], []
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if search:
            clauses.append("(scan_id LIKE ? OR user_prompt LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        total, rows = query_scans(where, tuple(params), limit, max(0, offset))
        for row in rows:
            row.pop("request_json", None)
            row.pop("result_json", None)
            row["finding_count"] = 0
        if rows:
            with connect_db() as connection:
                counts = dict(connection.execute(
                    f"SELECT scan_id, COUNT(*) AS n FROM findings WHERE scan_id IN "
                    f"({','.join('?' * len(rows))}) GROUP BY scan_id",
                    [row["scan_id"] for row in rows],
                ).fetchall())
            for row in rows:
                row["finding_count"] = counts.get(row["scan_id"], 0)
        return {"total": total, "rows": rows}

    @app.get("/api/live")
    def live(after_id: int = 0, limit: int = 50):
        if not db_available():
            return {"rows": []}
        _, rows = query_scans("WHERE id > ?", (after_id,), max(1, min(limit, 100)), 0)
        for row in rows:
            row.pop("request_json", None)
            row.pop("result_json", None)
        return {"rows": rows}

    @app.get("/api/scans/{scan_id}")
    def scan_detail(scan_id: str):
        if not db_available():
            return JSONResponse({"error": "report.db not found — run a scan first"}, status_code=503)
        with connect_db() as connection:
            row = connection.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row is None:
                return JSONResponse({"error": "scan not found"}, status_code=404)
            findings = [
                dict(finding)
                for finding in connection.execute(
                    "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
                )
            ]
        detail = decode_row(dict(row))
        detail["findings"] = findings
        return detail

    @app.get("/api/rule_hits")
    def rule_hits(rule_id: str = "", limit: int = 25):
        """Recent scans in which one detection (rule_id) actually fired — feeds
        the 'Recent hits' tab of the Rules & Engines detail modal."""
        rule_id = rule_id.strip()
        if not rule_id:
            return JSONResponse({"error": "rule_id is required"}, status_code=400)
        if not db_available():
            return JSONResponse({"error": "report.db not found — run a scan first"}, status_code=503)
        limit = max(1, min(limit, 100))
        with connect_db() as connection:
            total = connection.execute(
                "SELECT COUNT(*) AS n FROM findings WHERE rule_id = ?", (rule_id,)
            ).fetchone()["n"]
            rows = connection.execute(
                "SELECT f.ts, f.scan_id, f.source_id, f.source, f.layer, f.severity, f.evidence,"
                " s.decision, s.risk, s.risk_level, s.user_prompt, s.malicious"
                " FROM findings f LEFT JOIN scans s ON s.scan_id = f.scan_id"
                " WHERE f.rule_id = ? ORDER BY f.id DESC LIMIT ?",
                (rule_id, limit),
            ).fetchall()
        hits = [dict(row) for row in rows]
        for hit in hits:
            prompt = hit.get("user_prompt") or ""
            if len(prompt) > 140:
                hit["user_prompt"] = prompt[:140] + "…"
        return {"rule_id": rule_id, "total": total, "hits": hits}

    @app.get("/api/agent")
    def agent_status():
        return agent_status_payload()

    @app.post("/api/agent/tune")
    async def agent_tune(request: Request):
        agent = agent_module()
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not agent_cycle_lock.acquire(blocking=False):
            return JSONResponse(
                {"error": "another tune cycle is already running (manual or scheduled)"},
                status_code=409,
            )
        corpus = DEMO_CORPUS if (body or {}).get("corpus", "demo") == "demo" else FULL_CORPUS
        started = time.perf_counter()
        try:
            agent_instance = agent.RedTeamAgent(
                corpus_path=corpus,
                benign_sample=int((body or {}).get("benign_sample", 200)),
                attack_per_category=int((body or {}).get("attack_per_category", 20)),
            )
            # blocking scans must not freeze the portal's event loop
            summary = await run_in_threadpool(agent_instance.run_tune_cycle)
        except Exception as error:  # surface agent failures to the operator
            return JSONResponse({"error": f"{type(error).__name__}: {error}"}, status_code=500)
        finally:
            agent_cycle_lock.release()
        # A manual full run is equally valid as "last completed cycle" for the
        # scheduler's hash gate: same inputs, same verdict.
        _record_cycle_result(
            "manual", "completed", summary=summary,
            seconds=time.perf_counter() - started, fingerprint=config_fingerprint(),
        )
        return {"summary": summary, "status": agent_status_payload()}

    @app.post("/api/agent/approve")
    async def agent_approve(request: Request):
        agent = agent_module()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        candidate_id = str(body.get("candidate_id") or "")
        if not candidate_id:
            return JSONResponse({"error": "candidate_id required"}, status_code=400)
        corpus = FULL_CORPUS if body.get("scope") == "full" else None
        reason = str(body.get("reason") or "").strip()[:300]
        verifier = agent.RedTeamAgent(corpus_path=FULL_CORPUS)
        try:
            entry = await run_in_threadpool(
                lambda: verifier.approve(candidate_id, corpus=corpus, reason=reason)
            )
        except Exception as error:
            return JSONResponse({"error": f"{type(error).__name__}: {error}"}, status_code=400)
        return {"entry": entry, "policy": policy_override_state()}

    @app.post("/api/agent/reject")
    async def agent_reject(request: Request):
        agent = agent_module()
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        candidate_id = str(body.get("candidate_id") or "")
        if not candidate_id:
            return JSONResponse({"error": "candidate_id required"}, status_code=400)
        reason = str(body.get("reason") or "").strip()[:300]
        try:
            entry = agent.RedTeamAgent(corpus_path=FULL_CORPUS).reject(candidate_id, reason=reason)
        except Exception as error:
            return JSONResponse({"error": f"{type(error).__name__}: {error}"}, status_code=400)
        return {"entry": entry}

    @app.post("/api/validate")
    async def validate(request: Request):
        token = load_token()
        if not token:
            return JSONResponse(
                {"error": "PIF API token not configured (run scripts/main.py --init-token)"},
                status_code=503,
            )
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)

        prompt = str(body.get("prompt") or "")[:250_000]
        files = []
        for item in list(body.get("files") or [])[:10]:
            files.append(
                {
                    "name": str(item.get("name") or "attachment")[:255],
                    "type": str(item.get("type") or "application/octet-stream")[:100],
                    "data_base64": str(item.get("data_base64") or "")[:14_000_000],
                }
            )
        payload = {"user_prompt": prompt, "files": files}
        headers = {"Authorization": f"Bearer {token}", "X-PIF-Trace-ID": str(uuid.uuid4())}
        try:
            async with httpx.AsyncClient(trust_env=False, timeout=120) as client:
                response = await client.post(
                    PIF_API.rstrip("/") + "/v1/scan", json=payload, headers=headers
                )
        except httpx.HTTPError:
            return JSONResponse(
                {"error": f"PIF API unreachable at {PIF_API} — start scripts/main.py first"},
                status_code=502,
            )
        try:
            result = response.json()
        except json.JSONDecodeError:
            result = None
        return JSONResponse({"http_status": response.status_code, "result": result})

    @app.get("/api/benchmarks")
    def benchmarks_get():
        """Independent-evidence panel: the frozen public-dataset results and
        the layer ablation, exactly as published in reports/. Read-only — the
        numbers come from the same JSON files the README cites."""
        out = {"public": None, "ablation": None, "internal": None}
        public_path = Path("reports/evaluation_public.json")
        if public_path.is_file():
            try:
                data = json.loads(public_path.read_text(encoding="utf-8"))
                out["public"] = {
                    "datasets": data.get("datasets", {}),
                    "freeze_manifest": data.get("freeze_manifest", {}),
                    "unavailable": data.get("unavailable", []),
                }
            except (ValueError, OSError):
                pass
        ablation_path = Path("reports/ablation.json")
        if ablation_path.is_file():
            try:
                raw = json.loads(ablation_path.read_text(encoding="utf-8"))
                out["ablation"] = {
                    "columns": [
                        {"config": c["config"], "aggregate": c["aggregate"]}
                        for c in raw.get("columns", [])
                    ],
                    "judge_column": raw.get("judge_column"),
                }
            except (ValueError, OSError):
                pass
        eval_path = Path("reports/evaluation.json")
        if eval_path.is_file():
            try:
                data = json.loads(eval_path.read_text(encoding="utf-8"))
                out["internal"] = {
                    "attack_recall": data.get("attack_recall"),
                    "benign_fpr": data.get("benign_false_positive_rate"),
                    "release_gate": data.get("numerical_release_gate"),
                    "provenance_note": (data.get("provenance_note") or "")[:220],
                }
            except (ValueError, OSError):
                pass
        return JSONResponse(out)

    @app.get("/api/stats/range")
    def stats_range(from_ts: str = "", to_ts: str = ""):
        """Attack-pattern analytics for a date/time range (management view):
        attack types with frequency, hour-of-day distribution, daily decision
        timeline and top-fired rules — all from report.db, read-only."""
        if not db_available():
            return JSONResponse({"error": "report.db not found — run a scan first"}, status_code=503)
        # Range: inclusive date/datetime strings; empty means full history.
        from_clause, params = "", []
        if from_ts:
            from_clause += " AND s.ts >= ?"
            params.append(from_ts)
        if to_ts:
            # a bare date (10 chars) is inclusive through the whole day
            to_value = to_ts + "T23:59:59.999999" if len(to_ts) == 10 else to_ts
            from_clause += " AND s.ts <= ?"
            params.append(to_value)

        with connect_db() as connection:
            totals = connection.execute(
                f"""SELECT COUNT(*) AS total,
                           SUM(decision = 'block') AS blocked,
                           SUM(decision = 'sanitize') AS sanitized,
                           SUM(decision = 'isolate') AS isolated,
                           SUM(decision = 'allow') AS allowed,
                           AVG(risk) AS avg_risk,
                           MAX(risk) AS max_risk,
                           SUM(COALESCE(malicious, 0)) AS malicious_count
                    FROM scans s WHERE 1=1 {from_clause}""",
                params,
            ).fetchone()

            by_category = connection.execute(
                f"""SELECT f.category, COUNT(*) AS hits, MAX(f.severity) AS max_severity,
                           SUM(f.severity >= 0.5) AS actionable
                    FROM findings f JOIN scans s ON s.scan_id = f.scan_id
                    WHERE f.category IS NOT NULL {from_clause}
                    GROUP BY f.category ORDER BY hits DESC""",
                params,
            ).fetchall()

            by_hour = connection.execute(
                f"""SELECT CAST(strftime('%H', f.ts) AS INTEGER) AS hour, COUNT(*) AS hits
                    FROM findings f JOIN scans s ON s.scan_id = f.scan_id
                    WHERE f.category IS NOT NULL {from_clause}
                    GROUP BY hour ORDER BY hour""",
                params,
            ).fetchall()

            by_day = connection.execute(
                f"""SELECT substr(s.ts, 1, 10) AS day,
                           SUM(s.decision = 'block') AS blocked,
                           SUM(s.decision = 'sanitize') AS sanitized,
                           SUM(s.decision = 'isolate') AS isolated,
                           SUM(s.decision = 'allow') AS allowed,
                           COUNT(*) AS total
                    FROM scans s WHERE 1=1 {from_clause}
                    GROUP BY day ORDER BY day""",
                params,
            ).fetchall()

            top_rules = connection.execute(
                f"""SELECT f.rule_id, f.category, COUNT(*) AS hits
                    FROM findings f JOIN scans s ON s.scan_id = f.scan_id
                    WHERE f.rule_id IS NOT NULL AND f.rule_id != '' {from_clause}
                    GROUP BY f.rule_id ORDER BY hits DESC LIMIT 12""",
                params,
            ).fetchall()

            by_source = connection.execute(
                f"""SELECT COALESCE(NULLIF(f.source, ''), f.source_id) AS src, COUNT(*) AS hits
                    FROM findings f JOIN scans s ON s.scan_id = f.scan_id
                    WHERE f.category IS NOT NULL {from_clause}
                    GROUP BY src ORDER BY hits DESC LIMIT 8""",
                params,
            ).fetchall()

            # File-type attribution: a finding on file:N maps to the Nth name
            # in the scan's file_names — the attack channel (PDF vs image vs
            # DOCX vs email...) management asks about.
            file_rows = connection.execute(
                f"""SELECT f.source_id, s.file_names
                    FROM findings f JOIN scans s ON s.scan_id = f.scan_id
                    WHERE f.category IS NOT NULL AND f.source_id LIKE 'file:%' {from_clause}""",
                params,
            ).fetchall()
            by_filetype: dict[str, int] = {}
            for row in file_rows:
                try:
                    names = json.loads(row["file_names"] or "[]")
                except (ValueError, TypeError):
                    names = []
                try:
                    index = int(str(row["source_id"]).split(":")[1])
                except (IndexError, ValueError):
                    index = -1
                name = names[index] if 0 <= index < len(names) else ""
                ext = Path(name).suffix.lstrip(".").lower() or "unknown"
                by_filetype[ext] = by_filetype.get(ext, 0) + 1
            filetype_list = sorted(by_filetype.items(), key=lambda item: -item[1])[:10]

        return JSONResponse({
            "range": {"from": from_ts or "beginning", "to": to_ts or "now"},
            "totals": {
                "total": totals["total"] or 0,
                "blocked": totals["blocked"] or 0,
                "sanitized": totals["sanitized"] or 0,
                "isolated": totals["isolated"] or 0,
                "allowed": totals["allowed"] or 0,
                "malicious": totals["malicious_count"] or 0,
                "avg_risk": round(totals["avg_risk"], 3) if totals["avg_risk"] is not None else None,
                "max_risk": totals["max_risk"],
            },
            "by_category": [dict(row) for row in by_category],
            "by_hour": [dict(row) for row in by_hour],
            "by_day": [dict(row) for row in by_day],
            "top_rules": [dict(row) for row in top_rules],
            "by_source": [dict(row) for row in by_source],
            "by_filetype": [{"filetype": ext, "hits": hits} for ext, hits in filetype_list],
        })

    @app.get("/api/settings")
    def settings_get():
        """Every configurable setting: current value, source, documentation,
        and how a change applies (hot-reload vs restart)."""
        try:
            return JSONResponse(_settings_catalog())
        except Exception as error:  # noqa: BLE001
            return JSONResponse({"error": str(error)}, status_code=500)

    @app.post("/api/settings")
    async def settings_post(request: Request):
        """Change one setting. pif.ini keys take effect on API restart; the
        api_token is write-only; policy.ini keys hot-reload in the running
        firewall. Values are validated against the declared type before any
        file is touched."""
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        key = str(body.get("key", ""))
        value = str(body.get("value", ""))
        if not key:
            return JSONResponse({"error": "missing 'key'"}, status_code=400)
        try:
            if key == "api_token":
                if not value.strip():
                    return JSONResponse({"error": "token cannot be empty"}, status_code=400)
                token_path = Path(".pif-token")
                token_path.write_text(value.strip(), encoding="utf-8")
                token_path.chmod(0o600)
                return JSONResponse({"applied": True, "key": key, "restart_required": True,
                                     "note": "token stored in .pif-token; restart the PIF API to use it"})
            if key in POLICY_INI_KEYS:
                section, _, ini_key = key.partition(".")
                policy_path = Path("conf/policy.ini")
                current = configparser.ConfigParser()
                current.read(policy_path, encoding="utf-8")
                existing = current.get(section, ini_key) if current.has_option(section, ini_key) else ""
                kind = "bool" if existing.lower() in {"true", "false"} else ("int" if existing.lstrip("-").isdigit() and existing else "float" if existing.replace(".", "", 1).isdigit() and existing else "str")
                coerced = _coerce(value, kind)
                display = str(coerced).lower() if isinstance(coerced, bool) else str(coerced)
                _set_ini_key(policy_path, section, ini_key, display)
                return JSONResponse({"applied": True, "key": key, "hot_reload": True,
                                     "note": "the firewall hot-reloads conf/policy.ini on its next scan"})
            if key in PIF_INI_KEYS:
                import dataclasses as _dataclasses
                from pif.settings import Settings as _Settings
                field = next(f for f in _dataclasses.fields(_Settings) if f.name == key)
                coerced = _coerce(value, str(field.type))
                _set_ini_key(Path("conf/pif.ini"), "pif", key, str(coerced))
                return JSONResponse({"applied": True, "key": key, "restart_required": True,
                                     "note": "stored in conf/pif.ini; restart the PIF API to apply"})
            return JSONResponse({"error": "unknown or read-only setting: " + key}, status_code=400)
        except ValueError as error:
            return JSONResponse({"error": str(error)}, status_code=400)
        except Exception as error:  # noqa: BLE001
            return JSONResponse({"error": str(error)}, status_code=500)

    @app.get("/api/policy")
    def policy_get():
        """Proxy: live policy document (engines, stage map, every detection)
        from GET /v1/policy — feeds the Rules view and agent rule details."""
        token = load_token()
        if not token:
            return JSONResponse(
                {"error": "PIF API token not configured (run scripts/main.py --init-token)"},
                status_code=503,
            )
        try:
            with httpx.Client(trust_env=False, timeout=10) as client:
                response = client.get(
                    PIF_API.rstrip("/") + "/v1/policy",
                    headers={"Authorization": f"Bearer {token}"},
                )
        except httpx.HTTPError:
            return JSONResponse(
                {"error": f"PIF API unreachable at {PIF_API} — start scripts/main.py first"},
                status_code=502,
            )
        try:
            payload = response.json()
        except json.JSONDecodeError:
            payload = {"error": f"PIF API returned HTTP {response.status_code}"}
        return JSONResponse(payload, status_code=response.status_code)

    @app.get("/api/agent/scheduler")
    def agent_scheduler_status():
        return scheduler_status_payload()

    @app.post("/api/agent/scheduler")
    async def agent_scheduler_update(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        state = load_scheduler_state()
        if "enabled" in body:
            state["enabled"] = bool(body["enabled"])
        if "hour" in body:
            try:
                hour = int(body["hour"])
            except (TypeError, ValueError):
                return JSONResponse({"error": "hour must be an integer"}, status_code=400)
            if not 0 <= hour <= 23:
                return JSONResponse({"error": "hour must be 0-23"}, status_code=400)
            state["hour"] = hour
        if "interval_hours" in body:
            try:
                interval = int(body["interval_hours"])
            except (TypeError, ValueError):
                return JSONResponse({"error": "interval_hours must be an integer"}, status_code=400)
            if not 1 <= interval <= 168:
                return JSONResponse({"error": "interval_hours must be 1-168"}, status_code=400)
            state["interval_hours"] = interval
        if "corpus" in body:
            if body["corpus"] not in ("demo", "full"):
                return JSONResponse({"error": "corpus must be demo or full"}, status_code=400)
            state["corpus"] = body["corpus"]
        _write_json_file(SCHEDULER_STATE_PATH, state)
        return scheduler_status_payload()

    @app.post("/api/agent/scheduler/run")
    async def agent_scheduler_run():
        # Explicit button press: force=True bypasses the hash gate (the human
        # asked for a cycle NOW), but the busy check still applies.
        result = await run_in_threadpool(lambda: run_tune_cycle_task("manual", force=True))
        if result.get("outcome") == "busy":
            return JSONResponse({"error": "another tune cycle is already running"}, status_code=409)
        return {"result": result, "status": agent_status_payload(), "scheduler": scheduler_status_payload()}

    start_scheduler()
    return app


if __name__ == "__main__":
    uvicorn.run(create_app(), host="127.0.0.1", port=PORTAL_PORT, access_log=False)
