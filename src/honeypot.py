from flask import Flask, request, render_template_string, jsonify
import time
import json
import urllib.request
import threading
from pathlib import Path
import ipaddress

app = Flask(__name__)
HONEYPOT_LOG = Path('honeypot_interactions.json')
DASHBOARD_URL = "http://127.0.0.1:5010/events"


def _is_loopback_or_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def resolve_client_ip() -> tuple[str, str]:
    """Resolve best-effort attacker IP.

    Returns:
        (attributed_ip, socket_ip)
    """
    socket_ip = request.remote_addr or "unknown"

    # Common proxy/header chain support.
    # If a reverse proxy is in front of honeypot, this preserves real source.
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first, socket_ip

    x_real = request.headers.get("X-Real-IP", "").strip()
    if x_real:
        return x_real, socket_ip

    x_orig = request.headers.get("X-Original-Source-IP", "").strip()
    if x_orig:
        return x_orig, socket_ip

    # Demo fallback for local testing only: allow explicit src hint.
    hinted = (request.form.get("src_ip") or request.args.get("src_ip") or "").strip()
    if hinted and _is_loopback_or_private(socket_ip):
        return hinted, socket_ip

    return socket_ip, socket_ip

def log_interaction(data):
    attributed_ip, socket_ip = resolve_client_ip()
    logs = []
    if HONEYPOT_LOG.exists():
        try:
            logs = json.loads(HONEYPOT_LOG.read_text())
        except: logs = []
    
    logs.append({
        "time": time.time(),
        "src_ip": attributed_ip,
        "socket_ip": socket_ip,
        "method": request.method,
        "path": request.path,
        "payload": data,
        "user_agent": request.headers.get('User-Agent')
    })
    HONEYPOT_LOG.write_text(json.dumps(logs, indent=2))
    
    # Send to main dashboard as a 'honeypot_hit'
    try:
        hit_event = {
            "type": "honeypot_hit",
            "time": time.time(),
            "src_ip": attributed_ip,
            "socket_ip": socket_ip,
            "path": request.path,
            "method": request.method
        }
        req = urllib.request.Request(DASHBOARD_URL, 
                                  data=json.dumps(hit_event).encode(),
                                  headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=0.1)
    except: pass

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        log_interaction(request.form.to_dict())
        return render_template_string("""
            <h2 style='color: red;'>AUTHENTICATION FAILED</h2>
            <p>System is under high load. Please try again later.</p>
            <a href='/'>Retry</a>
        """), 401
    
    return render_template_string("""
    <html>
    <head><title>ISDNF - Shadow Admin Portal</title></head>
    <body style="background: #0f172a; color: #94a3b8; font-family: monospace; padding: 50px;">
        <div style="border: 1px solid #1e293b; padding: 20px; max-width: 400px; margin: 0 auto; box-shadow: 0 0 20px rgba(0,0,0,0.5);">
            <h1 style="color: #38bdf8;">SECURE ADMIN LOGIN</h1>
            <p style="font-size: 10px; color: #475569;">UNAUTHORIZED ACCESS IS PROHIBITED. IP LOGGED.</p>
            <form method="POST">
                <div style="margin-bottom: 10px;">
                    <label>Username</label><br>
                    <input type="text" name="user" style="width: 100%; background: #1e293b; border: 1px solid #334155; color: white;">
                </div>
                <div style="margin-bottom: 20px;">
                    <label>Password</label><br>
                    <input type="password" name="pass" style="width: 100%; background: #1e293b; border: 1px solid #334155; color: white;">
                </div>
                <button type="submit" style="background: #38bdf8; color: #0f172a; border: none; padding: 10px 20px; font-weight: bold; cursor: pointer;">LOGIN</button>
            </form>
        </div>
    </body>
    </html>
    """)

@app.route('/health')
def health():
    return jsonify({"status": "running", "type": "DECEPTION_NODE_01"})

if __name__ == '__main__':
    print("ISDNF Honeypot (Shadow Admin) starting on port 8080...")
    app.run(port=8080, host='0.0.0.0', debug=False)
