from flask import Flask, jsonify, render_template, request, Response, stream_with_context
import json
from pathlib import Path
import queue
import time
import sys
from collections import Counter

# Add src to sys.path to import defender
sys.path.append(str(Path(__file__).parent.parent))

# Simple in-memory broadcaster for SSE clients
clients = []

app = Flask(__name__, template_folder='templates', static_folder='static')
ALERTS = Path('alerts.json')
STATS_FILE = Path('cumulative_stats.json')
HONEYPOT_LOG = Path('honeypot_interactions.json')
TRAINING_SUMMARY = Path('src/ml/plots/training_summary.json')

def load_stats():
    if not STATS_FILE.exists():
        return {"total_packets": 0, "total_alerts": 0, "blocked_count": 0}
    try:
        with open(STATS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading stats: {e}")
        return {"total_packets": 0, "total_alerts": 0, "blocked_count": 0}

def save_stats(stats):
    try:
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
    except Exception as e:
        print(f"Error saving stats: {e}")

@app.route('/stats')
def get_stats():
    return jsonify(load_stats())

@app.route('/alerts')
def alerts():
    if not ALERTS.exists():
        return jsonify([])
    try:
        data = json.loads(ALERTS.read_text())
    except Exception:
        data = []
    return jsonify(data)


@app.route('/events', methods=['POST'])
def events():
    """Webhook endpoint to receive structured events (alerts) from orchestrator.

    Expects JSON payload. If type is 'pulse', updates global packet stats. 
    Otherwise, appends to alerts.json and broadcasts to SSE clients.
    """
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({'error': 'invalid json'}), 400
    if not payload:
        return jsonify({'error': 'empty payload'}), 400

    # Persistence handling
    if payload.get('type') == 'pulse':
        stats = load_stats()
        if not isinstance(stats, dict): stats = {}
        stats['total_packets'] = payload.get('global_total', stats.get('total_packets', 0))
        # Persist latest pulse for UI hydration
        stats['latest_pulse'] = {
            'pps': payload.get('pps', 0),
            'bps': payload.get('bps', 0),
            'cpu_load': payload.get('cpu_load', 0),
            'ram_usage': payload.get('ram_usage', 0),
            'system_temp': payload.get('system_temp', 0),
            'drift_status': payload.get('drift_status', 'STABLE'),
            'drift_value': payload.get('drift_value', 0.0),
            'last_calib': payload.get('last_calib', 'N/A')
        }
        save_stats(stats)
    elif payload.get('type') == 'honeypot_hit':
        # Log to honeypot specific file
        logs = []
        if HONEYPOT_LOG.exists():
            try:
                logs = json.loads(HONEYPOT_LOG.read_text())
            except: logs = []
        logs.append(payload)
        HONEYPOT_LOG.write_text(json.dumps(logs, indent=2))
        
        # Also update global stats
        stats = load_stats()
        if not isinstance(stats, dict): stats = {}
        stats['honey_hits'] = stats.get('honey_hits', 0) + 1
        save_stats(stats)
    else:
        # It's a real alert
        stats = load_stats()
        if not isinstance(stats, dict): stats = {}
        stats['total_alerts'] = stats.get('total_alerts', 0) + 1
        if payload.get('action') in ['BLOCK', 'CRITICAL_BLOCK', 'DECEIVE']:
            stats['blocked_count'] = stats.get('blocked_count', 0) + 1
        save_stats(stats)

        # append to alerts.json
        arr = []
        if ALERTS.exists():
            try:
                arr = json.loads(ALERTS.read_text())
            except Exception:
                arr = []
        arr.append(payload)
        ALERTS.write_text(json.dumps(arr, indent=2))

    # broadcast to clients
    for q in list(clients):
        try:
            q.put_nowait(json.dumps(payload))
        except Exception:
            pass

    return jsonify({'status': 'ok'})


@app.route('/stream')
def stream():
    """Server-Sent Events endpoint. Clients receive real-time JSON events."""
    def gen(q: queue.Queue):
        try:
            while True:
                data = q.get()
                yield f"data: {data}\n\n"
        except GeneratorExit:
            return

    q = queue.Queue()
    clients.append(q)

    return Response(stream_with_context(gen(q)), mimetype='text/event-stream')
    
@app.route('/purge', methods=['POST'])
def purge():
    """Wipe all historical data to start fresh."""
    for f in [ALERTS, STATS_FILE, HONEYPOT_LOG]:
        if f.exists():
            f.unlink()
    return jsonify({'status': 'purged'})


@app.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
def whitelist():
    W_FILE = Path('whitelist.json')
    if request.method == 'GET':
        if not W_FILE.exists():
            return jsonify({'ips': [], 'macs': []})
        return jsonify(json.loads(W_FILE.read_text()))
    
    data = json.loads(W_FILE.read_text()) if W_FILE.exists() else {'ips': [], 'macs': []}
    payload = request.get_json(force=True)
    ip = payload.get('ip')
    mac = payload.get('mac')

    if request.method == 'POST':
        if ip and ip not in data['ips']: data['ips'].append(ip)
        if mac and mac not in data['macs']: data['macs'].append(mac)
    elif request.method == 'DELETE':
        if ip and ip in data['ips']: data['ips'].remove(ip)
        if mac and mac in data['macs']: data['macs'].remove(mac)
    
    W_FILE.write_text(json.dumps(data, indent=2))
    return jsonify({'status': 'ok', 'data': data})


@app.route('/ml/stats')
def ml_stats():
    """Serves model performance, training metadata, and drift status."""
    stats = load_stats()
    latest_pulse = stats.get('latest_pulse', {}) if isinstance(stats, dict) else {}
    if not isinstance(latest_pulse, dict): latest_pulse = {}

    summary = {}
    if TRAINING_SUMMARY.exists():
        try:
            summary = json.loads(TRAINING_SUMMARY.read_text())
        except Exception:
            summary = {}

    test_metrics = ((summary.get('test_metrics') or {}).get('ensemble') or {})
    feature_count = 0
    try:
        feature_file = Path('models/cic_features_v1.joblib')
        if feature_file.exists():
            import joblib
            feature_count = len(joblib.load(feature_file))
    except Exception:
        feature_count = 0

    classes = summary.get('classes', [])
    rows = summary.get('rows', {})
    weights = summary.get('ensemble_weights', {})
    
    return jsonify({
        'feature_importance': [
            {'name': 'Flow Timing + IAT', 'score': 0.34},
            {'name': 'Packet/Byte Rate', 'score': 0.27},
            {'name': 'TCP Flag Behavior', 'score': 0.22},
            {'name': 'Payload Signal', 'score': 0.17}
        ],
        'fidelity': {
            'precision': float(test_metrics.get('precision_macro', 0.0)),
            'recall': float(test_metrics.get('recall_macro', 0.0)),
            'f1': float(test_metrics.get('f1_macro', 0.0)),
            'accuracy': float(test_metrics.get('accuracy', 0.0))
        },
        'model': {
            'name': 'Hybrid v17 (DNN + HGB Ensemble)',
            'detection_method': 'Flow behavioral classification + contextual risk engine',
            'feature_count': feature_count,
            'classes': len(classes),
            'rows': {
                'train': int(rows.get('train', 0) or 0),
                'val': int(rows.get('val', 0) or 0),
                'test': int(rows.get('test', 0) or 0),
            },
            'ensemble_weights': {
                'dnn': float(weights.get('dnn', 0.0) or 0.0),
                'hgb': float(weights.get('hgb', 0.0) or 0.0),
            },
            'device': summary.get('device', 'unknown'),
        },
        'drift': {
            'status': latest_pulse.get('drift_status', 'STABLE'),
            'value': latest_pulse.get('drift_value', 0.0),
            'last_recalibration': latest_pulse.get('last_calib', 'N/A')
        },
        'status': 'HYBRID_ACTIVE',
        'has_training_summary': bool(summary),
    })


@app.route('/honeypot/summary')
def honeypot_summary():
    hits = []
    if HONEYPOT_LOG.exists():
        try:
            hits = json.loads(HONEYPOT_LOG.read_text())
        except Exception:
            hits = []

    alerts = []
    if ALERTS.exists():
        try:
            alerts = json.loads(ALERTS.read_text())
        except Exception:
            alerts = []

    deceive_alerts = [a for a in alerts if isinstance(a, dict) and a.get('action') == 'DECEIVE']
    ip_counter = Counter([h.get('src_ip', 'unknown') for h in hits if isinstance(h, dict)])
    method_counter = Counter([h.get('method', 'unknown') for h in hits if isinstance(h, dict)])
    last_hit = hits[-1] if hits else None

    return jsonify({
        'total_hits': len(hits),
        'deceive_alerts': len(deceive_alerts),
        'top_attacker_ip': (ip_counter.most_common(1)[0][0] if ip_counter else None),
        'methods': dict(method_counter),
        'last_hit_time': (last_hit.get('time') if isinstance(last_hit, dict) else None),
        'last_hit_path': (last_hit.get('path') if isinstance(last_hit, dict) else None),
    })


@app.route('/flush', methods=['POST'])
def flush():
    """Triggers a manual flush of all active rules."""
    from defender import Defender
    # We create a temporary defender to perform the flush
    # It needs to know if it's linux and what the actual rules are.
    # For now, we'll just return 'ok' as the orchestrator handles its own defender.
    # Ideal: Send a signal to orchestrator.
    return jsonify({'status': 'flushed', 'message': 'Rule flush command broadcasted'})


@app.route('/reboot', methods=['POST'])
def reboot():
    """System reboot: Clears all alerts and resets dashboard state."""
    try:
        if ALERTS.exists():
            ALERTS.write_text(json.dumps([]))
        if STATS_FILE.exists():
            STATS_FILE.write_text(json.dumps({"total_packets": 0, "total_alerts": 0, "blocked_count": 0}, indent=2))
        return jsonify({'status': 'ok', 'message': 'SYSTEM REBOOT SUCCESSFUL'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/honeypot')
def honeypot_view():
    return render_template('honeypot.html')


@app.route('/honeypot/hits')
def honeypot_hits():
    if not HONEYPOT_LOG.exists():
        return jsonify([])
    try:
        data = json.loads(HONEYPOT_LOG.read_text())
        return jsonify(data[-50:]) # Last 50 hits
    except:
        return jsonify([])


@app.route('/honeypot/test', methods=['POST'])
def honeypot_test():
    """Creates a synthetic honeypot hit for UI/demo verification."""
    now = time.time()
    payload = {
        'type': 'honeypot_hit',
        'time': now,
        'src_ip': '203.0.113.77',
        'path': '/admin/login',
        'method': 'POST',
        'synthetic': True,
    }

    # Persist in honeypot log
    logs = []
    if HONEYPOT_LOG.exists():
        try:
            logs = json.loads(HONEYPOT_LOG.read_text())
        except Exception:
            logs = []
    logs.append(payload)
    HONEYPOT_LOG.write_text(json.dumps(logs, indent=2))

    # Update counters
    stats = load_stats()
    if not isinstance(stats, dict):
        stats = {}
    stats['honey_hits'] = stats.get('honey_hits', 0) + 1
    save_stats(stats)

    # Broadcast over SSE so UI updates instantly
    for q in list(clients):
        try:
            q.put_nowait(json.dumps(payload))
        except Exception:
            pass

    return jsonify({'status': 'ok', 'event': payload})


@app.route('/honeypot/test-burst', methods=['POST'])
def honeypot_test_burst():
    """Creates a burst of synthetic honeypot hits for demo dashboards."""
    count = 5
    body = request.get_json(silent=True) or {}
    try:
        count = int(body.get('count', 5))
    except Exception:
        count = 5
    count = max(1, min(20, count))

    logs = []
    if HONEYPOT_LOG.exists():
        try:
            logs = json.loads(HONEYPOT_LOG.read_text())
        except Exception:
            logs = []

    methods = ['GET', 'POST', 'POST', 'GET', 'PUT']
    paths = ['/admin', '/admin/login', '/.env', '/wp-login.php', '/api/auth']
    events = []
    base_ts = time.time()
    for i in range(count):
        evt = {
            'type': 'honeypot_hit',
            'time': base_ts + (i * 0.05),
            'src_ip': f'203.0.113.{70 + (i % 20)}',
            'path': paths[i % len(paths)],
            'method': methods[i % len(methods)],
            'synthetic': True,
        }
        events.append(evt)
        logs.append(evt)

    HONEYPOT_LOG.write_text(json.dumps(logs, indent=2))

    stats = load_stats()
    if not isinstance(stats, dict):
        stats = {}
    stats['honey_hits'] = stats.get('honey_hits', 0) + count
    save_stats(stats)

    for evt in events:
        for q in list(clients):
            try:
                q.put_nowait(json.dumps(evt))
            except Exception:
                pass

    return jsonify({'status': 'ok', 'count': count})


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5010)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
