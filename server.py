"""
server.py — Sentinel IDS Laptop Server
Receives alerts from Raspberry Pi over Ethernet, stores them in alerts.json,
and serves the monitoring dashboard.

Run:  python server.py
"""

import json
import os
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

# ── Config ────────────────────────────────────────────────────────────────────
ALERTS_FILE  = "alerts.json"
MAX_ALERTS   = 100          # keep only the last N alerts
PORT         = 5000
HOST         = "0.0.0.0"   # listen on all interfaces (LAN + localhost)

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=".")
CORS(app)                   # allow dashboard JS to call /alerts from any origin


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_alerts() -> list:
    """Load existing alerts from disk; return empty list if file missing/corrupt."""
    if not os.path.exists(ALERTS_FILE):
        return []
    try:
        with open(ALERTS_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_alerts(alerts: list) -> None:
    """Persist alerts list to disk (pretty-printed for readability)."""
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)


def normalise_alert(raw: dict) -> dict:
    """
    Convert the Pi's payload into the flat shape the dashboard expects:
      { timestamp, src_ip, dst_ip, attack_type, confidence, received_at }

    The Pi sends: timestamp, src_ip, dst_ip, protocol, features{...}, label
    """
    label = raw.get("label", "UNKNOWN").strip()

    # Map Pi labels → dashboard attack_type tokens
    label_map = {
        "ANOMALY":    "DDoS",   # default mapping — adjust to match your model
        "DDOS":       "DDoS",
        "DOS":        "DoS",
        "PORTSCAN":   "PortScan",
        "PORT_SCAN":  "PortScan",
        "BRUTEFORCE": "BruteForce",
        "BRUTE_FORCE":"BruteForce",
        "BENIGN":     "Benign",
        "NORMAL":     "Benign",
    }
    attack_type = label_map.get(label.upper(), label)

    # Derive a confidence value: prefer explicit field, else infer from features
    confidence = raw.get("confidence", None)
    if confidence is None:
        # Heuristic: SYN flood → high confidence DDoS
        features = raw.get("features", {})
        syn = features.get("SYN Flag Count", 0)
        confidence = min(0.99, 0.70 + (syn / 100) * 0.29) if syn else 0.85

    return {
        "timestamp":   raw.get("timestamp", datetime.now().isoformat()),
        "src_ip":      raw.get("src_ip", "—"),
        "dst_ip":      raw.get("dst_ip", "—"),
        "attack_type": attack_type,
        "confidence":  round(float(confidence), 4),
        "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        # keep raw fields for debugging
        "protocol":    raw.get("protocol"),
        "label":       label,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """Serve the monitoring dashboard."""
    return send_from_directory(".", "dashboard.html")


@app.route("/<path:filename>", methods=["GET"])
def static_files(filename):
    """Serve style.css, script.js, etc. from the project directory."""
    return send_from_directory(".", filename)


@app.route("/alert", methods=["POST"])
def receive_alert():
    """
    Receive a single alert from the Raspberry Pi.
    Expected JSON body: see project spec.
    """
    raw = request.get_json(silent=True)
    if not raw:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    alert = normalise_alert(raw)

    # Load → append → trim → save
    alerts = load_alerts()
    alerts.append(alert)
    if len(alerts) > MAX_ALERTS:
        alerts = alerts[-MAX_ALERTS:]   # keep the most recent
    save_alerts(alerts)

    # Console log
    print(
        f"[{alert['received_at']}]  ALERT RECEIVED"
        f"  |  {alert['attack_type']:12s}"
        f"  |  {alert['src_ip']} → {alert['dst_ip']}"
        f"  |  confidence: {alert['confidence']*100:.1f}%"
    )

    return jsonify({"status": "ok", "alert": alert}), 201


@app.route("/alerts", methods=["GET"])
def get_alerts():
    """Return all stored alerts as a JSON array (polled by the dashboard)."""
    return jsonify(load_alerts())


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Create an empty alerts.json if it doesn't exist yet
    if not os.path.exists(ALERTS_FILE):
        save_alerts([])
        print(f"[server] Created {ALERTS_FILE}")

    print(f"[server] Sentinel IDS server starting on http://{HOST}:{PORT}")
    print(f"[server] Dashboard → http://localhost:{PORT}/")
    print(f"[server] POST alerts to → http://<laptop-ip>:{PORT}/alert")
    print(f"[server] Storing last {MAX_ALERTS} alerts in {ALERTS_FILE}")
    print("-" * 60)

    app.run(host=HOST, port=PORT, debug=False)
