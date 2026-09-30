"""
dashboard_api.py — Serves the DeceptionNet dashboard (static page + JSON API).

Run standalone:  python dashboard_api.py --port 5000
Then open http://localhost:5000 in a browser.
"""

import argparse
import io
from datetime import datetime

from flask import Flask, jsonify, send_from_directory, request, send_file, render_template_string

from db import init_db, all_events, stats_summary, log_event
from classifier import classify, get_honeytoken_location
from honeypot_web import LOGIN_PAGE, _client_ip, _extract_request_summary, _update_last_classification

app = Flask(__name__, static_folder="dashboard", static_url_path="")


@app.before_request
def inspect_and_log_dashboard():
    """Global middleware: scans headers, cookies, query, body, and URL for honeytokens or attacks."""
    # Skip dashboard static assets and API routes
    if request.path in ["/", "/index.html", "/backgroundImage.jpg", "/api/stats", "/api/events", "/api/report.pdf", "/robots.txt", "/config.js", "/.env"]:
        return None

    client_ip = _client_ip()
    client_port = request.environ.get("REMOTE_PORT")
    request_summary = _extract_request_summary()
    location_tag = get_honeytoken_location(request_summary)

    if location_tag:
        raw_payload = f"[Honeytoken Triggered via {location_tag}] {request_summary}"
        log_event(service="web", source_ip=client_ip, source_port=client_port, raw_payload=raw_payload, attack_type="honeytoken_triggered")
        print(f"[HONEYTOKEN TRIGGERED] {client_ip} used token from bait location: {location_tag}")
        
        return jsonify({
            "status": "success",
            "access_granted": True,
            "session": {
                "token_type": "Bearer",
                "scope": "admin:read_write",
                "user_id": 1042,
                "account": "Enterprise Admin",
                "active_session": True
            },
            "system_status": "Operational",
            "message": "Debug session active. Internal system logs exposed."
        }), 200

    return None


@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE, error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    client_ip = _client_ip()
    client_port = request.environ.get("REMOTE_PORT")

    raw_payload = f"username={username}&password={password}"

    log_event(service="web", source_ip=client_ip, source_port=client_port,
              username=username, password=password, raw_payload=raw_payload)
    attack_type = classify(service="web", source_ip=client_ip, username=username,
                            password=password, raw_payload=raw_payload,
                            source_port=client_port)
    _update_last_classification(client_ip, attack_type)

    print(f"[WEB] {client_ip} tried {username}:{password} -> {attack_type}")

    return render_template_string(LOGIN_PAGE, error="Invalid username or password."), 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    client_ip = _client_ip()

    log_event(service="web", source_ip=client_ip, raw_payload=q)
    attack_type = classify(service="web", source_ip=client_ip, raw_payload=q)
    _update_last_classification(client_ip, attack_type)

    return f"<p>No results found for: {q}</p><p><a href='/'>Back</a></p>"


@app.route("/robots.txt")
def robots_txt():
    content = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /api/v1/internal?key=dnet_honey_99PqRsTuVwXyZ1234567890AbCdEfGhIj  # HONEYTOKEN BAIT (robots_txt_disallow)\n"
    )
    return content, 200, {"Content-Type": "text/plain"}


@app.route("/config.js")
def config_js():
    content = (
        "// Frontend Configuration\n"
        "window.ENV = {\n"
        "  API_BASE: '/api/v1',\n"
        "  API_KEY: 'dnet_honey_88AaBbCcDdEeFfGgHhIiJjKkLlMmNnOo' // HONEYTOKEN BAIT (config_js_source)\n"
        "};\n"
    )
    return content, 200, {"Content-Type": "application/javascript"}


@app.route("/.env")
def env_file():
    content = (
        "ENVIRONMENT=production\n"
        "DATABASE_URL=sqlite:///deceptionnet.db\n"
        "SECRET_KEY=dnet_honey_77ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLl  # HONEYTOKEN BAIT (env_file_leak)\n"
    )
    return content, 200, {"Content-Type": "text/plain"}


@app.route("/api/v1/internal")
def internal_api():
    return jsonify({
        "status": "success",
        "data": "Internal API endpoint accessible via honeytoken."
    })


@app.route("/api/events")
def api_events():
    limit = int(request.args.get("limit", 200))
    return jsonify(all_events(limit=limit))


@app.route("/api/stats")
def api_stats():
    return jsonify(stats_summary())


@app.route("/api/report.pdf")
def report_pdf():
    """Generate a simple PDF summary of logged attacks for submission."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError:
        return "reportlab not installed — run: pip install reportlab --break-system-packages", 500

    stats = stats_summary()
    events = all_events(limit=50)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "DeceptionNet — Attack Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Generated: {datetime.now().isoformat()}")
    y -= 30

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, f"Total events logged: {stats['total']}")
    y -= 20

    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y, "Attack type breakdown:")
    y -= 15
    c.setFont("Helvetica", 10)
    for row in stats["by_type"]:
        c.drawString(70, y, f"- {row['attack_type']}: {row['c']}")
        y -= 15

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y, "Top attacker IPs:")
    y -= 15
    c.setFont("Helvetica", 10)
    for row in stats["by_ip"]:
        c.drawString(70, y, f"- {row['source_ip']}: {row['c']} events")
        y -= 15
        if y < 100:
            c.showPage()
            y = height - 50

    y -= 10
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, y, "Recent events (most recent 50):")
    y -= 15
    c.setFont("Helvetica", 8)
    for e in events:
        line = f"[{e['timestamp']}] {e['service']} {e['source_ip']} user={e['username']} pass={e['password']} -> {e['attack_type']}"
        c.drawString(50, y, line[:110])
        y -= 12
        if y < 50:
            c.showPage()
            y = height - 50

    c.save()
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf", as_attachment=True,
                      download_name="deceptionnet_report.pdf")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    init_db()
    print(f"[Dashboard] http://localhost:{args.port}")
    app.run(host="0.0.0.0", port=args.port, threaded=True)
