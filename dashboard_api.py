"""
dashboard_api.py — Serves the DeceptionNet dashboard (static page + JSON API).

Run standalone:  python dashboard_api.py --port 5000
Then open http://localhost:5000 in a browser.
"""

import argparse
import io
from datetime import datetime

from flask import Flask, jsonify, send_from_directory, request, send_file

from db import init_db, all_events, stats_summary

app = Flask(__name__, static_folder="dashboard", static_url_path="")


@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


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
