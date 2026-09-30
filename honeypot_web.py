"""
honeypot_web.py — Fake admin login page & multi-location Honeytoken bait web honeypot.

Looks like a real admin panel login. Logs every submitted username/
password/request, flags SQLi, XSS, Honeytokens, and Honeytoken Sessions via the classifier.

Features multi-location honeytokens:
- HTML Comment in / -> dnet_honey_51Nx8fQ2eZvKYlo9A3bC7dEfGhIjKlMnOp
- /robots.txt -> dnet_honey_99PqRsTuVwXyZ1234567890AbCdEfGhIj
- /config.js -> dnet_honey_88AaBbCcDdEeFfGgHhIiJjKkLlMmNnOo
- /.env -> dnet_honey_77ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLl

Run standalone:  python honeypot_web.py --port 8080
"""

import argparse
from flask import Flask, request, render_template_string, jsonify

from db import init_db, log_event
from classifier import classify, get_honeytoken_location, HONEYTOKENS

app = Flask(__name__)

LOGIN_PAGE = """
<!doctype html>
<html>
<!-- HONEYTOKEN BAIT 1 (html_comment_login): DEPRECATED API KEY: dnet_honey_51Nx8fQ2eZvKYlo9A3bC7dEfGhIjKlMnOp -->
<head>
  <title>Admin Panel Login</title>
  <script src="/config.js"></script>
  <style>
    body { font-family: Arial, sans-serif; background: #1a1a2e; display: flex;
           height: 100vh; align-items: center; justify-content: center; margin: 0; }
    .box { background: #16213e; padding: 40px; border-radius: 8px; width: 320px; }
    h2 { color: #eee; margin-top: 0; }
    input { width: 100%; padding: 10px; margin: 8px 0; border-radius: 4px;
            border: none; box-sizing: border-box; }
    button { width: 100%; padding: 10px; background: #0f3460; color: white;
             border: none; border-radius: 4px; cursor: pointer; margin-top: 10px; }
    .error { color: #ff6b6b; font-size: 14px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>🔒 Admin Panel</h2>
    <form method="POST" action="/login">
      <input type="text" name="username" placeholder="Username" autocomplete="off">
      <input type="password" name="password" placeholder="Password" autocomplete="off">
      <button type="submit">Sign In</button>
    </form>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
  </div>
</body>
</html>
"""


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _extract_request_summary():
    """Build a comprehensive string of the request for inspection."""
    headers_str = " | ".join(f"{k}:{v}" for k, v in request.headers.items() if k.lower() in ["authorization", "x-api-key", "cookie", "user-agent"])
    body_str = request.get_data(as_text=True) or ""
    return f"URI={request.path} | Query={request.query_string.decode()} | Headers={headers_str} | Body={body_str[:100]}"


@app.before_request
def inspect_and_log():
    """Global middleware: scans headers, cookies, query, body, and URL for honeytokens or attacks."""
    # Ignore static assets if any
    if request.path in ["/robots.txt", "/config.js", "/.env"]:
        return None

    client_ip = _client_ip()
    client_port = request.environ.get("REMOTE_PORT")
    request_summary = _extract_request_summary()
    location_tag = get_honeytoken_location(request_summary)

    if location_tag:
        raw_payload = f"[Honeytoken Triggered via {location_tag}] {request_summary}"
        log_event(service="web", source_ip=client_ip, source_port=client_port, raw_payload=raw_payload, attack_type="honeytoken_triggered")
        print(f"[HONEYTOKEN TRIGGERED] {client_ip} used token from bait location: {location_tag}")
        
        # Return a convincing fake JSON response to keep the attacker engaged
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
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/robots.txt")
def robots_txt():
    """Bait 2: Exposes honeytoken in robots.txt disallow path."""
    content = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /api/v1/internal?key=dnet_honey_99PqRsTuVwXyZ1234567890AbCdEfGhIj  # HONEYTOKEN BAIT (robots_txt_disallow)\n"
    )
    return content, 200, {"Content-Type": "text/plain"}


@app.route("/config.js")
def config_js():
    """Bait 3: Exposes honeytoken in JavaScript source code."""
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
    """Bait 4: Exposes honeytoken in fake environment file leak."""
    content = (
        "ENVIRONMENT=production\n"
        "DATABASE_URL=sqlite:///deceptionnet.db\n"
        "SECRET_KEY=dnet_honey_77ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLl  # HONEYTOKEN BAIT (env_file_leak)\n"
    )
    return content, 200, {"Content-Type": "text/plain"}


@app.route("/api/v1/internal")
def internal_api():
    """Bait endpoint referenced in robots.txt."""
    return jsonify({
        "status": "success",
        "data": "Internal API endpoint accessible via honeytoken."
    })


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
    """A second bait field — search boxes are a classic XSS/SQLi target."""
    q = request.args.get("q", "")
    client_ip = _client_ip()

    log_event(service="web", source_ip=client_ip, raw_payload=q)
    attack_type = classify(service="web", source_ip=client_ip, raw_payload=q)
    _update_last_classification(client_ip, attack_type)

    return f"<p>No results found for: {q}</p><p><a href='/'>Back</a></p>"


def _update_last_classification(source_ip, attack_type):
    import sqlite3
    from db import DB_PATH
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        UPDATE events SET attack_type = ?
        WHERE id = (SELECT id FROM events WHERE source_ip = ? ORDER BY id DESC LIMIT 1)
        """,
        (attack_type, source_ip),
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    init_db()
    print(f"[Web honeypot] listening on 0.0.0.0:{args.port}")
    app.run(host="0.0.0.0", port=args.port, threaded=True)

