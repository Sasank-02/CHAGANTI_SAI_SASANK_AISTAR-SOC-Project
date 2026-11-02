import os
import sys

# Ensure root workspace is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from flask import Flask, render_template, send_from_directory, jsonify, request
from api.server import app as api_app

app = Flask(__name__, template_folder="templates", static_folder="static")

@app.route("/")
def dashboard():
    """Serves the main Agentic AI SOC Operations Center dashboard."""
    return render_template("index.html")

# Forward all /api/ calls directly to the api_app so dashboard works standalone
@app.route("/api/<path:subpath>", methods=["GET", "POST", "OPTIONS"])
def proxy_api(subpath):
    with api_app.test_client() as client:
        method = request.method
        path = f"/api/{subpath}"
        query = request.query_string.decode("utf-8")
        if query:
            path += f"?{query}"
        
        headers = {k: v for k, v in request.headers if k.lower() != 'host'}
        data = request.get_data()

        resp = client.open(path, method=method, headers=headers, data=data)
        return (resp.get_data(), resp.status_code, resp.headers.items())

if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    print(f"[*] Starting AISTAR Agentic SOC Dashboard on http://127.0.0.1:{port}...")
    app.run(host="0.0.0.0", port=port, debug=True)
