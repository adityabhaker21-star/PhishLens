import os
import sys
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAGES_DIR = os.path.join(BASE_DIR, "pages")
DASHBOARD_FILE = os.path.join(BASE_DIR, "dashboard.html")

INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>PhishLens Demo Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 680px; margin: 3rem auto; padding: 1.5rem; line-height: 1.6; color: #1e293b; background: #f8fafc; }
    h2 { color: #0f172a; margin-bottom: 0.5rem; }
    .card { background: white; border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); border: 1px solid #e2e8f0; margin-bottom: 1.5rem; }
    code { background: #f1f5f9; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.9em; font-family: monospace; }
    ul { list-style: none; padding-left: 0; }
    li { margin: 0.75rem 0; }
    a { color: #2563eb; text-decoration: none; font-weight: 600; }
    a:hover { text-decoration: underline; }
    .badge-danger { background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 6px; font-size: 0.8em; margin-left: 8px; }
    .badge-safe { background: #dcfce7; color: #166534; padding: 2px 8px; border-radius: 6px; font-size: 0.8em; margin-left: 8px; }
    .badge-suspicious { background: #fef3c7; color: #92400e; padding: 2px 8px; border-radius: 6px; font-size: 0.8em; margin-left: 8px; }
  </style>
</head>
<body>
  <h2>🛡️ PhishLens Demo Hub (Port 8080)</h2>
  <p>Instant local test environment for real-time phishing interception.</p>

  <div class="card">
    <h3 style="margin-top:0">Demo Websites:</h3>
    <ul>
      <li>
        <a href="http://novabank-kyc-verify.test:8080/">http://novabank-kyc-verify.test:8080/</a>
        <span class="badge-danger">Phishing Attack</span>
      </li>
      <li>
        <a href="http://novabank.test:8080/">http://novabank.test:8080/</a>
        <span class="badge-safe">Safe Banking</span>
      </li>
      <li>
        <a href="http://borderline.test:8080/">http://borderline.test:8080/</a>
        <span class="badge-suspicious">Suspicious Sign-in</span>
      </li>
    </ul>

    <hr style="margin: 1.25rem 0; border: none; border-top: 1px solid #e2e8f0;">

    <h4 style="margin: 0.5rem 0;">Direct Localhost Links (No hosts file needed):</h4>
    <ul>
      <li><a href="/novabank-phish">http://localhost:8080/novabank-phish</a> <span class="badge-danger">Phishing</span></li>
      <li><a href="/novabank-legit">http://localhost:8080/novabank-legit</a> <span class="badge-safe">Safe</span></li>
      <li><a href="/borderline">http://localhost:8080/borderline</a> <span class="badge-suspicious">Suspicious</span></li>
      <li><a href="/reanime">http://localhost:8080/reanime</a> <span class="badge-danger">Streaming & Popunder Test</span></li>
      <li><a href="/dashboard.html" target="_blank">http://localhost:8080/dashboard.html</a> <strong>(Live Dashboard)</strong></li>
    </ul>
  </div>
</body>
</html>"""

SUBMIT_HTML = """<!DOCTYPE html>
<html><body style="font-family:sans-serif;text-align:center;padding:4rem;background:#0f172a;color:#f8fafc;">
  <h2>🔒 Demo Action Sink</h2>
  <p>PhishLens intercepted the form submission. No credentials were sent or stored.</p>
  <p><a href="javascript:history.back()" style="color:#38bdf8;">&larr; Back to safety</a></p>
</body></html>"""

class FastDemoHandler(SimpleHTTPRequestHandler):
    # Disable slow reverse DNS lookup on Windows
    def address_string(self):
        return self.client_address[0]

    # Suppress noisy standard logs for faster throughput
    def log_message(self, format, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")

    def _send_data(self, data_bytes, content_type="text/html; charset=utf-8", status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data_bytes)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")

        # Favicon fast response
        if path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return

        # Form submission sink
        if path.startswith("/submit"):
            self._send_data(SUBMIT_HTML.encode("utf-8"))
            return

        # Dashboard
        if path == "/dashboard.html" or path == "/dashboard":
            if os.path.exists(DASHBOARD_FILE):
                with open(DASHBOARD_FILE, "rb") as f:
                    self._send_data(f.read())
                    return

        # Direct path routing without hosts file
        if path in ("/novabank-phish", "/novabank-phish.html", "/phish"):
            phish_file = os.path.join(PAGES_DIR, "novabank-kyc-verify.test", "index.html")
            if os.path.exists(phish_file):
                with open(phish_file, "rb") as f:
                    self._send_data(f.read())
                    return

        if path in ("/novabank-legit", "/novabank-legit.html", "/legit"):
            legit_file = os.path.join(PAGES_DIR, "novabank.test", "index.html")
            if os.path.exists(legit_file):
                with open(legit_file, "rb") as f:
                    self._send_data(f.read())
                    return

        if path in ("/borderline", "/borderline.html"):
            border_file = os.path.join(PAGES_DIR, "borderline.test", "index.html")
            if os.path.exists(border_file):
                with open(border_file, "rb") as f:
                    self._send_data(f.read())
                    return

        if path in ("/reanime", "/reanime-sim", "/reanime.html"):
            reanime_file = os.path.join(PAGES_DIR, "reanime-sim.test", "index.html")
            if os.path.exists(reanime_file):
                with open(reanime_file, "rb") as f:
                    self._send_data(f.read())
                    return

        # Host-based routing (e.g. novabank-kyc-verify.test:8080)
        host = self.headers.get("Host", "").split(":")[0].lower()
        target_file = os.path.join(PAGES_DIR, host, "index.html")
        if os.path.exists(target_file):
            with open(target_file, "rb") as f:
                self._send_data(f.read())
                return

        # Fallback to Hub Index
        self._send_data(INDEX_HTML.encode("utf-8"))

    def do_POST(self):
        self.do_GET()

def run():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), FastDemoHandler)
    server.daemon_threads = True
    print(f"Fast Multi-threaded Demo Server running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping demo server.")

if __name__ == "__main__":
    run()

