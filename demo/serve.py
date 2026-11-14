import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAGES_DIR = os.path.join(BASE_DIR, "pages")

INDEX_HTML = """<!DOCTYPE html>
<html>
<head><title>PhishLens Demo Server</title>
<style>body{font-family:sans-serif;max-width:600px;margin:3rem auto;padding:1rem;line-height:1.6}</style>
</head>
<body>
  <h2>PhishLens Local Demo Server (Port 8080)</h2>
  <p>To test hostname resolution, ensure this entry is in your hosts file:</p>
  <code>127.0.0.1 novabank.test novabank-kyc-verify.test collect.test borderline.test</code>
  <hr style="margin:1.5rem 0">
  <h3>Demo Links:</h3>
  <ul>
    <li><a href="http://novabank.test:8080/">http://novabank.test:8080/</a> (Real Nova Bank - Safe)</li>
    <li><a href="http://novabank-kyc-verify.test:8080/">http://novabank-kyc-verify.test:8080/</a> (Fake KYC Clone - Phishing)</li>
    <li><a href="http://borderline.test:8080/">http://borderline.test:8080/</a> (Borderline Sign-in - Suspicious)</li>
  </ul>
</body>
</html>"""

SUBMIT_HTML = """<!DOCTYPE html>
<html><body style="font-family:sans-serif;text-align:center;padding:4rem;">
  <h2>Demo only</h2>
  <p>PhishLens intercepted submission. No credentials were collected or stored.</p>
</body></html>"""

class DemoHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/submit"):
            self._send_html(SUBMIT_HTML)
            return
        self._serve_page()

    def do_POST(self):
        if self.path.startswith("/submit"):
            self._send_html(SUBMIT_HTML)
            return
        self._serve_page()

    def _send_html(self, content):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _serve_page(self):
        host = self.headers.get("Host", "").split(":")[0].lower()
        target_file = os.path.join(PAGES_DIR, host, "index.html")
        if os.path.exists(target_file):
            with open(target_file, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
        else:
            self._send_html(INDEX_HTML)

def run():
    server = HTTPServer(("0.0.0.0", PORT), DemoHandler)
    print(f"Demo server running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping demo server.")

if __name__ == "__main__":
    run()
