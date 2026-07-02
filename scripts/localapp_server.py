"""Deterministic local app for the capture-parity benchmark pair.

Serves the same endpoints as examples/fixtures/localapp.har on a fixed port.
The page fires every API call on load, so a correct live recorder must
capture them all — this is what regressed in early CDP capture (the attach
race lost the initial page-load traffic).

Usage:
    python scripts/localapp_server.py          # serves on 127.0.0.1:8971
    tapestry import examples/fixtures/localapp.har --site localapp
    tapestry record http://127.0.0.1:8971/ --site localapp-cdp --headless \
        --timeout-secs 25 --allow-low-signal
    tapestry generate localapp && tapestry generate localapp-cdp
    tapestry benchmark
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8971

PAGE = b"""<!doctype html>
<html><head><title>localapp</title><script>
fetch('/api/items?page=1&limit=5').then(r => r.json());
fetch('/api/items/1').then(r => r.json());
fetch('/api/items/2').then(r => r.json());
fetch('/api/config').then(r => r.json());
</script></head><body>localapp parity fixture</body></html>"""

RESPONSES = {
    "/api/items": {"items": [{"id": 1, "title": "One"}, {"id": 2, "title": "Two"}], "total": 2},
    "/api/items/1": {"id": 1, "title": "One", "status": "published"},
    "/api/items/2": {"id": 2, "title": "Two", "status": "draft"},
    "/api/config": {"feature_flags": {"beta": True}, "locale": "en-GB"},
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(PAGE)
        elif path in RESPONSES:
            body = json.dumps(RESPONSES[path]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"localapp serving on http://127.0.0.1:{PORT}/")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
