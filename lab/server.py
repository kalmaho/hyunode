"""Intentionally missing security headers; binds to loopback only."""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Lab(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<html><title>Hyunode Lab</title><h1>Hyunode isolated lab</h1><p>Synthetic data only. Security headers intentionally omitted.</p></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    print('Lab: http://127.0.0.1:8080', flush=True)
    HTTPServer(('127.0.0.1', 8080), Lab).serve_forever()
