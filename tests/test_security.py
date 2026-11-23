import http.client
import contextlib
import io
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server

class SecurityTests(unittest.TestCase):
    def test_busy_port_does_not_reset_existing_jobs(self):
        with patch.object(server, 'DashboardServer', side_effect=OSError(10048, 'address in use')), patch.object(server, 'init') as initialize, contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(server.main(), 1)
            initialize.assert_not_called()
            self.assertIn('8787', error.getvalue())

    def test_dashboard_prevents_duplicate_listener(self):
        app = server.DashboardServer(('127.0.0.1', 0), server.Handler)
        try:
            with self.assertRaises(OSError):
                server.DashboardServer(('127.0.0.1', app.server_port), server.Handler)
        finally:
            app.server_close()

    def test_target_scope(self):
        with patch.object(server, 'ALLOWED', {'127.0.0.1'}), patch.object(server, 'PORTS', {8080}):
            self.assertEqual(server.validate_url('http://127.0.0.1:8080'), 'http://127.0.0.1:8080')
            for url in ['http://example.com:8080', 'http://8.8.8.8:8080', 'http://127.0.0.1:22',
                        'file:///tmp/x', 'http://user:pass@127.0.0.1:8080', 'http://127.0.0.1:8080/admin',
                        'http://127.0.0.1:8080?x=1', 'http://169.254.169.254:8080']:
                with self.subTest(url=url), self.assertRaises(ValueError):
                    server.validate_url(url)

    def test_api_auth_and_host(self):
        app = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        threading.Thread(target=app.serve_forever, daemon=True).start()
        try:
            conn = http.client.HTTPConnection('127.0.0.1', app.server_port)
            conn.request('POST', '/api/scans', '{}', {'Host': 'localhost:8787', 'Content-Type': 'application/json'})
            self.assertEqual(conn.getresponse().status, 403)
            conn.close()
            conn = http.client.HTTPConnection('127.0.0.1', app.server_port)
            conn.request('GET', '/api/session', headers={'Host': 'attacker.example'})
            self.assertEqual(conn.getresponse().status, 403)
            conn.close()
        finally:
            app.shutdown()
            app.server_close()

    def test_redirect_is_not_followed(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        calls = []
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append(self.path)
                self.send_response(302)
                self.send_header('Location', 'http://169.254.169.254/')
                self.end_headers()
            def log_message(self, *_):
                pass
        app = HTTPServer(('127.0.0.1', 0), Redirect)
        threading.Thread(target=app.serve_forever, daemon=True).start()
        try:
            findings, status = server.inspect_headers('http://127.0.0.1:' + str(app.server_port))
            self.assertEqual(status, 302)
            self.assertEqual(calls, ['/'])
            self.assertEqual(len(findings), 2)
        finally:
            app.shutdown()
            app.server_close()

    def test_scan_persists_actual_evidence(self):
        spec = importlib.util.spec_from_file_location('lab_server', server.ROOT / 'lab' / 'server.py')
        lab = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lab)
        app = lab.HTTPServer(('127.0.0.1', 0), lab.Lab)
        threading.Thread(target=app.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory, patch.object(server, 'DATA', Path(directory)), patch.object(server, 'PORTS', {app.server_port}), patch.object(server.shutil, 'which', return_value=None):
                server.init()
                with server.db() as con:
                    con.execute("INSERT INTO scans(id,target_id,status,created) VALUES(1,1,'queued',?)", (server.now(),))
                server.scan(1, 'http://127.0.0.1:' + str(app.server_port))
                with server.db() as con:
                    row = con.execute('SELECT * FROM scans WHERE id=1').fetchone()
                result = json.loads(row['result'])
                self.assertEqual(row['status'], 'completed')
                self.assertEqual(result['http_status'], 200)
                self.assertEqual(result['ports'][0]['state'], 'open')
                self.assertEqual(len(result['findings']), 2)
                self.assertEqual(result['nuclei'], 'not_installed')
        finally:
            app.shutdown()
            app.server_close()

if __name__ == '__main__':
    unittest.main()
