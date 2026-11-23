"""Hyunode: local, allowlisted security lab dashboard (Python standard library)."""
import concurrent.futures
from contextlib import contextmanager
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import ai_analysis
from evidence import summarize

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
TOKEN = secrets.token_urlsafe(32)
LOCK = threading.Lock()
ALLOWED = {x.strip() for x in os.getenv('HYUNODE_ALLOWED_IPS', '127.0.0.1').split(',')}
PORTS = {int(x) for x in os.getenv('HYUNODE_ALLOWED_PORTS', '3000,8000,8080,8443').split(',')}
POOL = concurrent.futures.ThreadPoolExecutor(max_workers=1)
AI_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=1)

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

@contextmanager
def db():
    DATA.mkdir(exist_ok=True)
    con = sqlite3.connect(str(DATA / 'hyunode.db'))
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()

def init():
    with db() as con:
        con.executescript('''CREATE TABLE IF NOT EXISTS targets(id INTEGER PRIMARY KEY, name TEXT, url TEXT UNIQUE, created TEXT);
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, target_id INTEGER, status TEXT, created TEXT, result TEXT);
        CREATE TABLE IF NOT EXISTS ai_runs(id INTEGER PRIMARY KEY, scan_id INTEGER, status TEXT, created TEXT, result TEXT);
        ''')
        con.execute("UPDATE scans SET status='interrupted' WHERE status IN ('queued','running')")
        con.execute("UPDATE ai_runs SET status='interrupted' WHERE status IN ('queued','running')")

def validate_url(raw):
    u = urlsplit(raw)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
        raise ValueError('HTTP(S) 원점 주소만 입력하세요. 경로·인증정보·쿼리는 허용하지 않습니다.')
    try:
        ip = ipaddress.ip_address(u.hostname)
    except ValueError:
        raise ValueError('내부 모드에서는 DNS 대신 허용된 고정 IP를 사용하세요.')
    if str(ip) not in ALLOWED or not (ip.is_private or ip.is_loopback) or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise ValueError('서버 설정에서 허용한 내부 실습 IP만 등록할 수 있습니다.')
    port = u.port or (443 if u.scheme == 'https' else 80)
    if port not in PORTS:
        raise ValueError('허용되지 않은 포트입니다: ' + str(port))
    host = '[' + str(ip) + ']' if ip.version == 6 else str(ip)
    return '{}://{}:{}'.format(u.scheme, host, port)

def probe(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.7):
            return {'port': port, 'state': 'open'}
    except OSError:
        return {'port': port, 'state': 'closed_or_filtered'}

def inspect_headers(url, observations=None):
    u = urlsplit(url)
    cls = http.client.HTTPSConnection if u.scheme == 'https' else http.client.HTTPConnection
    conn = cls(u.hostname, u.port, timeout=5)
    try:
        conn.request('GET', '/', headers={'User-Agent': 'Hyunode-Lab/1.0', 'Connection': 'close'})
        response = conn.getresponse()
        response_headers = response.getheaders()
        headers = {k.lower(): v for k, v in response_headers}
        # Read at most 64 KiB; store structural counts only. Never follow redirects.
        if observations is not None:
            body = response.read(65537)
            observations.update(summarize(response_headers, body[:65536], len(body) > 65536))
        checks = [('content-security-policy', 'Content-Security-Policy 미설정', 'medium', '콘텐츠 출처를 제한하는 CSP 정책을 서비스에 맞게 설정하세요.'),
                  ('x-content-type-options', 'X-Content-Type-Options 미설정', 'low', 'nosniff 응답 헤더를 설정하세요.')]
        if u.scheme == 'https':
            checks.append(('strict-transport-security', 'HSTS 미설정', 'low', 'HTTPS 운영 정책에 맞춰 HSTS를 설정하세요.'))
        findings = []
        for key, title, severity, fix in checks:
            if key not in headers:
                findings.append({'title': title, 'severity': severity, 'source': 'HTTP headers', 'status': '검토 필요',
                                 'evidence': 'GET / → HTTP {}; {} 헤더 없음'.format(response.status, key),
                                 'remediation': fix, 'note': '설정 관찰 결과이며 악용 가능한 취약점으로 확정하지 않습니다.'})
        return findings, response.status
    finally:
        conn.close()

def run_nuclei(url):
    binary = shutil.which('nuclei')
    approved = []
    manifest = ROOT / 'nuclei-templates' / 'approved.json'
    if manifest.exists():
        for item in json.loads(manifest.read_text(encoding='utf-8')):
            path = (ROOT / 'nuclei-templates' / item['file']).resolve()
            if path.parent != (ROOT / 'nuclei-templates').resolve() or path.suffix not in ('.yaml', '.yml'):
                raise ValueError('잘못된 승인 템플릿 경로')
            if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('승인 템플릿 해시가 변경되었습니다.')
            approved.append(path)
    if not binary:
        return [], 'not_installed'
    if not approved:
        return [], 'no_approved_templates'
    args = [binary, '-u', url, '-jsonl', '-silent', '-rl', '2', '-c', '1', '-timeout', '5', '-retries', '0', '-dr', '-ni', '-duc']
    for path in approved:
        args += ['-t', str(path)]
    process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=90, shell=False)
    if process.returncode:
        return [], 'engine_error'
    findings = []
    for line in process.stdout.splitlines():
        try:
            match = json.loads(line)
            info = match.get('info', {})
            findings.append({'title': info.get('name', 'Nuclei match'), 'severity': info.get('severity', 'info'),
                             'source': 'Nuclei', 'status': '검토 필요', 'evidence': match.get('matched-at', url),
                             'remediation': info.get('remediation', '재현과 영향 검토 후 수정안을 기록하세요.'),
                             'note': '템플릿 일치는 취약점 확정이 아닙니다. 수동 재현이 필요합니다.'})
        except (ValueError, TypeError):
            continue
    return findings, 'completed'

def scan(scan_id, url):
    result = {'ports': [], 'findings': [], 'notes': [], 'nuclei': 'not_run', 'ai': 'not_configured'}
    with db() as con:
        con.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,))
    try:
        url = validate_url(url)
        ip = urlsplit(url).hostname
        result['ports'] = [probe(ip, port) for port in sorted(PORTS)]
        try:
            result['observations'] = {}
            result['findings'], result['http_status'] = inspect_headers(url, result['observations'])
        except (OSError, http.client.HTTPException) as exc:
            result['notes'].append('HTTP 점검 실패: ' + str(exc))
        try:
            matches, result['nuclei'] = run_nuclei(url)
            result['findings'].extend(matches)
        except Exception as exc:
            result['nuclei'] = 'engine_error'
            result['notes'].append('Nuclei 점검 실패: ' + str(exc))
        status = 'partial' if result['notes'] or result['nuclei'] == 'engine_error' else 'completed'
    except Exception as exc:
        result['notes'].append(str(exc))
        status = 'failed'
    result['finished'] = now()
    with db() as con:
        con.execute('UPDATE scans SET status=?,result=? WHERE id=?', (status, json.dumps(result, ensure_ascii=False), scan_id))

def state():
    with db() as con:
        targets = [dict(r) for r in con.execute('SELECT * FROM targets ORDER BY id DESC')]
        scans = [dict(r) for r in con.execute('SELECT scans.*, targets.name, targets.url FROM scans JOIN targets ON targets.id=scans.target_id ORDER BY scans.id DESC LIMIT 100')]
        ai_runs = [dict(r) for r in con.execute('SELECT * FROM ai_runs ORDER BY id DESC LIMIT 100')]
    for item in scans:
        item['result'] = json.loads(item['result']) if item['result'] else None
    for item in ai_runs:
        item['result'] = json.loads(item['result']) if item['result'] else None
    return {'targets': targets, 'scans': scans, 'ai_runs': ai_runs, 'config': {'allowed_ips': sorted(ALLOWED), 'ports': sorted(PORTS),
            'nuclei_installed': bool(shutil.which('nuclei')), 'ai': ai_analysis.config(), 'external_asm': False}}


def ai_preview(scan_id):
    with db() as con:
        row = con.execute('SELECT * FROM scans WHERE id=?', (scan_id,)).fetchone()
    if not row:
        raise ValueError('검사 결과가 없습니다.')
    item = dict(row)
    item['result'] = json.loads(item['result']) if item['result'] else None
    bundle = ai_analysis.evidence_bundle(item)
    digest = hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest()
    return {'bundle': bundle, 'digest': digest, 'settings': ai_analysis.config()}


def run_ai(run_id, bundle):
    with db() as con:
        con.execute("UPDATE ai_runs SET status='running' WHERE id=?", (run_id,))
    try:
        result = ai_analysis.analyze(bundle)
        result['evidence'] = bundle
        status = 'completed'
    except Exception as exc:
        # Do not expose upstream bodies, tokens, or arbitrary exception text.
        result = {'error': str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else 'AI 응답 처리에 실패했습니다.'}
        status = 'failed'
    result['finished'] = now()
    with db() as con:
        con.execute('UPDATE ai_runs SET status=?,result=? WHERE id=?', (status, json.dumps(result, ensure_ascii=False), run_id))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, payload, kind='application/json; charset=utf-8'):
        data = json.dumps(payload, ensure_ascii=False).encode() if isinstance(payload, (dict, list)) else payload.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def trusted_host(self):
        return self.headers.get('Host') in ('127.0.0.1:8787', 'localhost:8787')

    def do_GET(self):
        if not self.trusted_host():
            return self.reply(403, {'error': '로컬 호스트만 허용합니다.'})
        path = urlsplit(self.path).path
        if path == '/api/state':
            return self.reply(200, state())
        if path == '/api/session':
            return self.reply(200, {'token': TOKEN})
        files = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css'), '/ai.js': ('ai.js', 'text/javascript'), '/ai.css': ('ai.css', 'text/css')}
        if path in files:
            name, mime = files[path]
            return self.reply(200, (ROOT / 'web' / name).read_text(encoding='utf-8'), mime + '; charset=utf-8')
        return self.reply(404, {'error': '페이지를 찾을 수 없습니다.'})

    def do_POST(self):
        if not self.trusted_host() or self.headers.get('X-Hyunode-Token') != TOKEN:
            return self.reply(403, {'error': '유효한 로컬 세션이 필요합니다.'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 8192:
                raise ValueError('잘못된 요청 크기')
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError('JSON 객체가 필요합니다.')
            if self.path == '/api/ai/preview':
                return self.reply(200, ai_preview(body.get('scan_id')))
            if self.path == '/api/ai/analyze':
                preview = ai_preview(body.get('scan_id'))
                if not preview['settings']['configured']:
                    raise ValueError('서버에 OPENAI_API_KEY와 OPENAI_MODEL을 설정하고 재시작하세요.')
                if body.get('consent') is not True or body.get('digest') != preview['digest']:
                    raise ValueError('전송할 근거를 미리 확인하고 동의해주세요.')
                with LOCK, db() as con:
                    if con.execute("SELECT id FROM ai_runs WHERE status IN ('queued','running')").fetchone():
                        raise ValueError('AI 분석이 이미 진행 중입니다.')
                    count = con.execute('SELECT COUNT(*) FROM ai_runs WHERE created>=?', (now()[:10],)).fetchone()[0]
                    if count >= 20:
                        raise ValueError('하루 AI 분석 20회 한도에 도달했습니다 (UTC 기준).')
                    cursor = con.execute("INSERT INTO ai_runs(scan_id,status,created) VALUES(?,'queued',?)", (body['scan_id'], now()))
                    run_id = cursor.lastrowid
                    con.commit()
                    AI_POOL.submit(run_ai, run_id, preview['bundle'])
                return self.reply(202, {'id': run_id})
            if self.path == '/api/targets':
                url = validate_url(body.get('url', ''))
                name = body.get('name', '').strip()
                if not name or len(name) > 80:
                    raise ValueError('대상 이름은 1~80자로 입력하세요.')
                with db() as con:
                    con.execute('INSERT INTO targets(name,url,created) VALUES(?,?,?)', (name, url, now()))
                return self.reply(201, {'ok': True})
            if self.path == '/api/scans':
                with LOCK, db() as con:
                    if con.execute("SELECT id FROM scans WHERE status IN ('queued','running')").fetchone():
                        raise ValueError('진행 중인 검사가 있습니다. 완료 후 다시 실행하세요.')
                    target = con.execute('SELECT * FROM targets WHERE id=?', (body.get('target_id'),)).fetchone()
                    if not target:
                        raise ValueError('등록된 대상을 선택하세요.')
                    validate_url(target['url'])
                    cursor = con.execute("INSERT INTO scans(target_id,status,created) VALUES(?,'queued',?)", (target['id'], now()))
                    scan_id = cursor.lastrowid
                    con.commit()
                    POOL.submit(scan, scan_id, target['url'])
                return self.reply(202, {'id': scan_id})
            return self.reply(404, {'error': '지원하지 않는 기능입니다.'})
        except (ValueError, TypeError, sqlite3.IntegrityError) as exc:
            return self.reply(400, {'error': '이미 등록된 대상입니다.' if isinstance(exc, sqlite3.IntegrityError) else str(exc)})

if __name__ == '__main__':
    init()
    print('Hyunode → http://127.0.0.1:8787', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8787), Handler).serve_forever()
