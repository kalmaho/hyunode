"""Extract bounded structural metadata without storing raw HTML or secrets."""
from html.parser import HTMLParser


class Structure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = 0
        self.password_fields = 0
        self.file_fields = 0
        self.scripts = 0
        self.inline_scripts = 0
        self.links = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.forms += 1
        if tag == 'input':
            self.password_fields += attrs.get('type', '').lower() == 'password'
            self.file_fields += attrs.get('type', '').lower() == 'file'
        if tag == 'script':
            self.scripts += 1
            self.inline_scripts += 'src' not in attrs
        if tag == 'a':
            self.links += 1


def summarize(response_headers, body, truncated):
    headers = {}
    cookies = []
    for k, v in response_headers:
        name = k.lower()
        headers[name] = v
        if name == 'set-cookie':
            flags = {part.strip().split('=', 1)[0].lower() for part in v.split(';')[1:]}
            cookies.append({'secure': 'secure' in flags, 'httponly': 'httponly' in flags, 'samesite': 'samesite' in flags})
    parser = Structure()
    is_html = 'text/html' in headers.get('content-type', '').lower()
    if is_html:
        parser.feed(body.decode('utf-8', errors='replace'))
    return {'headers_present': {name: name in headers for name in ('content-security-policy', 'x-content-type-options',
             'strict-transport-security', 'x-frame-options', 'referrer-policy', 'permissions-policy')},
            'cookie_flags': cookies[:20], 'html_sampled': is_html, 'body_truncated': truncated,
            'structure': {k: getattr(parser, k) for k in ('forms', 'password_fields', 'file_fields', 'scripts', 'inline_scripts', 'links')}}
