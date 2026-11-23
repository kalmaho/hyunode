import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_analysis
from evidence import summarize


class AIReviewTests(unittest.TestCase):
    def setUp(self):
        self.local = patch('local_ai.selected', return_value=None)
        self.local.start()
        self.addCleanup(self.local.stop)
        self.saved = patch('credentials.read_saved', return_value={})
        self.saved.start()
        self.addCleanup(self.saved.stop)

    def bundle(self):
        return ai_analysis.evidence_bundle({'status': 'completed', 'result': {
            'ports': [{'port': 8080, 'state': 'open'}], 'http_status': 200,
            'findings': [{'source': 'Nuclei', 'title': 'secret-host.example password=secret', 'evidence': 'sensitive'},
                         {'source': 'HTTP headers', 'title': 'Content-Security-Policy 미설정'}],
            'notes': ['private credential']}})

    def valid(self):
        return {'summary': '검토', 'observed_facts': [{'statement': '열린 포트', 'evidence_ids': ['E1']}],
                'hypotheses': [], 'priorities': ['수동 확인'], 'coverage_gaps': ['인증 점검 없음']}

    def test_evidence_omits_raw_values(self):
        body = b'<form action="https://secret.example"><input type="password" value="private-password"><script>SECRET</script>'
        obs = summarize([('Set-Cookie', 'session=COOKIE_SECRET; HttpOnly; Secure; SameSite=Lax'),
                         ('Content-Type', 'text/html'), ('X-Private', 'private-header')], body, False)
        encoded = json.dumps(obs)
        for secret in ['secret.example', 'private-password', 'SECRET', 'COOKIE_SECRET', 'private-header']:
            self.assertNotIn(secret, encoded)
        self.assertEqual(obs['structure']['password_fields'], 1)
        self.assertEqual(obs['cookie_flags'], [{'secure': True, 'httponly': True, 'samesite': True}])
        bundle = json.dumps(self.bundle())
        self.assertNotIn('secret-host', bundle)
        self.assertNotIn('credential', bundle)

    def test_rejects_invented_evidence(self):
        value = self.valid()
        value['observed_facts'][0]['evidence_ids'] = ['E999']
        with self.assertRaises(ValueError):
            ai_analysis.validate_analysis(value, self.bundle())

    def test_rejects_wrong_response_shape(self):
        value = self.valid()
        value['hypotheses'] = 'not an array'
        with self.assertRaises(ValueError):
            ai_analysis.validate_analysis(value, self.bundle())

    def test_responses_request_and_parsing_without_real_api(self):
        response = MagicMock(status=200)
        response.read.return_value = json.dumps({'status': 'completed', 'output': [
            {'type': 'reasoning'}, {'type': 'message', 'content': [{'type': 'output_text', 'text': json.dumps(self.valid())}]}],
            'usage': {'input_tokens': 10, 'output_tokens': 20, 'total_tokens': 30}}).encode()
        conn = MagicMock()
        conn.getresponse.return_value = response
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'sk-test-key', 'OPENAI_MODEL': 'test-model'}), patch('ai_analysis.http.client.HTTPSConnection', return_value=conn):
            result = ai_analysis.analyze(self.bundle())
        args = conn.request.call_args.args
        payload = json.loads(args[2])
        self.assertFalse(payload['store'])
        self.assertNotIn('tools', payload)
        self.assertTrue(payload['text']['format']['strict'])
        self.assertEqual(result['usage']['total_tokens'], 30)
        self.assertEqual(result['analysis'], self.valid())
        conn.close.assert_called_once()

    def test_api_failure_does_not_leak_error_body(self):
        response = MagicMock(status=401)
        response.read.return_value = b'upstream PRIVATE_SECRET'
        conn = MagicMock()
        conn.getresponse.return_value = response
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'sk-test-key', 'OPENAI_MODEL': 'test-model'}), patch('ai_analysis.http.client.HTTPSConnection', return_value=conn):
            with self.assertRaises(ValueError) as raised:
                ai_analysis.analyze(self.bundle())
        self.assertNotIn('PRIVATE_SECRET', str(raised.exception))

    def test_unconfigured_does_not_call_api(self):
        with patch.dict(os.environ, {}, clear=True), patch('ai_analysis.http.client.HTTPSConnection') as connection:
            with self.assertRaises(ValueError):
                ai_analysis.analyze(self.bundle())
            connection.assert_not_called()

    def test_quota_and_rate_limits_are_distinguished_without_exposing_body(self):
        for code, kind, expected in [('insufficient_quota', 'insufficient_quota', '잔액'),
                                     ('rate_limit_exceeded', 'rate_limit_error', '속도'),
                                     ('slow_down', 'rate_limit_error', '속도')]:
            raw = json.dumps({'error': {'code': code, 'type': kind, 'message': 'PRIVATE_SECRET'}}).encode()
            message = ai_analysis.api_error(429, raw)
            self.assertIn(expected, message)
            self.assertNotIn('PRIVATE_SECRET', message)
        self.assertIn('일 수 있습니다', ai_analysis.api_error(429, b'not-json PRIVATE_SECRET'))


if __name__ == '__main__':
    unittest.main()
