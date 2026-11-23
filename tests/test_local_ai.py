import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import local_ai
import ai_analysis


class LocalAITests(unittest.TestCase):
    def test_local_selection_never_reads_openai_credentials(self):
        with patch('local_ai.selected', return_value='qwen3.5:2b'), patch('local_ai.config', return_value={'provider': 'local'}), patch('credentials.resolve') as secret:
            self.assertEqual(ai_analysis.config()['provider'], 'local')
            secret.assert_not_called()

    def test_local_failure_has_no_paid_fallback(self):
        with patch('local_ai.selected', return_value='qwen3.5:2b'), patch('local_ai.analyze', side_effect=ValueError('offline')), patch('credentials.resolve') as secret:
            with self.assertRaisesRegex(ValueError, 'offline'):
                ai_analysis.analyze({})
            secret.assert_not_called()

    def test_cloud_model_rejected(self):
        with patch('local_ai.request', return_value={'remote_model': 'remote-model'}):
            with self.assertRaises(ValueError):
                local_ai.check_model('cloud-alias')

    def test_local_output_validated_and_tools_not_granted(self):
        bundle = {'evidence': [{'id': 'E1'}]}
        review = {'summary': '검토', 'observed_facts': [{'statement': '관찰', 'evidence_ids': ['E1']}], 'hypotheses': [], 'priorities': [], 'coverage_gaps': ['제한된 입력']}
        reply = {'done': True, 'done_reason': 'stop', 'message': {'content': json.dumps(review)}, 'prompt_eval_count': 30, 'eval_count': 40}
        with patch('local_ai.check_model'), patch('local_ai.request', return_value=reply) as transport:
            result = local_ai.analyze('model', bundle, ai_analysis.SCHEMA, ai_analysis.INSTRUCTIONS, ai_analysis.validate_analysis)
        payload = transport.call_args.args[2]
        self.assertFalse(payload['stream'])
        self.assertNotIn('tools', payload)
        self.assertEqual(result['usage']['total_tokens'], 70)
        self.assertEqual(result['analysis'], review)

    def test_invented_local_evidence_not_accepted(self):
        review = {'summary': '검토', 'observed_facts': [{'statement': '추정', 'evidence_ids': ['E999']}], 'hypotheses': [], 'priorities': [], 'coverage_gaps': []}
        with patch('local_ai.check_model'), patch('local_ai.request', return_value={'done': True, 'message': {'content': json.dumps(review)}}):
            with self.assertRaisesRegex(ValueError, '검증'):
                local_ai.analyze('model', {'evidence': [{'id': 'E1'}]}, ai_analysis.SCHEMA, '', ai_analysis.validate_analysis)
