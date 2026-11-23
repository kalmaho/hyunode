import ctypes
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import credentials
import ai_analysis


class CredentialTests(unittest.TestCase):
    def test_environment_override_does_not_read_stored_key(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'temporary-key', 'OPENAI_MODEL': 'temporary-model'}, clear=True), patch('credentials.read_saved') as saved:
            value = credentials.resolve()
        self.assertEqual(value['source'], 'environment')
        saved.assert_not_called()

    def test_partial_environment_does_not_mix_keys_and_models(self):
        with patch.dict(os.environ, {'OPENAI_MODEL': 'temporary-model'}, clear=True), patch('credentials.read_saved') as saved:
            self.assertFalse(credentials.resolve()['key'])
        saved.assert_not_called()

    def test_saved_configuration_never_exposes_key_in_public_config(self):
        with patch.dict(os.environ, {}, clear=True), patch('credentials.read_saved', return_value={'key': 'PRIVATE_TEST_KEY', 'model': 'test-model'}):
            config = ai_analysis.config()
        self.assertTrue(config['configured'])
        self.assertEqual(config['source'], 'windows_credential_manager')
        self.assertNotIn('PRIVATE_TEST_KEY', json.dumps(config))

    def test_native_write_uses_current_machine_persistence_and_clears_buffer(self):
        dll = MagicMock()
        captured = {}
        def write(pointer, flags):
            entry = ctypes.cast(pointer, ctypes.POINTER(credentials.Credential)).contents
            captured['persist'] = entry.Persist
            captured['target'] = entry.TargetName
            captured['type'] = entry.Type
            captured['size'] = entry.CredentialBlobSize
            captured['pointer'] = entry.CredentialBlob
            captured['blob'] = ctypes.string_at(entry.CredentialBlob, entry.CredentialBlobSize)
            return True
        dll.CredWriteW.side_effect = write
        with patch('credentials.api', return_value=dll):
            credentials.save('test-key', 'test-model')
        self.assertEqual(captured['persist'], 2)
        self.assertEqual(captured['target'], credentials.TARGET)
        self.assertEqual(json.loads(captured['blob']), {'key': 'test-key', 'model': 'test-model'})
        self.assertEqual(ctypes.string_at(captured['pointer'], captured['size']), b'\x00' * captured['size'])

    def test_native_read_frees_os_buffer(self):
        raw = json.dumps({'key': 'test-key', 'model': 'test-model'}).encode()
        blob = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
        entry = credentials.Credential()
        entry.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte))
        entry.CredentialBlobSize = len(raw)
        dll = MagicMock()
        def read(target, kind, flags, out):
            result = ctypes.cast(out, ctypes.POINTER(ctypes.POINTER(credentials.Credential)))
            result[0] = ctypes.pointer(entry)
            return True
        dll.CredReadW.side_effect = read
        with patch('credentials.os.name', 'nt'), patch('credentials.api', return_value=dll):
            self.assertEqual(credentials.read_saved()['model'], 'test-model')
        dll.CredFree.assert_called_once()

    def test_missing_credential_falls_back_to_unconfigured(self):
        dll = MagicMock()
        dll.CredReadW.return_value = False
        with patch('credentials.os.name', 'nt'), patch('credentials.api', return_value=dll), patch('credentials.ctypes.get_last_error', return_value=1168, create=True):
            self.assertEqual(credentials.read_saved(), {})

    def test_credential_storage_error_does_not_leak_key(self):
        with patch('credentials.resolve', side_effect=OSError('private-error')):
            value = ai_analysis.config()
        self.assertFalse(value['configured'])
        self.assertEqual(value['source'], 'credential_error')
        self.assertNotIn('private-error', json.dumps(value))


if __name__ == '__main__':
    unittest.main()
