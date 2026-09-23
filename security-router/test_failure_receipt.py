"""Run the trusted workflow's failure parser against SDK-shaped and hostile inputs."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / '.github/workflows/pr-security-gate.yml').read_text())
STEPS = WORKFLOW['jobs']['scan']['steps']
STEP = next(s for s in STEPS if s.get('id') == 'failure_receipt')
SECRET = 'private-sentinel-sk-ant-oat-test-user-source-session-id'
FIELDS = {'schema', 'source_status', 'category', 'result_subtype',
          'sdk_error', 'api_error_status'}


def assistant(error=None, parent=None):
    return dict(type='assistant', error=error, parent_tool_use_id=parent,
                session_id=SECRET, message=dict(role='assistant', id=SECRET,
                content=[dict(type='text', text=SECRET)]))


def result(**overrides):
    return dict(type='result', subtype='success', is_error=True,
                result=SECRET, session_id=SECRET, **overrides)


class FailureReceipt(unittest.TestCase):
    def run_receipt(self, messages=None, raw=None, mode=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / 'runner temp'
            runner.mkdir()
            checkout = root / 'checkout'
            checkout.mkdir()
            (checkout / 'json.py').write_text(f'raise RuntimeError("{SECRET}")\n')
            expected = runner / 'claude-execution-output.json'
            payload = raw if raw is not None else json.dumps(messages).encode()
            if mode == 'symlink':
                target = root / SECRET
                target.write_bytes(payload)
                expected.symlink_to(target)
            elif mode == 'fifo':
                os.mkfifo(expected)
            elif mode != 'missing':
                expected.write_bytes(payload)
            outputs = root / 'outputs'
            env = {**os.environ, 'RUNNER_TEMP': str(runner),
                   'EXECUTION_FILE': str(expected), 'GITHUB_OUTPUT': str(outputs)}
            if mode == 'outside':
                env['EXECUTION_FILE'] = str(root / SECRET)
            if mode == 'output_error':
                env['GITHUB_OUTPUT'] = str(root)
            run = subprocess.run(['bash', '-c', STEP['run']], cwd=checkout,
                                 env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stderr, '')
            self.assertNotIn(SECRET, run.stdout)
            self.assertNotIn(str(root), run.stdout)
            receipt = json.loads(run.stdout.splitlines()[-1])
            self.assertEqual(set(receipt), FIELDS)
            self.assertLessEqual(len(json.dumps(receipt)), 512)
            if mode != 'output_error':
                output = outputs.read_text()
                self.assertTrue(output.startswith('receipt_file='))
                artifact = Path(output.strip().split('=', 1)[1])
                self.assertTrue(artifact.is_relative_to(runner))
                self.assertEqual(json.loads(artifact.read_text()), receipt)
                self.assertNotIn(SECRET, artifact.read_text())
            else:
                self.assertIn('::warning::Safe scanner failure receipt could not be retained.',
                              run.stdout)
            return receipt

    def test_real_sdk_array_retains_typed_model_failure_without_content(self):
        receipt = self.run_receipt([
            {'type': 'system', 'subtype': 'init', 'model': SECRET},
            {'type': 'user', 'message': {'content': SECRET}},
            assistant('model_not_found'), result(api_error_status=404)])
        self.assertEqual(receipt['category'], 'model_not_found')
        self.assertEqual(receipt['sdk_error'], 'model_not_found')
        self.assertEqual(receipt['api_error_status'], 404)

    def test_typed_auth_billing_capacity_and_request_errors(self):
        for error in ('authentication_failed', 'oauth_org_not_allowed', 'account_on_hold',
                      'billing_error', 'rate_limit', 'overloaded', 'invalid_request',
                      'server_error', 'max_output_tokens'):
            with self.subTest(error=error):
                self.assertEqual(self.run_receipt([assistant(error), result()])['category'], error)

    def test_http_status_fallback_when_typed_assistant_error_is_missing(self):
        for status, category in ((401, 'authentication_failed'), (403, 'permission_denied'),
                                 (404, 'request_not_found'), (429, 'rate_limit'),
                                 (529, 'overloaded'), (400, 'invalid_request')):
            with self.subTest(status=status):
                receipt = self.run_receipt([assistant(), result(api_error_status=status)])
                self.assertEqual(receipt['category'], category)
                self.assertEqual(receipt['api_error_status'], status)

    def test_absent_fields_and_freeform_body_stay_unclassified(self):
        doc = result()
        doc['result'] = 'API Error: 401 authentication_failed ' + SECRET
        receipt = self.run_receipt([assistant(SECRET), doc])
        self.assertEqual(receipt['category'], 'unclassified')
        self.assertIsNone(receipt['sdk_error'])
        self.assertIsNone(receipt['api_error_status'])

    def test_last_terminal_result_uses_only_last_root_assistant(self):
        messages = [assistant('authentication_failed'), result(api_error_status=401),
                    assistant('model_not_found'), assistant('billing_error', parent=SECRET),
                    result(api_error_status=404)]
        self.assertEqual(self.run_receipt(messages)['category'], 'model_not_found')
        messages.insert(-1, assistant())
        receipt = self.run_receipt(messages)
        self.assertIsNone(receipt['sdk_error'])
        self.assertEqual(receipt['category'], 'request_not_found')
        # No assistant in the last result's interval must not reuse an earlier error.
        receipt = self.run_receipt([assistant('billing_error'), result(),
                                    result(api_error_status=404)])
        self.assertIsNone(receipt['sdk_error'])
        self.assertEqual(receipt['category'], 'request_not_found')

    def test_loop_failures_ignore_stale_assistant_errors(self):
        for subtype, category in (('error_max_turns', 'turn_limit'),
                                  ('error_max_budget_usd', 'budget_limit'),
                                  ('error_during_execution', 'execution_error'),
                                  ('error_max_structured_output_retries', 'structured_output_limit')):
            terminal = dict(type='result', subtype=subtype, is_error=True, errors=[SECRET])
            self.assertEqual(self.run_receipt([assistant('billing_error'), terminal])['category'],
                             category)

    def test_success_result_is_not_misreported_as_provider_failure(self):
        terminal = result()
        terminal['is_error'] = False
        receipt = self.run_receipt([assistant('billing_error'), terminal])
        self.assertEqual(receipt['category'], 'no_failed_result')
        self.assertIsNone(receipt['sdk_error'])

    def test_untrusted_status_and_error_shapes_are_not_copied(self):
        for status in (SECRET, True, 401.0, 999, {'token': SECRET}):
            with self.subTest(status=status):
                receipt = self.run_receipt([assistant({'token': SECRET}),
                                            result(api_error_status=status)])
                self.assertEqual(receipt['category'], 'unclassified')
                self.assertIsNone(receipt['api_error_status'])

    def test_malformed_duplicate_deep_or_non_array_json_is_safe(self):
        payloads = [b'{', json.dumps({'secret': SECRET}).encode(),
                    b'[{"type":"result","type":"assistant"}]',
                    b'[' * 2000 + b']' * 2000]
        for raw in payloads:
            with self.subTest(raw=raw[:20]):
                self.assertEqual(self.run_receipt(raw=raw)['source_status'], 'invalid')

    def test_oversize_input_and_message_count_are_bounded(self):
        self.assertEqual(self.run_receipt(raw=b' ' * (4 * 1024 * 1024 + 1))['source_status'],
                         'invalid')
        self.assertEqual(self.run_receipt([{}] * 10001)['source_status'], 'invalid')

    def test_missing_outside_symlink_and_fifo_inputs_do_not_leak(self):
        for mode in ('missing', 'outside', 'symlink', 'fifo'):
            with self.subTest(mode=mode):
                receipt = self.run_receipt([assistant('billing_error'), result()], mode=mode)
                self.assertNotEqual(receipt['source_status'], 'ok')
                self.assertEqual(receipt['category'], 'unclassified')

    def test_receipt_storage_failure_does_not_raise_or_change_the_scan(self):
        receipt = self.run_receipt([assistant('model_not_found'), result()], mode='output_error')
        self.assertEqual(receipt['category'], 'model_not_found')

    def test_workflow_failure_only_isolation_and_safe_artifact_path(self):
        self.assertEqual(STEP['if'], "always() && (steps.scan.outcome == 'failure' || steps.scan.outcome == 'cancelled')")
        self.assertIs(STEP['continue-on-error'], True)
        self.assertIn("python3 -I - <<'FAILURE_RECEIPT_PY'", STEP['run'])
        upload = next(s for s in STEPS if s.get('id') == 'failure_receipt_upload')
        self.assertIs(upload['continue-on-error'], True)
        gate_index = next(i for i, s in enumerate(STEPS)
                          if s['name'] == 'Gate on high/critical findings')
        self.assertGreater(STEPS.index(STEP), gate_index)
        self.assertGreater(STEPS.index(upload), STEPS.index(STEP))
        self.assertEqual(STEP['timeout-minutes'], 1)
        self.assertEqual(upload['timeout-minutes'], 1)
        self.assertEqual(upload['with']['path'],
                         'DOLLAR{{ steps.failure_receipt.outputs.receipt_file }}'.replace('DOLLAR', chr(36)))
        self.assertEqual(upload['with']['retention-days'], 7)
        for step_id in ('failure_receipt', 'failure_receipt_upload'):
            self.assertEqual(sum(s.get('id') == step_id for s in STEPS), 1)


if __name__ == '__main__':
    unittest.main()
