"""Exercise the extracted workflow step with SDK 0.3.280 shapes and hostile data.

Contract: published sdk.d.ts SDKSystem/Assistant/User/Result/TaskNotification,
sdk-tools.d.ts WorkflowOutput/BashOutput. IDs are joins only; text is never read.
"""
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
STEP = next(s for s in STEPS if s.get('id') == 'stage_receipt')
MARKER = 'synthetic-content-never-published'
PLUGIN = '/home/runner/.claude/plugins/cache/claude-plugins-official/claude-security/0.11.0'
SESSION = 'test-session'


def init(**overrides):
    return dict(type='system', subtype='init', session_id=SESSION,
                tools=['Read', 'Workflow', 'Bash'],
                slash_commands=['claude-security:claude-security'],
                plugins=[dict(name='claude-security', path=PLUGIN)], **overrides)


def result(subtype='success', **overrides):
    return dict(type='result', subtype=subtype, session_id=SESSION,
                is_error=False, permission_denials=[], result=MARKER, **overrides)


def call(name, inputs, call_id='call-1', parent=None):
    return dict(type='assistant', parent_tool_use_id=parent, session_id=SESSION,
                message=dict(stop_reason='tool_use', content=[dict(type='tool_use',
                    id=call_id, name=name, input=inputs)]))


def returned(call_id='call-1', output=None, error=False, parent=None):
    return dict(type='user', session_id=SESSION, parent_tool_use_id=parent,
                tool_use_result=output, message=dict(content=[dict(type='tool_result',
                    tool_use_id=call_id, is_error=error, content=MARKER)]))


def launched(task_id='task-1'):
    return dict(status='async_launched', taskType='local_workflow', taskId=task_id,
                summary=MARKER, scriptPath=MARKER, transcriptDir=MARKER)


def notification(status='completed', task_id='task-1', call_id='call-1'):
    return dict(type='system', subtype='task_notification', session_id=SESSION,
                task_id=task_id, tool_use_id=call_id, status=status,
                output_file=MARKER, summary=MARKER)


class StageReceipt(unittest.TestCase):
    def run_receipt(self, messages=None, raw=None, mode=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / 'runner temp'
            runner.mkdir()
            checkout = root / 'checkout'
            checkout.mkdir()
            (checkout / 'json.py').write_text(f'raise RuntimeError("{MARKER}")\n')
            expected = runner / 'claude-execution-output.json'
            payload = raw if raw is not None else json.dumps(messages).encode()
            if mode == 'symlink':
                target = root / MARKER
                target.write_bytes(payload)
                expected.symlink_to(target)
            elif mode == 'fifo':
                os.mkfifo(expected)
            elif mode != 'missing':
                expected.write_bytes(payload)
            if mode == 'report':
                report = checkout / 'CLAUDE-SECURITY-20260923-000000'
                report.mkdir()
                (report / 'CLAUDE-SECURITY-RESULTS.jsonl').write_text('')
            outputs = root / 'outputs'
            env = {**os.environ, 'RUNNER_TEMP': str(runner),
                   'EXECUTION_FILE': str(expected), 'GITHUB_OUTPUT': str(outputs)}
            if mode == 'outside':
                env['EXECUTION_FILE'] = str(root / MARKER)
            if mode == 'output_error':
                env['GITHUB_OUTPUT'] = str(root)
            run = subprocess.run(['bash', '-c', STEP['run']], cwd=checkout, env=env,
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stderr, '')
            self.assertNotIn(MARKER, run.stdout)
            self.assertNotIn(str(root), run.stdout)
            if mode == 'report':
                self.assertEqual(run.stdout, '')
                self.assertFalse(outputs.exists())
                return None
            receipt = json.loads(run.stdout.splitlines()[-1])
            self.assertEqual(set(receipt), {'schema', 'source_status', 'result',
                                           'workflow', 'skill', 'helpers'})
            self.assertEqual(set(receipt['workflow']), {'available', 'invoked', 'launched',
                'completed', 'failed', 'stopped', 'tool_errors'})
            self.assertEqual(set(receipt['result']), {'subtype', 'is_error', 'limit',
                'stop_reason', 'last_assistant_stop', 'permission_denials', 'refusal_no_fallback'})
            self.assertEqual(set(receipt['helpers']), {'write_scan_meta', 'keep_waiting',
                                                      'save_result', 'render_report'})
            self.assertLessEqual(len(run.stdout.splitlines()[-1]), 2048)
            if mode != 'output_error':
                artifact = Path(outputs.read_text().strip().split('=', 1)[1])
                self.assertTrue(artifact.is_relative_to(runner))
                self.assertEqual(json.loads(artifact.read_text()), receipt)
                self.assertNotIn(MARKER, artifact.read_text())
                self.assertNotIn(SESSION, artifact.read_text())
                self.assertNotIn(PLUGIN, artifact.read_text())
            else:
                self.assertIn('::warning::Safe scanner stage receipt could not be retained.',
                              run.stdout)
            return receipt

    def test_workflow_launch_is_not_completion_and_ids_must_join(self):
        messages = [init(), call('Workflow', {'name': 'claude-security:scan'}),
                    returned(output=launched()), result()]
        receipt = self.run_receipt(messages)
        self.assertEqual(receipt['workflow'], dict(available=True, invoked=1, launched=1,
                                                 completed=0, failed=0, stopped=0, tool_errors=0))
        for event in (notification(task_id='unrelated'), notification(call_id='unrelated')):
            self.assertEqual(self.run_receipt(messages[:-1]+[event,result()])['workflow']['completed'], 0)
        # SDK permits trailing system notifications after the terminal result.
        self.assertEqual(self.run_receipt(messages+[notification()])['workflow']['completed'], 1)

    def test_workflow_terminal_states_and_duplicate_events(self):
        for status in ('completed', 'failed', 'stopped'):
            event = notification(status)
            receipt = self.run_receipt([init(), call('Workflow', {'name': 'claude-security:scan'}),
                returned(output=launched()), event, event, result()])
            self.assertEqual(receipt['workflow'][status], 1)
        started = dict(type='system', subtype='task_started', session_id=SESSION,
            task_id='task-1', tool_use_id='call-1', task_type='local_workflow', workflow_name=MARKER)
        receipt = self.run_receipt([init(), call('Workflow', {'name': 'claude-security:scan'}),
                                   started, notification(), result()])
        self.assertEqual(receipt['workflow']['completed'], 1)

    def test_workflow_errors_do_not_copy_the_error_or_count_launch(self):
        for output,error in (({'error': MARKER}, False), (launched(), True)):
            receipt = self.run_receipt([init(), call('Workflow', {'name': 'claude-security:scan'}),
                                       returned(output=output,error=error), result()])
            self.assertEqual(receipt['workflow']['tool_errors'], 1)
            self.assertEqual(receipt['workflow']['launched'], 0)

    def test_nested_wrong_session_and_prior_result_calls_are_excluded(self):
        root_call = call('Workflow', {'name': 'claude-security:scan'})
        nested = call('Workflow', {'name': 'claude-security:scan'},parent=MARKER)
        other = call('Workflow', {'name': 'claude-security:scan'})
        other['session_id'] = MARKER
        for prefix in ([nested], [other], [root_call,returned(output=launched()),result()]):
            receipt = self.run_receipt([init(),*prefix,returned(output=launched()),notification(),result()])
            self.assertEqual(receipt['workflow']['invoked'], 0)
            self.assertEqual(receipt['workflow']['completed'], 0)
        receipt = self.run_receipt([init(),root_call,returned(output=launched(),parent=MARKER),
                                   notification(),result()])
        self.assertEqual(receipt['workflow']['completed'], 0)

    def test_missing_tool_metadata_stays_unknown(self):
        receipt = self.run_receipt([result()])
        self.assertIsNone(receipt['workflow']['available'])
        self.assertIsNone(receipt['skill']['available'])
        metadata = init(); metadata['tools'] = ['Read']; metadata['slash_commands'] = []
        receipt = self.run_receipt([metadata,result()])
        self.assertIs(receipt['workflow']['available'],False)
        self.assertIs(receipt['skill']['available'],False)

    def test_exact_skill_and_helper_invocations_and_completion(self):
        messages = [init(),call('Skill',dict(skill='claude-security:claude-security'),call_id='skill')]
        helpers = [('write_scan_meta','python3','write_scan_meta.py'),
                   ('keep_waiting','bash','keep-waiting.sh'),
                   ('save_result','python3','save_result.py'),
                   ('render_report','python3','render_report.py')]
        for key,command,filename in helpers:
            messages.extend([call('Bash',dict(command=f'{command} "{PLUGIN}/scripts/{filename}" "{MARKER}"'),key),
                             returned(key,dict(stdout=MARKER,stderr=MARKER,interrupted=False))])
        receipt = self.run_receipt(messages+[result()])
        self.assertEqual(receipt['skill']['invoked'],1)
        for key,_,_ in helpers:
            self.assertEqual(receipt['helpers'][key],dict(invoked=1,completed=1,errors=0))

    def test_helpers_reject_lookalikes_compound_commands_and_unknown_outputs(self):
        valid = f'python3 "{PLUGIN}/scripts/render_report.py" target'
        for command in (f'echo {valid}', valid+'; '+MARKER,valid+' && true',
                        valid+' | cat',valid+' $(echo x)',valid+'\ntrue',
                        'python3 /unrelated/scripts/render_report.py target', 'python3 "unterminated'):
            receipt = self.run_receipt([init(),call('Bash',dict(command=command)),returned(output={}),result()])
            self.assertEqual(receipt['helpers']['render_report']['invoked'],0)
        for output in ({},dict(interrupted=False,backgroundTaskId=MARKER),
                       dict(interrupted=False,timedOutAfterMs=1000)):
            receipt = self.run_receipt([init(),call('Bash',dict(command=valid)),returned(output=output),result()])
            self.assertEqual(receipt['helpers']['render_report']['completed'],0)
        for output,error in ((dict(interrupted=True),False),(dict(interrupted=False),True)):
            receipt = self.run_receipt([init(),call('Bash',dict(command=valid)),returned(output=output,error=error),result()])
            self.assertEqual(receipt['helpers']['render_report']['errors'],1)
        ambiguous = returned(output=dict(interrupted=False))
        ambiguous['message']['content'].append(dict(type='tool_result',tool_use_id='other',content=MARKER))
        receipt = self.run_receipt([init(),call('Bash',dict(command=valid)),ambiguous,result()])
        self.assertEqual(receipt['helpers']['render_report']['completed'],0)

    def test_typed_limits_stop_reasons_and_refusal_without_text(self):
        for subtype,limit in (('success','none_reported'),('error_max_budget_usd','budget'),
                              ('error_max_turns','turns'),('error_during_execution','execution'),
                              ('error_max_structured_output_retries','structured_output')):
            receipt = self.run_receipt([init(),result(subtype,stop_reason='refusal')])
            self.assertEqual(receipt['result']['limit'],limit)
            self.assertEqual(receipt['result']['stop_reason'],'refusal')
        refusal = dict(type='system',subtype='model_refusal_no_fallback',session_id=SESSION,
                       content=MARKER,api_refusal_explanation=MARKER,api_refusal_category=MARKER)
        receipt = self.run_receipt([init(),refusal,result(stop_reason=MARKER)])
        self.assertTrue(receipt['result']['refusal_no_fallback'])
        self.assertEqual(receipt['result']['stop_reason'],'unknown')
        receipt = self.run_receipt([init(),dict(type='assistant',session_id=SESSION,parent_tool_use_id=None,
             message=dict(stop_reason='refusal',content=[dict(type='text',text=MARKER)])),result()])
        self.assertEqual(receipt['result']['last_assistant_stop'],'refusal')

    def test_malformed_and_hostile_shapes_are_bounded_and_private(self):
        for raw in (b'{', b'[{"type":"result","type":"assistant"}]',
                    b'['*2000+b']'*2000,b' '* (4*1024*1024+1)):
            self.assertEqual(self.run_receipt(raw=raw)['source_status'],'invalid')
        for messages in ([{}]*10001,{},[dict(type='result')]):
            self.assertEqual(self.run_receipt(messages)['source_status'],'invalid')
        malformed=init();malformed['tools']=[{'unexpected':MARKER}];malformed['plugins']=[{'name':MARKER,'path':MARKER}]
        receipt=self.run_receipt([malformed,call('Workflow',{'name':[MARKER]}),
                                result(stop_reason={'unexpected':MARKER})])
        self.assertIsNone(receipt['workflow']['available'])
        self.assertEqual(receipt['workflow']['invoked'],0)
        too_many=call('Bash',{});too_many['message']['content']=[{}]*10001
        self.assertEqual(self.run_receipt([init(),too_many,result()])['source_status'],'invalid')

    def test_safe_io_and_report_present_short_circuit(self):
        for mode in ('missing','outside','symlink','fifo'):
            receipt=self.run_receipt([init(),result()],mode=mode)
            self.assertNotEqual(receipt['source_status'],'ok')
            self.assertIsNone(receipt['workflow']['available'])
        self.assertEqual(self.run_receipt([init(),result()],mode='output_error')['source_status'],'ok')
        self.assertIsNone(self.run_receipt([init(),result()],mode='report'))

    def test_diagnostic_steps_are_after_the_gate_and_do_not_change_its_verdict(self):
        self.assertEqual(STEP['if'],"always() && steps.scan.outcome == 'success' && steps.scan.outputs.execution_file != ''")
        gate=next(s for s in STEPS if s['name']=='Gate on high/critical findings')
        upload=next(s for s in STEPS if s.get('id')=='stage_receipt_upload')
        self.assertGreater(STEPS.index(STEP),STEPS.index(gate))
        self.assertGreater(STEPS.index(upload),STEPS.index(STEP))
        for step in (STEP,upload):
            self.assertIs(step['continue-on-error'],True)
            self.assertEqual(step['timeout-minutes'],1)
        self.assertIn("python3 -I - <<'STAGE_RECEIPT_PY'",STEP['run'])
        self.assertEqual(upload['with']['path'],
            'DOLLAR{{ steps.stage_receipt.outputs.receipt_file }}'.replace('DOLLAR',chr(36)))
        self.assertEqual(upload['with']['retention-days'],7)
        with tempfile.TemporaryDirectory() as directory:
            env={**os.environ,'SHOULD_SCAN':'true','SCAN_OUTCOME':'success',
                 'EXECUTION_FILE':'/runner/claude-execution-output.json','BLOCKING':'true',
                 'STEP_TIMEOUT':'90','GITHUB_STEP_SUMMARY':str(Path(directory)/'summary')}
            verdict=subprocess.run(['bash','-c',gate['run']],cwd=directory,env=env,
                                   capture_output=True,text=True,timeout=10)
            self.assertNotEqual(verdict.returncode,0)
            self.assertIn('No scan results found',verdict.stdout)


if __name__ == '__main__':
    unittest.main()
