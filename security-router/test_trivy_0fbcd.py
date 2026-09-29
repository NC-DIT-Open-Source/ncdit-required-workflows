"""Exact 0fbcd config observations and source bindings; no hosted/full-scan claim."""
import copy,hashlib,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('current_0fbcd_contract',H/'trivy_contract.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
RAW=(H/'fixtures/0fbcd-policy-source.json').read_bytes()
assert hashlib.sha256(RAW).hexdigest()=='a73ea107f3485a32ec6dcce4125f1dc0b9cd34e82835b9adcd79c8d9a0aae816'
F=json.loads(RAW)
# Retain all authentic 0fbcd methods and raw observations at their historical
# policy constants; current8348 is tested separately without relabeling old scans.
c.SOURCES={p:c.sha(b.encode())for p,b in F['sources'].items()}
c.EXPECTED=[c.normalized(r,f,'')for r in F['actual_config']['Results']for f in r.get('Misconfigurations',[])]
def findings(value):return [(r,f)for r in value['Results']for f in r.get('Misconfigurations',[])]
def triple():return tuple(copy.deepcopy(F[k])for k in ('synthetic_filesystem','actual_config','synthetic_sarif'))
class Source0fbcd(unittest.TestCase):
 def test_actual_scan_is_complete_and_limited(self):
  self.assertEqual(hashlib.sha256(F['actual_config_raw'].encode()).hexdigest(),F['actual_config_sha256'])
  self.assertEqual(json.loads(F['actual_config_raw']),F['actual_config'])
  self.assertEqual(F['actual_config_native_terminal']['stdout_sha256'],F['actual_config_sha256'])
  self.assertEqual(F['actual_config_native_terminal']['native_exit_code'],0);self.assertTrue(F['actual_config_native_terminal']['supervisor_reaped'])
  self.assertEqual(F['scanner']['version'],'0.70.0');self.assertFalse(F['hosted_clearance']);self.assertFalse(F['whole_filesystem_scan_performed']);self.assertFalse(F['vulnerability_scan_performed'])
  raw=F['actual_config'];self.assertEqual(raw['Trivy']['Version'],'0.70.0');self.assertEqual(raw['ArtifactType'],'filesystem')
  self.assertEqual(sum(r['MisconfSummary']['Successes']for r in raw['Results']),2039)
  self.assertEqual(len(findings(raw)),9)
  observed=[c.normalized(r,f,'')for r,f in findings(raw)];self.assertEqual(observed,c.EXPECTED)
  self.assertEqual(c.report(raw,'',config_only=True)['blockers'],[])
 def test_exact_thirteen_source_bodies_and_only_two_changed_members(self):
  self.assertEqual(F['source_head'],'0fbcd14bf229930a9712147c4c4dfc8bf6248301')
  self.assertEqual(F['source_tree'],'8851ca41f233fc73b3ebe3335c69325eef041610')
  self.assertEqual({p:c.sha(b.encode())for p,b in F['sources'].items()},c.SOURCES)
  self.assertEqual(len(c.SOURCES),13)
  self.assertEqual(set(c.SOURCES),set(F['previous_policy']['sources']))
  self.assertEqual({p for p in c.SOURCES if c.SOURCES[p]!=F['previous_policy']['sources'][p]}, {'infra/aws/modules/database-audit-projection/main.tf','infra/aws/database-audit/main.tf'})
  for r,f in findings(F['actual_config']):
   source=F['sources']['infra/aws/'+r['Target']].splitlines()
   for line in f['CauseMetadata'].get('Code',{}).get('Lines',[]):
    if not line['Truncated']:self.assertEqual(line['Content'],source[line['Number']-1])
 def test_only_two_same_receiver_high_classifications(self):
  old=[copy.deepcopy(x)for x in F['previous_policy']['expected']if x['severity']=='HIGH'];new=[copy.deepcopy(x)for x in c.EXPECTED if x['severity']=='HIGH']
  for rows in (old,new):
   for row in rows:row.pop('start_line');row.pop('end_line')
  self.assertEqual(new,old);self.assertEqual(len(new),2);self.assertTrue(all(x['rule']=='AWS-0132'for x in new))
  self.assertEqual(sorted(x['severity']for x in c.EXPECTED),['HIGH','HIGH','LOW','LOW','LOW','LOW','MEDIUM','MEDIUM','MEDIUM'])
  trails=[x for x in c.EXPECTED if x['rule']=='AWS-0014'];self.assertEqual(len(trails),2)
  self.assertTrue(all(x['resource']=='aws_cloudtrail.database[0]'for x in trails))
 def test_real_scanner_locations_are_exact_not_guessed(self):
  expected={(x['target'],x['rule']):(x['start_line'],x['end_line'])for x in c.EXPECTED}
  self.assertEqual(expected[('modules/audit-foundation/receivers.tf','AWS-0089')],(67,81))
  self.assertEqual(expected[('modules/audit-foundation/receivers.tf','AWS-0132')],(103,110))
  self.assertEqual(expected[('operator-database/stores.tf','AWS-0014')],(176,176))
  self.assertEqual(expected[('operator-database/hosted/stores.tf','AWS-0014')],(157,157))
  self.assertEqual(expected[('modules/database-audit-projection/main.tf','AWS-0066')],(117,135))
  for index in range(9):
   for field in ('StartLine','EndLine'):
    value=copy.deepcopy(F['actual_config']);findings(value)[index][1]['CauseMetadata'][field]+=1
    with self.subTest(index=index,field=field),self.assertRaises(ValueError):c.report(value,'',config_only=True)
 def test_synthetic_native_conversion_retains_exact_nine_raw_findings(self):
  projected=copy.deepcopy(F['actual_config'])
  projected['ArtifactType']='repository'
  projected['Metadata']={'RepoURL':'https://github.com/'+c.REPOSITORY+'.git','Commit':F['source_head']}
  for r in projected['Results']:
   r['Target']='infra/aws/'+r['Target']
   for f in r.get('Misconfigurations',[]):
    for o in f['CauseMetadata'].get('Occurrences',[]):o['Filename']='infra/aws/'+o['Filename']
  self.assertEqual(projected,F['synthetic_filesystem'])
  values=triple();before=copy.deepcopy(values);decision,upload,removed=c.upload_view(*values)
  self.assertEqual(values,before);self.assertEqual(len(decision['iac_findings']),9);self.assertEqual(len(removed),2)
  self.assertEqual(len(values[2]['runs'][0]['results']),9);self.assertEqual(len(upload['runs'][0]['results']),7)
  restored=copy.deepcopy(upload)
  for row in sorted(removed,key=lambda x:x['raw_result_index']):restored['runs'][0]['results'].insert(row['raw_result_index'],values[2]['runs'][0]['results'][row['raw_result_index']])
  self.assertEqual(restored,values[2]);self.assertEqual(F['synthetic_converter_terminal']['native_exit_code'],0)
 def test_every_finding_schema_identity_multiplicity_hostile(self):
  for which in (0,1):
   for index in range(9):
    for mode in ('missing','duplicate','severity','rule','resource','caller'):
     values=triple();r,f=findings(values[which])[index]
     if mode=='missing':r['Misconfigurations'].remove(f)
     elif mode=='duplicate':r['Misconfigurations'].append(copy.deepcopy(f))
     elif mode=='severity':f['Severity']='CRITICAL'
     elif mode=='rule':f['ID']='AWS-9999'
     elif mode=='resource':f['CauseMetadata']['Resource']='foreign'
     else:f['CauseMetadata']['Occurrences']=[{'Resource':'foreign','Filename':'foreign.tf','Location':{'StartLine':1,'EndLine':2}}]
     with self.subTest(which=which,index=index,mode=mode),self.assertRaises(ValueError):c.classify(*values)
  for kind in ('Vulnerabilities','Secrets','Licenses'):
   for severity in ('HIGH','CRITICAL'):
    values=triple();values[0]['Results'].append(dict(Target='foreign.txt',Class='secret',Type='synthetic',**{kind:[{'Severity':severity}]}))
    with self.subTest(kind=kind,severity=severity),self.assertRaises(ValueError):c.classify(*values)
 def test_new_low_medium_observations_cannot_become_exceptions(self):
  for target in ('modules/database-audit-projection/main.tf','operator-database/hosted/stores.tf'):
   for severity in ('HIGH','CRITICAL'):
    values=triple()
    for report in values[:2]:
     for r,f in findings(report):
      if r['Target'].endswith(target):f['Severity']=severity
    with self.subTest(target=target,severity=severity),self.assertRaises(ValueError):c.classify(*values)
 def test_current_source_clean_hash_positive_and_all_mutations(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp).resolve()
   def git(*a):return subprocess.check_output(['git','-C',str(root),*a],stderr=subprocess.DEVNULL,text=True).strip()
   git('init','-q');git('config','user.name','synthetic');git('config','user.email','synthetic@example.invalid');git('remote','add','origin','https://github.com/'+c.REPOSITORY+'.git')
   for n,b in F['sources'].items():p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(b)
   git('add','.');git('commit','-qm','exact public source fixture')
   self.assertEqual(c.source(root,git('rev-parse','HEAD'),os.environ)['source_sha256'],c.SOURCES)
   for n in c.SOURCES:
    p=root/n;before=p.read_bytes();p.write_bytes(before+b'\n# mutation\n');git('add',n);git('commit','-qm','synthetic hash hostile')
    with self.subTest(path=n),self.assertRaisesRegex(ValueError,'reviewed-source-hash'):c.source(root,git('rev-parse','HEAD'),os.environ)
    p.write_bytes(before);git('add',n);git('commit','-qm','restore fixture')
   (root/'untracked').write_text('synthetic')
   with self.assertRaisesRegex(ValueError,'dirty-checkout'):c.source(root,git('rev-parse','HEAD'),os.environ)
 def test_only_observed_projection_coordinates_changed_and_stale_rows_reject(self):
  previous=copy.deepcopy(F['previous_policy']['expected'])
  self.assertEqual(previous[2]['start_line'],104);self.assertEqual(previous[2]['end_line'],122)
  self.assertEqual(previous[2]['occurrences'][0]['end_line'],88)
  previous[2]['start_line']=117;previous[2]['end_line']=135;previous[2]['occurrences'][0]['end_line']=89
  self.assertEqual(c.EXPECTED,previous)
  for field,old in (('StartLine',104),('EndLine',122),('caller_end',88)):
   values=triple()
   for report in values[:2]:
    r,f=next((r,f)for r,f in findings(report)if r['Target'].endswith('modules/database-audit-projection/main.tf'))
    if field=='caller_end':f['CauseMetadata']['Occurrences'][0]['Location']['EndLine']=old
    else:f['CauseMetadata'][field]=old
   with self.subTest(field=field),self.assertRaises(ValueError):c.classify(*values)
if __name__=='__main__':unittest.main(verbosity=2)
