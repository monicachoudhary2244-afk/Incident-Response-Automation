import csv
import json
from pathlib import Path
import tempfile
import unittest
from engine import Platform, classify, validate, read_alerts


def alert(event_id='TEST-1',kind='failed_login'):
    value={'event_id':event_id,'event_type':kind,'timestamp':'2026-10-31T10:00:00+00:00',
           'asset':'TEST-ASSET','summary':'Classroom test'}
    if kind=='failed_login':value['failed_attempts']=8
    return value

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.platform=Platform(self.root/'test.db')
        self.addCleanup(self.platform.close_connection)

    def test_rule_severity_and_threshold(self):
        self.assertEqual(classify(alert())[0],'HIGH')
        value=alert(); value['failed_attempts']=4
        self.assertEqual(classify(value)[0],'LOW')
        value['failed_attempts']=5
        self.assertEqual(classify(value)[0],'HIGH')
        for kind,expected in [('malware_alert','CRITICAL'),('phishing_email','HIGH'),('suspicious_process','MEDIUM')]:
            self.assertEqual(classify(alert(kind=kind))[0],expected)

    def test_ingestion_creates_automatic_tasks(self):
        incident=self.platform.ingest([alert()])[0]['id']
        data=self.platform.detail(incident)
        self.assertEqual(data['status'],'WAITING_APPROVAL')
        self.assertEqual([a['status'] for a in data['actions']],['COMPLETED','COMPLETED','PENDING_APPROVAL'])
        self.assertEqual(len(data['audit']),4)

    def test_exact_duplicate_is_idempotent(self):
        first=self.platform.ingest([alert()])[0]['id']
        before=self.platform.detail(first)
        result=self.platform.ingest([alert()])[0]
        self.assertEqual(result,{'id':first,'duplicate':True})
        self.assertEqual(self.platform.detail(first),before)

    def test_conflict_rolls_back_entire_batch(self):
        self.platform.ingest([alert()])
        changed=alert(); changed['asset']='different'
        with self.assertRaises(ValueError):self.platform.ingest([alert('NEW'),changed])
        self.assertEqual(len(self.platform.list_incidents()),1)
        self.assertEqual(self.platform.detail(1)['alert']['asset'],'TEST-ASSET')

    def test_invalid_batch_has_no_partial_import(self):
        bad=alert('BAD'); bad['event_type']='unknown'
        with self.assertRaises(ValueError):self.platform.ingest([alert(),bad])
        self.assertEqual(self.platform.list_incidents(),[])

    def test_rejects_missing_timezone_and_bool_attempts(self):
        value=alert(); value['timestamp']='2026-10-31T10:00:00'
        with self.assertRaises(ValueError):validate(value)
        value=alert(); value['failed_attempts']=True
        with self.assertRaises(ValueError):validate(value)

    def test_approval_is_simulated_and_not_repeatable(self):
        incident=self.platform.ingest([alert()])[0]['id']
        data=self.platform.approve(incident,'Reviewed demo')
        self.assertEqual(data['status'],'SIMULATED_CONTAINMENT')
        self.assertEqual(data['actions'][-1]['status'],'SIMULATED')
        self.assertIn('No IP, device or email was changed',data['actions'][-1]['result'])
        with self.assertRaises(ValueError):self.platform.approve(incident,'Again')
        self.assertEqual(data,self.platform.detail(incident))

    def test_closure_requires_completed_workflow(self):
        incident=self.platform.ingest([alert()])[0]['id']
        with self.assertRaises(ValueError):self.platform.resolve(incident,'Too early')
        self.platform.approve(incident,'Reviewed')
        self.assertEqual(self.platform.resolve(incident,'Done')['status'],'CLOSED')
        with self.assertRaises(ValueError):self.platform.resolve(incident,'Again')

    def test_low_priority_closes_without_containment(self):
        value=alert(); value['failed_attempts']=2
        incident=self.platform.ingest([value])[0]['id']
        self.assertEqual(self.platform.detail(incident)['status'],'READY_REVIEW')
        self.assertEqual(self.platform.resolve(incident,'Reviewed benign demo')['status'],'CLOSED')

    def test_blank_notes_rejected(self):
        incident=self.platform.ingest([alert()])[0]['id']
        with self.assertRaises(ValueError):self.platform.approve(incident,' ')
        self.assertEqual(self.platform.detail(incident)['status'],'WAITING_APPROVAL')

    def test_database_persistence(self):
        incident=self.platform.ingest([alert()])[0]['id']
        other=Platform(self.root/'test.db')
        try:self.assertEqual(other.detail(incident)['event_id'],'TEST-1')
        finally:other.close_connection()

    def test_unknown_id_and_parameterized_text(self):
        with self.assertRaises(ValueError):self.platform.detail(999)
        event_id="x'); DROP TABLE incidents; --"
        self.platform.ingest([alert(event_id)])
        self.assertEqual(self.platform.list_incidents()[0]['event_id'],event_id)

    def test_csv_neutralizes_formula(self):
        self.platform.ingest([alert('=1+1')]); path=self.root/'out.csv'
        self.platform.export(path)
        with path.open(encoding='utf-8-sig',newline='') as stream:rows=list(csv.reader(stream))
        self.assertEqual(rows[1][1],"'=1+1")

    def test_import_file_validation_and_limit(self):
        path=self.root/'alerts.json'; path.write_text(json.dumps([alert()]))
        self.assertEqual(len(read_alerts(path)),1)
        path.write_text('x'*(2*1024*1024+1))
        with self.assertRaises(ValueError):read_alerts(path)
        with self.assertRaises(ValueError):self.platform.ingest([])

if __name__=='__main__':unittest.main(verbosity=2)
