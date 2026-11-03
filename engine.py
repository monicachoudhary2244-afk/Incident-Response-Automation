"""Local educational incident response engine. All containment is SIMULATED."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

EVENT_TYPES = {'failed_login', 'malware_alert', 'phishing_email', 'suspicious_process'}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def validate(event):
    if not isinstance(event, dict):
        raise ValueError('Each alert must be a JSON object.')
    required = {'event_id', 'event_type', 'timestamp', 'asset', 'summary'}
    allowed = required | {'source_ip', 'user', 'failed_attempts', 'indicator'}
    if set(event) - allowed or required - set(event):
        raise ValueError('Alert has missing or unsupported fields. See sample_data/alerts.json.')
    for key in required | (set(event) & {'source_ip', 'user', 'indicator'}):
        if not isinstance(event[key], str) or not event[key].strip() or len(event[key]) > 2000:
            raise ValueError(f'{key} must be nonempty text of at most 2000 characters.')
    if event['event_type'] not in EVENT_TYPES:
        raise ValueError('Unsupported event_type.')
    try:
        timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('timestamp must be an ISO 8601 date-time.') from exc
    if timestamp.tzinfo is None:
        raise ValueError('timestamp must include a timezone, for example +00:00.')
    attempts = event.get('failed_attempts')
    if event['event_type'] == 'failed_login':
        if type(attempts) is not int or not 1 <= attempts <= 1000000:
            raise ValueError('failed_login requires failed_attempts between 1 and 1000000.')
    elif attempts is not None:
        raise ValueError('failed_attempts is only accepted for failed_login.')
    return dict(event)


def classify(event):
    kind = event['event_type']
    if kind == 'failed_login':
        if event['failed_attempts'] >= 5:
            return 'HIGH', 'Repeated login failures', 'SIMULATE_BLOCK_SOURCE'
        return 'LOW', 'Login failure review', None
    if kind == 'malware_alert':
        return 'CRITICAL', 'Malware alert response', 'SIMULATE_ISOLATE_ASSET'
    if kind == 'phishing_email':
        return 'HIGH', 'Phishing alert response', 'SIMULATE_QUARANTINE_EMAIL'
    return 'MEDIUM', 'Suspicious process review', None


class Platform:
    def __init__(self, database=None):
        self.path = Path(database or Path.home() / '.college_ir' / 'incidents.db').expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL,
            payload_hash TEXT NOT NULL, event_json TEXT NOT NULL,
            title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closure_note TEXT);
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id),
            name TEXT NOT NULL, status TEXT NOT NULL, result TEXT,
            UNIQUE(incident_id,name));
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id),
            at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
        ''')

    def close_connection(self):
        self.db.close()

    def _audit(self, incident_id, event, detail):
        self.db.execute('INSERT INTO audit(incident_id,at,event,detail) VALUES(?,?,?,?)',
                        (incident_id, utc_now(), event, detail))

    def ingest(self, events):
        if not isinstance(events, list) or not 1 <= len(events) <= 1000:
            raise ValueError('Import must be a JSON list containing 1 to 1000 alerts.')
        checked = [validate(event) for event in events]
        result = []
        # Entire batch commits or rolls back, including audit records.
        with self.db:
            for event in checked:
                payload = json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
                digest = hashlib.sha256(payload.encode()).hexdigest()
                existing = self.db.execute('SELECT id,payload_hash FROM incidents WHERE event_id=?',
                                           (event['event_id'],)).fetchone()
                if existing:
                    if existing['payload_hash'] != digest:
                        raise ValueError(f"Event ID conflict: {event['event_id']}. Existing alert is unchanged.")
                    result.append({'id': existing['id'], 'duplicate': True})
                    continue
                severity, title, containment = classify(event)
                stamp = utc_now()
                status = 'WAITING_APPROVAL' if containment else 'READY_REVIEW'
                cursor = self.db.execute('''INSERT INTO incidents
                    (event_id,payload_hash,event_json,title,severity,status,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?)''',
                    (event['event_id'],digest,payload,title,severity,status,stamp,stamp))
                incident_id = cursor.lastrowid
                self._audit(incident_id, 'INGESTED', 'Validated alert and assigned rule-based severity.')
                for name, receipt in [
                    ('CAPTURE_ALERT', 'Stored supplied alert metadata in SQLite; no endpoint evidence was collected.'),
                    ('CREATE_LOCAL_NOTIFICATION', f'Local notification: {severity} incident requires review. No email sent.')]:
                    self.db.execute('INSERT INTO actions(incident_id,name,status,result) VALUES(?,?,?,?)',
                                    (incident_id,name,'COMPLETED',receipt))
                    self._audit(incident_id, name, receipt)
                if containment:
                    self.db.execute('INSERT INTO actions(incident_id,name,status,result) VALUES(?,?,?,?)',
                        (incident_id,containment,'PENDING_APPROVAL','No external action performed.'))
                    self._audit(incident_id, 'APPROVAL_REQUIRED', containment)
                result.append({'id': incident_id, 'duplicate': False})
        return result

    def list_incidents(self):
        return [dict(r) for r in self.db.execute('''SELECT id,event_id,title,severity,status,
            created_at,updated_at FROM incidents ORDER BY id DESC''')]

    def detail(self, incident_id):
        row = self.db.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
        if row is None:
            raise ValueError('Incident not found.')
        data = dict(row)
        data['alert'] = json.loads(data.pop('event_json'))
        data['actions'] = [dict(r) for r in self.db.execute(
            'SELECT name,status,result FROM actions WHERE incident_id=? ORDER BY id', (incident_id,))]
        data['audit'] = [dict(r) for r in self.db.execute(
            'SELECT at,event,detail FROM audit WHERE incident_id=? ORDER BY id', (incident_id,))]
        return data

    def approve(self, incident_id, note):
        note = self._note(note)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            data = self.detail(incident_id)
            if data['status'] != 'WAITING_APPROVAL':
                raise ValueError('Only incidents waiting for approval can run containment simulation.')
            pending = [a for a in data['actions'] if a['status'] == 'PENDING_APPROVAL']
            if not pending:
                raise ValueError('No pending actions.')
            self._audit(incident_id, 'APPROVED', note)
            for action in pending:
                receipt = 'SIMULATED ONLY: ' + action['name'] + '. No IP, device or email was changed.'
                self.db.execute('UPDATE actions SET status=?,result=? WHERE incident_id=? AND name=?',
                                ('SIMULATED',receipt,incident_id,action['name']))
                self._audit(incident_id, 'SIMULATION_COMPLETED', receipt)
            self.db.execute('UPDATE incidents SET status=?,updated_at=? WHERE id=?',
                            ('SIMULATED_CONTAINMENT',utc_now(),incident_id))
        return self.detail(incident_id)

    def resolve(self, incident_id, note):
        note = self._note(note)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            data = self.detail(incident_id)
            if data['status'] not in ('READY_REVIEW', 'SIMULATED_CONTAINMENT'):
                raise ValueError('Review or approve pending simulation before closing. Closed incidents cannot be closed again.')
            self.db.execute('UPDATE incidents SET status=?,closure_note=?,updated_at=? WHERE id=?',
                            ('CLOSED',note,utc_now(),incident_id))
            self._audit(incident_id, 'CLOSED', note)
        return self.detail(incident_id)

    @staticmethod
    def _note(note):
        if not isinstance(note, str) or not note.strip() or len(note) > 2000:
            raise ValueError('Enter a review note between 1 and 2000 characters.')
        return note.strip()

    def export(self, destination):
        fields = ['id','event_id','title','severity','status','created_at','updated_at']
        def safe(value):
            text = str(value)
            return "'" + text if text.lstrip().startswith(('=', '+', '-', '@')) or text.startswith(('\t','\r','\n')) else text
        with open(destination, 'w', encoding='utf-8-sig', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(fields)
            for row in self.list_incidents():
                writer.writerow([safe(row[field]) for field in fields])


def read_alerts(path):
    path = Path(path)
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Alert file exceeds the 2 MiB demo import limit.')
    return json.loads(path.read_text(encoding='utf-8'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', help='SQLite path; default is ~/.college_ir/incidents.db')
    sub = parser.add_subparsers(dest='command', required=True)
    ingest = sub.add_parser('ingest'); ingest.add_argument('file')
    sub.add_parser('list')
    show = sub.add_parser('show'); show.add_argument('id', type=int)
    for command in ('approve', 'close'):
        cmd = sub.add_parser(command); cmd.add_argument('id', type=int); cmd.add_argument('--note', required=True)
    export = sub.add_parser('export'); export.add_argument('file')
    args = parser.parse_args()
    platform = None
    try:
        platform = Platform(args.db)
        if args.command == 'ingest': result = platform.ingest(read_alerts(args.file))
        elif args.command == 'list': result = platform.list_incidents()
        elif args.command == 'show': result = platform.detail(args.id)
        elif args.command == 'approve': result = platform.approve(args.id, args.note)
        elif args.command == 'close': result = platform.resolve(args.id, args.note)
        else:
            platform.export(args.file); result = {'exported': args.file}
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except (OSError, ValueError, sqlite3.Error) as error:
        parser.exit(1, f'Error: {error}\n')
    finally:
        if platform: platform.close_connection()

if __name__ == '__main__':
    main()
