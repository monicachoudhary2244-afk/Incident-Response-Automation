"""Repeatable demo using a temporary database, without touching the GUI database."""
from pathlib import Path
import json
import tempfile
from engine import Platform, read_alerts


def main():
    root=Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix='college_ir_demo_') as temporary:
        platform=Platform(Path(temporary)/'demo.db')
        try:
            alerts=read_alerts(root/'sample_data'/'alerts.json')
            imported=platform.ingest(alerts)
            print('New incidents:',len(imported))
            print('Duplicate alerts skipped:',sum(r['duplicate'] for r in platform.ingest(alerts)))
            for row in reversed(platform.list_incidents()):
                print(row['id'],row['severity'],row['status'],row['title'])
            first=imported[0]['id']
            print('After approval:',platform.approve(first,'Reviewed classroom sample; approve simulation.')['status'])
            print('After closure:',platform.resolve(first,'Simulation verified; classroom incident closed.')['status'])
            platform.export(root/'docs'/'sample_incidents.csv')
            (root/'docs'/'sample_incident_detail.json').write_text(json.dumps(platform.detail(first),indent=2),encoding='utf-8')
            print('Exported docs/sample_incidents.csv and docs/sample_incident_detail.json')
        finally: platform.close_connection()

if __name__=='__main__':main()
