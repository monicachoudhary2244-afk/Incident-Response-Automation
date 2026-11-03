# Incident Response Automation Platform

College cybersecurity project: Python + Tkinter + SQLite. Imports structured alerts, assigns severity, creates playbook tasks, requests review before simulated containment, and records closure notes and audit history.

**All containment is simulated.** No IP is blocked, device isolated, email quarantined, message sent or URL visited. The application automates local records and workflow; it does not integrate with real security products.

## Start on a laptop

1. Extract the entire ZIP.
2. Use Python 3.10+ with Tkinter and sqlite3 available. There are no pip dependencies.
3. Open a terminal in the `Incident_Response_Automation` folder.
4. Run `python -m tkinter` to check GUI support.
5. Run `python app.py`, or use `start_windows.bat` on Windows when Python is on PATH.
6. Click **Load sample alerts**.

Use `python3` instead of `python` where required. The GUI needs a local desktop; it does not display directly in Google Colab or on an Android phone. The CLI and `demo.py` can run without a desktop.

## Five minute demonstration

1. Load the five sample alerts. Expect one critical, two high, one medium and one low incident. Three incidents await approval; two are ready for review.
2. Load the samples again. Expect five duplicates skipped and no additional incidents.
3. Select the repeated-login-failures incident. Show its original alert, two completed local tasks and one pending simulated block action.
4. Click **Approve simulation**, then enter a review note. Status becomes `SIMULATED_CONTAINMENT`.
5. Show the audit timeline and simulation receipt. Explain that no real blocking occurred.
6. Click **Close incident** and enter a closure note. Status becomes `CLOSED`.
7. Export the incident summary to CSV.
8. Select a low or medium incident. It can be closed after review without containment approval.

For an isolated repeatable demo: `python demo.py`. It uses a temporary database and writes example outputs into `docs/`; it does not change your dashboard database.

## CLI commands

Run from the project folder. Put the global `--db` option before the command. IDs below assume a new `classroom.db`; use the returned IDs for an existing database.

```bash
python engine.py --db classroom.db ingest sample_data/alerts.json
python engine.py --db classroom.db list
python engine.py --db classroom.db show 1
python engine.py --db classroom.db approve 1 --note "Reviewed classroom alert"
python engine.py --db classroom.db close 1 --note "Simulation verified and reviewed"
python engine.py --db classroom.db export incident_report.csv
python -m unittest -v
```

Omit `--db` to use the same default database as the GUI: `~/.college_ir/incidents.db`. `~` means the current user's home directory. Back up this file with the application closed. For a fresh CLI demonstration choose a new database filename. The GUI keeps its incidents between sessions; loading samples does not reset it. There is no delete/reset button.

## Implemented playbooks

| Input alert | Severity | Automatic local steps | Approval step |
|---|---|---|---|
| `failed_login`, 5 or more attempts | HIGH | Capture supplied alert, create local notification | Simulate source blocking |
| `failed_login`, 1–4 attempts | LOW | Capture supplied alert, create local notification | None; review and close |
| `malware_alert` | CRITICAL | Capture supplied alert, create local notification | Simulate asset isolation |
| `phishing_email` | HIGH | Capture supplied alert, create local notification | Simulate email quarantine |
| `suspicious_process` | MEDIUM | Capture supplied alert, create local notification | None; review and close |

These are fixed educational rules, not validated threat scores. Failed attempts must already be aggregated by the input producer. The platform does not combine login events, apply a time window or independently detect malware/phishing.

## Input format

Import a UTF-8 JSON **array** of 1–1000 alert objects; files must be no larger than 2 MiB. Required fields are `event_id`, `event_type`, `timestamp`, `asset`, `summary`. Optional fields are `source_ip`, `user`, `indicator`; `failed_attempts` is required only for `failed_login` and must be an integer from 1 to 1,000,000. Text values must contain 1–2000 characters. Timestamps need an explicit timezone. Unknown fields and event types are rejected. Use `sample_data/alerts.json` as the template.

```json
[
  {
    "event_id": "MY-DEMO-001",
    "event_type": "failed_login",
    "timestamp": "2026-10-31T10:00:00+00:00",
    "asset": "LAB-PC-01",
    "summary": "Repeated failed login alert",
    "source_ip": "203.0.113.17",
    "failed_attempts": 8
  }
]
```

The exact event ID is the deduplication key. A repeated ID with the same canonical JSON payload is skipped. Reusing an ID with different content rejects the entire batch. Different IDs create separate incidents even if they describe the same activity. Field ordering is ignored in payload comparison; case, whitespace and timestamp strings are otherwise preserved.

## Database design

- `incidents`: unique upstream event ID, payload digest, original alert JSON, title, severity, workflow status, timestamps and closure note.
- `actions`: incident reference, unique action name per incident, execution status and local result receipt.
- `audit`: incident reference, UTC timestamp, event label and detail.

Imports use transactions: a conflict rolls back new rows from the whole batch. Approval and closure lock their write transaction before checking state. SQL values are bound through placeholders. CSV fields that could begin formulas are prefixed with an apostrophe. The payload hash supports duplicate checking, not digital signatures or an immutable evidence chain.

## Files

- `engine.py`: validation, rules, SQLite persistence, workflow, exports and CLI.
- `app.py`: desktop dashboard.
- `demo.py`: temporary-database workflow demo.
- `test_engine.py`: 14 automated tests.
- `sample_data/alerts.json`: five fictional input alerts.
- `docs/Project_Report.docx`: editable five-page submission report.
- `docs/VIVA.md`: 16 viva questions and presentation script.
- `docs/test_results.txt`: actual automated test output.
- `docs/demo_output.txt`: actual demonstration output.
- `docs/sample_incidents.csv`: incident summary from the demo.
- `docs/sample_incident_detail.json`: full example incident with actions and audit entries.

## Validation and limits

The 14 automated engine tests and CLI integration check passed in the build environment on Python 3.12.14. The GUI was compiled and imported, but not visually exercised because the environment has no desktop display. Run it on your own laptop before presentation. No cross-platform execution, detection-accuracy or performance benchmarks are claimed.

This is a single-user educational prototype. It has no login, role-based access, separate approver identity, real connectors, service scheduler, retry queue, retention policy, cryptographic audit protection or multi-tenant isolation. Approval is a local workflow gate; the same operator can import and approve. Audit data and alerts are plaintext SQLite records and can be edited by someone with filesystem access. Rejected operations are shown as errors but are not logged as audit events. There is no rejection, reopening or undo workflow. Closure represents review completion in the demo, not proof of real-world remediation.

The GUI performs bounded local imports synchronously and can pause briefly during larger batches; it is intended for small classroom examples. Source IPs and indicators are stored as descriptive text and never executed or fetched. Imported labels are trusted inputs, not independently verified security findings. Use fictional data for demonstrations.

## Troubleshooting and submission

- `python` not recognized: use the installed interpreter command (`py` on some Windows setups, `python3` on many Unix setups).
- Missing Tkinter: use your Python distributor's Tcl/Tk installation instructions. It is not a normal pip package.
- No display: use a desktop session or `python demo.py` / CLI.
- Database locked: close other app instances and retry.
- Event ID conflict: preserve the original alert or use a distinct ID for a genuinely new event.
- Cannot close: select a ready-for-review or simulated-containment incident and provide a nonempty note.

Fill in student details in the Word report. Add your own dashboard screenshots, actual laptop configuration and demo observations. Read the viva notes so you can explain the state transitions and simulation boundaries.

## References

Official Python documentation for sqlite3, Tkinter and unittest is listed in the report:
https://docs.python.org/3/library/sqlite3.html
https://docs.python.org/3/library/tkinter.html
https://docs.python.org/3/library/unittest.html
