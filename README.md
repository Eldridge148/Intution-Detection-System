# File Integrity Monitoring & Alert System

A lightweight intrusion detection system (IDS) that monitors a local folder of
sensitive files for unauthorized changes. Files are encrypted and hashed to
establish a baseline, a monitor script continuously checks for modifications,
deletions, or unexpected new files, and any anomaly triggers an automated
email alert.

## Architecture

```
secrets/        -> real monitored files (local only, gitignored)
encrypted/      -> AES-encrypted copies of the monitored files (local only)
secret.key      -> Fernet encryption key (local only, gitignored)
baseline.json   -> filename -> SHA-256 hash map used for integrity checks (local only)
logs/           -> activity log of scans and alerts (local only)

encrypt_files.py  -> encrypts files in secrets/, builds baseline.json
monitor_files.py  -> watches secrets/, compares against baseline.json, triggers alerts
alerts.py         -> sends email alerts via Gmail SMTP
```

Note: GitHub Actions cannot see files on a local machine, so this project
runs locally (via a scheduled task or by leaving `monitor_files.py` running).
GitHub hosts the code, version history, and documentation — not the
monitored data itself.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Put real (or simulated) sensitive files in a local `secrets/` folder.

3. Generate the encryption baseline:
   ```bash
   python encrypt_files.py
   ```
   This creates `secret.key`, `encrypted/`, and `baseline.json`.

4. Set up email alerting (Gmail):
   - Enable 2-Step Verification on the sending Gmail account.
   - Generate an App Password (Google Account → Security → App Passwords).
   - Set it as an environment variable:
     ```bash
     export ALERT_SENDER_PASSWORD="your-16-char-app-password"
     ```

5. Run the monitor:
   ```bash
   python monitor_files.py
   ```

## How it works

- **Encryption** — `encrypt_files.py` uses Fernet (AES) to encrypt each file
  and records a SHA-256 hash of the original content as the integrity
  baseline.
- **Monitoring** — `monitor_files.py` re-hashes the folder on an interval and
  compares against the baseline, flagging:
  - **Modified** files (hash mismatch) — HIGH severity
  - **Deleted** files — HIGH severity
  - **Unexpected new** files — MEDIUM severity
- **Alerting** — any flagged event is logged to `logs/activity.log` and
  triggers an email alert via `alerts.py` with the event type, filename,
  severity, and timestamp.

## Known fix applied

Deleted files are removed from `baseline.json` immediately after the first
alert fires, so the monitor doesn't keep re-alerting on the same missing
file every scan cycle.

## Security notes

- `secret.key`, `baseline.json`, `secrets/`, `encrypted/`, and `logs/` are
  all gitignored — none of the actual data or key material should ever be
  committed.
- The email sender's app password is read from an environment variable,
  never hardcoded.
