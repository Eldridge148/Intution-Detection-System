import os
import hashlib
import json
import time
from datetime import datetime

from alerts import send_email_alert

SOURCE_DIR = "secrets"
BASELINE_FILE = "baseline.json"
LOG_FILE = "logs/activity.log"
CHECK_INTERVAL = 15  # seconds between checks


def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def load_baseline():
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def save_baseline(baseline):
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)


def log_event(message):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    timestamp = datetime.now().isoformat()
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def trigger_alert(event_type, filename, severity):
    log_event(f"ALERT [{severity}] {event_type}: {filename}")
    send_email_alert(event_type, filename, severity)


def scan_folder(baseline):
    current_files = set(os.listdir(SOURCE_DIR))
    known_files = set(baseline.keys())

    # Check for modified or deleted files
    for filename in known_files:
        filepath = os.path.join(SOURCE_DIR, filename)

        if not os.path.exists(filepath):
            trigger_alert("FILE DELETED", filename, "HIGH")
            del baseline[filename]
            continue

        current_hash = hash_file(filepath)
        if current_hash != baseline[filename]["hash"]:
            trigger_alert("FILE MODIFIED", filename, "HIGH")
            baseline[filename]["hash"] = current_hash  # update baseline after alert

    # Check for new, unexpected files
    new_files = current_files - known_files
    for filename in new_files:
        trigger_alert("UNEXPECTED NEW FILE", filename, "MEDIUM")
        filepath = os.path.join(SOURCE_DIR, filename)
        baseline[filename] = {"hash": hash_file(filepath), "encrypted_path": None}

    save_baseline(baseline)


def main():
    log_event("Monitor started.")
    baseline = load_baseline()

    try:
        while True:
            scan_folder(baseline)
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        log_event("Monitor stopped.")


if __name__ == "__main__":
    main()
