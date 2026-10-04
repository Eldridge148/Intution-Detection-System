import os
import hashlib
import json
from cryptography.fernet import Fernet

# Config
SOURCE_DIR = "secrets"          # folder with original files
ENCRYPTED_DIR = "encrypted"     # where encrypted copies go
KEY_FILE = "secret.key"
BASELINE_FILE = "baseline.json"


def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key


def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def encrypt_file(fernet, filepath, out_path):
    with open(filepath, "rb") as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    with open(out_path, "wb") as f:
        f.write(encrypted)


def main():
    os.makedirs(SOURCE_DIR, exist_ok=True)
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)
    key = load_or_create_key()
    fernet = Fernet(key)

    baseline = {}

    for filename in os.listdir(SOURCE_DIR):
        src_path = os.path.join(SOURCE_DIR, filename)
        if not os.path.isfile(src_path):
            continue

        # Hash the ORIGINAL file (before encryption) as the integrity baseline
        file_hash = hash_file(src_path)

        # Encrypt and save
        out_path = os.path.join(ENCRYPTED_DIR, filename + ".enc")
        encrypt_file(fernet, src_path, out_path)

        baseline[filename] = {
            "hash": file_hash,
            "encrypted_path": out_path
        }

        print(f"Encrypted {filename} -> {out_path}")

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"\nBaseline hashes saved to {BASELINE_FILE}")
    print(f"Key saved to {KEY_FILE} — keep this safe, it's needed to decrypt.")


if __name__ == "__main__":
    main()
