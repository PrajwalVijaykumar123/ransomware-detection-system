"""
Ransomware Behavior Simulator (SAFE)

This does NOT contain any real encryption, malicious code, or actual ransomware.
It only mimics the observable behavior of ransomware for testing the detector:
1. Creates a batch of test files
2. Rapidly "encrypts" them by overwriting with random bytes (high entropy, like real
   encrypted output) and renaming with a suspicious extension
3. Drops a fake ransom note (plain text, for detection testing only)

Use this only in a dedicated test folder - never point it at real files.
"""

import os
import sys
import time
import random

RANSOM_NOTE_TEXT = """
YOUR FILES HAVE BEEN ENCRYPTED!

All your important files have been encrypted with strong encryption.
To decrypt your files, you must pay 0.5 BITCOIN to the address below.

Wallet: [TEST-SIMULATION-NOT-REAL]

You have 48 hours. After that, your private key will be deleted
and your files will be lost forever.

This is a SIMULATED ransom note for security testing purposes only.
"""


def create_test_files(target_dir, count=15):
    os.makedirs(target_dir, exist_ok=True)
    for i in range(count):
        file_path = os.path.join(target_dir, f"document_{i}.txt")
        with open(file_path, "w") as f:
            f.write(f"This is test document number {i}. Totally harmless content.\n" * 10)
    print(f"Created {count} test files in {target_dir}")


def simulate_encryption(target_dir, delay=0.3):
    files = [f for f in os.listdir(target_dir) if os.path.isfile(os.path.join(target_dir, f))]

    print(f"Simulating rapid 'encryption' of {len(files)} files...")
    for filename in files:
        file_path = os.path.join(target_dir, filename)

        random_data = bytes(random.getrandbits(8) for _ in range(2048))
        with open(file_path, "wb") as f:
            f.write(random_data)

        new_path = file_path + ".locked"
        os.rename(file_path, new_path)

        print(f"  'Encrypted': {filename} -> {os.path.basename(new_path)}")
        time.sleep(delay)

    note_path = os.path.join(target_dir, "README_DECRYPT.txt")
    with open(note_path, "w") as f:
        f.write(RANSOM_NOTE_TEXT)
    print(f"  Dropped simulated ransom note: {note_path}")


if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "test_target"

    print("=" * 60)
    print("RANSOMWARE BEHAVIOR SIMULATOR (SAFE - no real malicious code)")
    print("=" * 60)

    create_test_files(target_dir)
    time.sleep(2)
    simulate_encryption(target_dir)

    print("\nSimulation complete. Check your detector's output/logs.")
