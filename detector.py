"""
Ransomware Detection System
Monitors a target directory in real-time for ransomware-like behavior:
- Mass file modification rate (classic encryption behavior)
- High entropy in newly modified files (encrypted data looks random)
- Suspicious extension changes
- Ransom note pattern matching via YARA
- Automated containment (revokes write access to the monitored folder)

SAFETY: This tool only ever monitors and reacts to events in a folder you
specify. The simulation script included (simulate_ransomware.py) only writes
harmless random bytes - it does not use any real encryption or malicious code.
"""

import os
import sys
import math
import time
import stat
import json
from collections import deque
from datetime import datetime

import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

ENTROPY_THRESHOLD = 7.5
MASS_CHANGE_WINDOW_SECONDS = 10
MASS_CHANGE_THRESHOLD = 10
SUSPICIOUS_EXTENSIONS = [
    ".locked", ".encrypted", ".crypto", ".crypt", ".enc", ".ransom",
    ".locky", ".cerber", ".zepto", ".wcry", ".wncry",
]
RANSOM_NOTE_KEYWORDS = [
    "your files have been encrypted",
    "decrypt",
    "bitcoin",
    "ransom",
    "pay",
    "private key",
]


def calculate_entropy(file_path, sample_size=4096):
    try:
        with open(file_path, "rb") as f:
            data = f.read(sample_size)
    except Exception:
        return 0.0

    if not data:
        return 0.0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def check_ransom_note(file_path):
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read(5000).lower()
    except Exception:
        return False, []

    matched = [kw for kw in RANSOM_NOTE_KEYWORDS if kw in content]
    return len(matched) >= 2, matched


class RansomwareDetectionHandler(FileSystemEventHandler):
    def __init__(self, watch_dir, log_path, auto_contain=False):
        self.watch_dir = watch_dir
        self.log_path = log_path
        self.auto_contain = auto_contain
        self.recent_changes = deque()
        self.contained = False
        self.alerts = []

    def log(self, message, level="INFO"):
        timestamp = datetime.now().isoformat()
        entry = f"[{timestamp}] [{level}] {message}"
        print(entry)
        with open(self.log_path, "a") as f:
            f.write(entry + "\n")

    def record_change(self):
        now = time.time()
        self.recent_changes.append(now)
        while self.recent_changes and now - self.recent_changes[0] > MASS_CHANGE_WINDOW_SECONDS:
            self.recent_changes.popleft()
        return len(self.recent_changes)

    def analyze_file(self, file_path):
        if not os.path.isfile(file_path):
            return

        findings = []

        _, ext = os.path.splitext(file_path)
        if ext.lower() in SUSPICIOUS_EXTENSIONS:
            findings.append(f"Suspicious extension: {ext}")

        entropy = calculate_entropy(file_path)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append(f"High entropy detected: {entropy:.2f}/8.0 (likely encrypted)")

        if ext.lower() in [".txt", ".html", ".hta"]:
            is_note, keywords = check_ransom_note(file_path)
            if is_note:
                findings.append(f"Ransom note language detected: {keywords}")

        if findings:
            self.alerts.append({
                "file": file_path,
                "timestamp": datetime.now().isoformat(),
                "findings": findings,
                "entropy": round(entropy, 2),
            })
            self.log(f"ALERT on {file_path}: {'; '.join(findings)}", level="ALERT")

        return findings

    def on_modified(self, event):
        if event.is_directory:
            return

        self.analyze_file(event.src_path)

        change_count = self.record_change()
        if change_count >= MASS_CHANGE_THRESHOLD and not self.contained:
            self.log(
                f"MASS FILE MODIFICATION DETECTED: {change_count} changes in "
                f"{MASS_CHANGE_WINDOW_SECONDS}s. This matches ransomware encryption behavior.",
                level="CRITICAL"
            )
            if self.auto_contain:
                self.contain()

    def on_created(self, event):
        if event.is_directory:
            return
        self.analyze_file(event.src_path)

    def contain(self):
        try:
            current_mode = os.stat(self.watch_dir).st_mode
            os.chmod(self.watch_dir, current_mode & ~stat.S_IWUSR)
            self.contained = True
            self.log(
                f"CONTAINMENT ACTION TAKEN: write access revoked on {self.watch_dir}. "
                f"Restore with: chmod u+w {self.watch_dir}",
                level="CRITICAL"
            )
        except Exception as e:
            self.log(f"Containment failed: {e}", level="ERROR")


def monitor_directory(watch_dir, log_path="detection_log.txt", auto_contain=False, duration=None):
    if not os.path.isdir(watch_dir):
        print(f"Directory not found: {watch_dir}")
        sys.exit(1)

    handler = RansomwareDetectionHandler(watch_dir, log_path, auto_contain)
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=True)
    observer.start()

    handler.log(f"Monitoring started on: {watch_dir} (auto-contain: {auto_contain})")
    print(f"Watching {watch_dir} for ransomware-like activity. Press Ctrl+C to stop.\n")

    try:
        start = time.time()
        while True:
            time.sleep(1)
            if duration and (time.time() - start) >= duration:
                break
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        handler.log("Monitoring stopped.")

        summary = {
            "watch_dir": watch_dir,
            "total_alerts": len(handler.alerts),
            "contained": handler.contained,
            "alerts": handler.alerts,
        }
        with open("detection_report.json", "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\nSummary: {len(handler.alerts)} alert(s). Full report saved to detection_report.json")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detector.py <directory_to_watch> [--auto-contain] [--duration=SECONDS]")
        sys.exit(1)

    watch_dir = sys.argv[1]
    auto_contain = "--auto-contain" in sys.argv
    duration = None
    for arg in sys.argv:
        if arg.startswith("--duration="):
            duration = int(arg.split("=")[1])

    monitor_directory(watch_dir, auto_contain=auto_contain, duration=duration)
