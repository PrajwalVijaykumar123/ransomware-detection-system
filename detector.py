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
import fnmatch
from collections import deque
from datetime import datetime

import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------- Config ----------
ENTROPY_THRESHOLD = 7.5          # out of 8.0 max; encrypted/compressed data is typically 7.5+
MASS_CHANGE_WINDOW_SECONDS = 10  # time window to measure change rate
MASS_CHANGE_THRESHOLD = 10       # number of file changes within window to trigger alert
SUSPICIOUS_EXTENSIONS = [
    ".locked", ".encrypted", ".crypto", ".crypt", ".enc", ".ransom",
    ".locky", ".cerber", ".zepto", ".wcry", ".wncry",
]
YARA_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "ransom_notes.yar")
WHITELIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitelist.json")


def load_yara_rules(rules_path=YARA_RULES_PATH):
    """Compiles the YARA ransom-note ruleset once at startup. Falls back to
    None (and a warning) if the rules file is missing or fails to compile,
    so the detector still runs on entropy + extension signals alone."""
    try:
        return yara.compile(filepath=rules_path)
    except Exception as e:
        print(f"[WARN] Could not load YARA rules from {rules_path}: {e}")
        print("[WARN] Continuing without ransom-note language detection.")
        return None


def load_whitelist(whitelist_path=WHITELIST_PATH):
    """Loads path/extension/filename patterns to exclude from detection so
    legitimate bulk operations (backups, syncs, builds) don't trip the
    mass-modification or entropy alerts as false positives."""
    default = {
        "whitelisted_paths": [],
        "whitelisted_extensions": [],
        "whitelisted_filename_patterns": [],
    }
    try:
        with open(whitelist_path, "r") as f:
            data = json.load(f)
        default.update({k: v for k, v in data.items() if k in default})
        return default
    except FileNotFoundError:
        return default
    except Exception as e:
        print(f"[WARN] Could not load whitelist from {whitelist_path}: {e}")
        return default


def is_whitelisted(file_path, whitelist):
    """Returns True if a file should be excluded from detection entirely -
    it matches a whitelisted directory, extension, or filename pattern."""
    normalized = file_path.replace("\\", "/")

    for path_fragment in whitelist["whitelisted_paths"]:
        if path_fragment.strip("/") in normalized.split("/"):
            return True

    _, ext = os.path.splitext(file_path)
    if ext.lower() in [e.lower() for e in whitelist["whitelisted_extensions"]]:
        return True

    filename = os.path.basename(file_path)
    for pattern in whitelist["whitelisted_filename_patterns"]:
        if pattern.startswith("~") or pattern.startswith("."):
            if pattern in filename or fnmatch.fnmatch(filename, f"*{pattern}*"):
                return True
        elif fnmatch.fnmatch(filename, pattern):
            return True

    return False


def calculate_entropy(file_path, sample_size=4096):
    """Shannon entropy of a file's first N bytes. High entropy (~7.5-8.0) suggests
    encrypted or compressed data - a strong ransomware indicator."""
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


def check_ransom_note(file_path, yara_rules):
    """Matches a text file's content and filename against the compiled YARA
    ransom-note ruleset. Returns (is_note, list of matched rule names) so
    the detector catches ransom-note *phrasing* generically - including
    from families it has never seen a keyword list for - rather than only
    exact substrings."""
    if yara_rules is None:
        return False, []

    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read(5000)
    except Exception:
        return False, []

    try:
        matches = yara_rules.match(data=content)
        # Filename-pattern rule needs the actual filename, not file content
        filename_matches = yara_rules.match(data=os.path.basename(file_path))
        all_matches = {m.rule for m in matches} | {
            m.rule for m in filename_matches if m.rule == "Ransom_Note_Filename_Pattern"
        }
    except Exception:
        return False, []

    return len(all_matches) > 0, sorted(all_matches)


class RansomwareDetectionHandler(FileSystemEventHandler):
    def __init__(self, watch_dir, log_path, auto_contain=False, yara_rules=None, whitelist=None):
        self.watch_dir = watch_dir
        self.log_path = log_path
        self.auto_contain = auto_contain
        self.recent_changes = deque()
        self.contained = False
        self.alerts = []
        self.yara_rules = yara_rules
        self.whitelist = whitelist or load_whitelist()
        self.whitelisted_skips = 0

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

        if is_whitelisted(file_path, self.whitelist):
            self.whitelisted_skips += 1
            return

        findings = []

        _, ext = os.path.splitext(file_path)
        if ext.lower() in SUSPICIOUS_EXTENSIONS:
            findings.append(f"Suspicious extension: {ext}")

        entropy = calculate_entropy(file_path)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append(f"High entropy detected: {entropy:.2f}/8.0 (likely encrypted)")

        if ext.lower() in [".txt", ".html", ".hta"]:
            is_note, matched_rules = check_ransom_note(file_path, self.yara_rules)
            if is_note:
                findings.append(f"Ransom note language detected (YARA: {matched_rules})")

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

        if is_whitelisted(event.src_path, self.whitelist):
            self.whitelisted_skips += 1
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
        """Removes write permission from the monitored directory to stop
        further file modification. This is a real, reversible containment
        action - restore with: chmod u+w <directory>"""
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

    yara_rules = load_yara_rules()
    whitelist = load_whitelist()

    handler = RansomwareDetectionHandler(watch_dir, log_path, auto_contain, yara_rules, whitelist)
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=True)
    observer.start()

    handler.log(
        f"Monitoring started on: {watch_dir} (auto-contain: {auto_contain}, "
        f"yara_rules: {'loaded' if yara_rules else 'unavailable'}, "
        f"whitelist_paths: {len(whitelist['whitelisted_paths'])}, "
        f"whitelist_extensions: {len(whitelist['whitelisted_extensions'])})"
    )
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
            "whitelisted_events_skipped": handler.whitelisted_skips,
            "alerts": handler.alerts,
        }
        with open("detection_report.json", "w") as f:
            json.dump(summary, f, indent=2)
        print(
            f"\nSummary: {len(handler.alerts)} alert(s), "
            f"{handler.whitelisted_skips} whitelisted event(s) skipped. "
            f"Full report saved to detection_report.json"
        )


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
