# Ransomware Detection System

A real-time ransomware detection and automated containment tool. Monitors a directory for the behavioral signatures of ransomware — mass file modification, high entropy (encrypted-looking) content, suspicious extensions, and ransom note language — and automatically revokes write access to contain the threat.

## What This Project Does

- **Real-time file system monitoring** using the `watchdog` library
- **Mass modification detection** — flags when file changes exceed a threshold within a short time window, the classic signature of ransomware encrypting a directory
- **Shannon entropy analysis** — calculates the randomness of file content; encrypted data scores 7.5+/8.0, far higher than normal text or documents
- **Suspicious extension detection** — flags common ransomware extensions (`.locked`, `.encrypted`, `.crypto`, etc.)
- **YARA-based ransom note detection** — matches dropped notes against a real compiled YARA ruleset (`rules/ransom_notes.yar`) for payment-demand/threat language, known note filenames, and embedded crypto-wallet patterns, rather than a flat keyword list — so it also catches note styles it hasn't seen a specific keyword for
- **Whitelist system** — `whitelist.json` excludes known-noisy paths (`.git/`, `node_modules/`, build/venv dirs), archive extensions, and temp-file patterns (`.bak`, `.swp`, `~$...`) from detection, so legitimate bulk operations (backups, syncs, builds) don't trigger false positives
- **Automated containment** — when mass modification is detected, automatically revokes write access to the monitored directory, actively stopping the attack in progress (not just alerting after the fact)
- Full logging and JSON summary report of every detection run (now including whitelisted-event counts)
- **HTML dashboard** (`dashboard.py`) — turns a `detection_report.json` into a single self-contained report: containment status, severity breakdown, and a timeline of every alert, viewable in any browser with no server needed

## Live Test Results

Running the included safe simulator against the detector produced a real, measurable containment outcome:

- Detector flagged mass modification after **10 file changes in 10 seconds**
- Automated containment (write access revocation) triggered immediately
- This **stopped the simulated attack mid-execution** — only 10 of 15 target files were affected before containment locked the directory, directly limiting the blast radius

```
[CRITICAL] MASS FILE MODIFICATION DETECTED: 10 changes in 10s.
[CRITICAL] CONTAINMENT ACTION TAKEN: write access revoked on test_target.
[ALERT] High entropy detected: 7.91/8.0 (likely encrypted)
[ALERT] Ransom note language detected (YARA: ['Generic_Ransom_Note_Language', 'Ransom_Note_Filename_Pattern'])
```

## Safety

The included `simulate_ransomware.py` does **not** contain any real encryption, malicious code, or actual ransomware. It only mimics the *observable behavior* of ransomware (overwriting files with random bytes, renaming with suspicious extensions, dropping a plaintext fake ransom note) for safely testing the detector. All testing was done in an isolated local test directory.

## Tech Stack

- Python 3.11
- watchdog — real-time file system event monitoring
- yara-python — compiled YARA rule matching for ransom note language
- Shannon entropy calculation (pure Python/math)

## Setup

1. Install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. Start monitoring a directory:
   ```bash
   python3 detector.py /path/to/watch --auto-contain
   ```
   On startup it loads `rules/ransom_notes.yar` (YARA ruleset) and `whitelist.json`
   (noise-reduction config) automatically from the project directory.

3. (For testing only) Run the safe simulator in a separate terminal, pointed at a dedicated test folder:
   ```bash
   python3 simulate_ransomware.py test_target
   ```

4. To restore write access after a containment action:
   ```bash
   chmod u+w /path/to/watch
   ```

5. Generate a visual report from the run:
   ```bash
   python3 dashboard.py detection_report.json -o dashboard.html
   open dashboard.html   # or just double-click it
   ```

### Tuning the whitelist

Edit `whitelist.json` to exclude paths, extensions, or filename patterns specific
to your environment — e.g. add your backup tool's output directory if it does
large batch writes that would otherwise look like mass encryption.

## Architecture

```
File System Events (watchdog)
        |
        v
Whitelist check (path / extension / filename pattern) -> skip if matched
        |
        v
Per-file analysis: entropy check, extension check, YARA ransom-note scan
        |
        v
Change-rate tracking (sliding time window)
        |
        v
Mass modification threshold exceeded?
        |
        v
Automated containment (revoke write access) + logging + JSON report
```

## Project Structure

```
ransomware-detection-system/
├── detector.py              # Main monitoring + detection + containment logic
├── simulate_ransomware.py   # Safe behavioral simulator for testing
├── dashboard.py             # Generates an HTML report from detection_report.json
├── rules/
│   └── ransom_notes.yar     # YARA rules: ransom-note language, filenames, wallet patterns
├── whitelist.json           # Paths/extensions/patterns excluded from detection
├── requirements.txt
└── README.md
```

## What I Learned

- Real-time file system monitoring using OS-level event hooks (watchdog/inotify-style APIs)
- Shannon entropy as a practical, format-agnostic signal for detecting encrypted content — works even against unknown/novel ransomware, unlike signature-based detection alone
- Writing and compiling YARA rules for behavioral/language signatures (not just malware sample hashes) — matching the *shape* of ransom note language and dropped-note filenames so unseen note variants still get flagged
- Designing automated response (not just detection) — and the real tradeoffs involved, since containment actions have real consequences and must be reversible
- Building a whitelist/allowlist layer to deliberately trade a little detection sensitivity for far fewer false positives on legitimate bulk file operations
- Safely simulating malicious behavior for testing without using any actual malicious code

## Next Steps

- Extend containment options: process termination, network isolation, automated backups before lockdown
- Detect trusted *processes* (not just paths/extensions) making bulk changes, to whitelist e.g. a known backup agent regardless of which files it touches
- Auto-open or auto-regenerate the dashboard at the end of each monitoring run instead of running it as a separate step
