# Ransomware Detection System

A real-time ransomware detection and automated containment tool. Monitors a directory for the behavioral signatures of ransomware - mass file modification, high entropy (encrypted-looking) content, suspicious extensions, and ransom note language - and automatically revokes write access to contain the threat.

## What This Project Does

- Real-time file system monitoring using the watchdog library
- Mass modification detection - flags when file changes exceed a threshold within a short time window, the classic signature of ransomware encrypting a directory
- Shannon entropy analysis - calculates the randomness of file content; encrypted data scores 7.5+/8.0, far higher than normal text or documents
- Suspicious extension detection - flags common ransomware extensions (.locked, .encrypted, .crypto, etc.)
- Ransom note language detection - scans text files for common ransom note phrasing
- Automated containment - when mass modification is detected, automatically revokes write access to the monitored directory, actively stopping the attack in progress, not just alerting after the fact
- Full logging and JSON summary report of every detection run

## Live Test Results

Running the included safe simulator against the detector produced a real, measurable containment outcome:

- Detector flagged mass modification after 10 file changes in 10 seconds
- Automated containment (write access revocation) triggered immediately
- This stopped the simulated attack mid-execution - only 10 of 15 target files were affected before containment locked the directory, directly limiting the blast radius

    [CRITICAL] MASS FILE MODIFICATION DETECTED: 10 changes in 10s.
    [CRITICAL] CONTAINMENT ACTION TAKEN: write access revoked on test_target.
    [ALERT] High entropy detected: 7.91/8.0 (likely encrypted)

## Safety

The included simulate_ransomware.py does NOT contain any real encryption, malicious code, or actual ransomware. It only mimics the observable behavior of ransomware (overwriting files with random bytes, renaming with suspicious extensions, dropping a plaintext fake ransom note) for safely testing the detector. All testing was done in an isolated local test directory.

## Tech Stack

- Python 3.11
- watchdog - real-time file system event monitoring
- Shannon entropy calculation (pure Python/math)

## Setup

1. Install dependencies:

    python3 -m venv venv
    source venv/bin/activate
    pip install watchdog yara-python

2. Start monitoring a directory:

    python3 detector.py /path/to/watch --auto-contain

3. (For testing only) Run the safe simulator in a separate terminal, pointed at a dedicated test folder:

    python3 simulate_ransomware.py test_target

4. To restore write access after a containment action:

    chmod u+w /path/to/watch

## Architecture

File System Events (watchdog) -> Per-file analysis (entropy, extension, ransom note scan) -> Change-rate tracking (sliding time window) -> Mass modification threshold exceeded? -> Automated containment (revoke write access) + logging + JSON report

## What I Learned

- Real-time file system monitoring using OS-level event hooks (watchdog/inotify-style APIs)
- Shannon entropy as a practical, format-agnostic signal for detecting encrypted content - works even against unknown/novel ransomware, unlike signature-based detection alone
- Designing automated response, not just detection - and the real tradeoffs involved, since containment actions have real consequences and must be reversible
- Safely simulating malicious behavior for testing without using any actual malicious code

## Next Steps

- Add YARA-based ransom note matching (currently keyword-based) for more precise detection
- Extend containment options: process termination, network isolation, automated backups before lockdown
- Add a whitelist system to reduce false positives from legitimate bulk operations (e.g. backup software)
- Build a dashboard view consistent with the other projects in this portfolio
