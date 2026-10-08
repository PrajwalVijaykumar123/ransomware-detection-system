"""
Dashboard generator: turns a detection_report.json (produced by detector.py)
into a single self-contained HTML report - a timeline of alerts, a severity
breakdown, and the containment outcome - so a detection run can be reviewed
visually instead of by reading raw JSON/log lines.

Usage:
    python3 dashboard.py [detection_report.json] [-o dashboard.html]
"""

import sys
import json
import html
import argparse
from datetime import datetime
from collections import Counter


def severity_of(finding_text):
    text = finding_text.lower()
    if "ransom note" in text or "mass file modification" in text:
        return "critical"
    if "high entropy" in text:
        return "high"
    if "suspicious extension" in text:
        return "medium"
    return "low"


SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#6b7280",
}


def build_dashboard(report, log_lines=None):
    alerts = report.get("alerts", [])
    watch_dir = report.get("watch_dir", "(unknown)")
    contained = report.get("contained", False)
    whitelisted_skips = report.get("whitelisted_events_skipped", 0)

    # Flatten findings with severity + timestamp for the timeline/table
    rows = []
    severity_counts = Counter()
    for alert in alerts:
        ts = alert.get("timestamp", "")
        file_path = alert.get("file", "")
        entropy = alert.get("entropy", 0)
        for finding in alert.get("findings", []):
            sev = severity_of(finding)
            severity_counts[sev] += 1
            rows.append((ts, file_path, finding, entropy, sev))

    rows.sort(key=lambda r: r[0])

    total_findings = sum(severity_counts.values())
    first_ts = rows[0][0] if rows else None
    last_ts = rows[-1][0] if rows else None

    def fmt_ts(ts):
        if not ts:
            return "-"
        try:
            return datetime.fromisoformat(ts).strftime("%H:%M:%S.%f")[:-3]
        except Exception:
            return ts

    duration_str = "-"
    if first_ts and last_ts:
        try:
            delta = (datetime.fromisoformat(last_ts) - datetime.fromisoformat(first_ts)).total_seconds()
            duration_str = f"{delta:.1f}s"
        except Exception:
            pass

    status_label = "CONTAINED" if contained else ("CLEAN" if total_findings == 0 else "ALERTS ONLY")
    status_color = "#dc2626" if contained else ("#16a34a" if total_findings == 0 else "#ca8a04")

    table_rows = "\n".join(
        f"""<tr>
            <td class="mono">{fmt_ts(ts)}</td>
            <td class="mono">{html.escape(file_path)}</td>
            <td><span class="badge" style="background:{SEVERITY_COLOR[sev]}">{sev.upper()}</span></td>
            <td>{html.escape(finding)}</td>
            <td class="mono">{entropy if entropy else '-'}</td>
        </tr>"""
        for ts, file_path, finding, entropy, sev in rows
    )

    severity_bars = "\n".join(
        f"""<div class="bar-row">
            <span class="bar-label">{sev.upper()}</span>
            <div class="bar-track"><div class="bar-fill" style="width:{(count/total_findings*100) if total_findings else 0:.0f}%;background:{SEVERITY_COLOR[sev]}"></div></div>
            <span class="bar-count">{count}</span>
        </div>"""
        for sev, count in sorted(severity_counts.items(), key=lambda kv: ["critical", "high", "medium", "low"].index(kv[0]))
    )

    log_html = ""
    if log_lines:
        escaped = "\n".join(html.escape(line) for line in log_lines)
        log_html = f"""
        <div class="card">
            <h2>Raw Log</h2>
            <pre class="log">{escaped}</pre>
        </div>"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ransomware Detection Report — {html.escape(watch_dir)}</title>
<style>
    :root {{ color-scheme: light dark; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        max-width: 960px; margin: 0 auto; padding: 24px 16px 64px;
        background: #0b0d12; color: #e5e7eb;
    }}
    h1 {{ font-size: 1.4rem; margin-bottom: 4px; }}
    .subtitle {{ color: #9ca3af; margin-top: 0; font-size: 0.9rem; }}
    .status-banner {{
        display: inline-block; padding: 6px 14px; border-radius: 6px;
        font-weight: 700; letter-spacing: 0.04em; color: white;
        background: {status_color}; margin: 12px 0 20px;
    }}
    .stats {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
    .stat {{
        background: #151823; border: 1px solid #262b3a; border-radius: 10px;
        padding: 14px 18px; min-width: 130px; flex: 1;
    }}
    .stat .value {{ font-size: 1.6rem; font-weight: 700; }}
    .stat .label {{ font-size: 0.75rem; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.04em; }}
    .card {{
        background: #151823; border: 1px solid #262b3a; border-radius: 10px;
        padding: 18px 20px; margin-bottom: 20px;
    }}
    .card h2 {{ font-size: 1rem; margin: 0 0 14px; color: #d1d5db; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    th {{ text-align: left; color: #9ca3af; font-weight: 600; font-size: 0.75rem;
          text-transform: uppercase; padding: 6px 10px; border-bottom: 1px solid #262b3a; }}
    td {{ padding: 8px 10px; border-bottom: 1px solid #1c2030; vertical-align: top; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8rem; color: #93c5fd; }}
    .badge {{
        display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 0.7rem; font-weight: 700; color: white; letter-spacing: 0.03em;
    }}
    .bar-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
    .bar-label {{ width: 80px; font-size: 0.75rem; color: #9ca3af; }}
    .bar-track {{ flex: 1; height: 10px; background: #1c2030; border-radius: 5px; overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: 5px; }}
    .bar-count {{ width: 30px; text-align: right; font-size: 0.8rem; color: #d1d5db; }}
    .log {{
        background: #0b0d12; border-radius: 6px; padding: 12px; font-size: 0.75rem;
        color: #9ca3af; overflow-x: auto; max-height: 300px; overflow-y: auto;
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }}
    .empty {{ color: #6b7280; font-style: italic; padding: 20px 0; text-align: center; }}
</style>
</head>
<body>
    <h1>Ransomware Detection Report</h1>
    <p class="subtitle">Monitored directory: <span class="mono">{html.escape(watch_dir)}</span></p>
    <div class="status-banner">{status_label}</div>

    <div class="stats">
        <div class="stat"><div class="value">{len(alerts)}</div><div class="label">Alerted Files</div></div>
        <div class="stat"><div class="value">{total_findings}</div><div class="label">Total Findings</div></div>
        <div class="stat"><div class="value">{whitelisted_skips}</div><div class="label">Whitelisted Skips</div></div>
        <div class="stat"><div class="value">{duration_str}</div><div class="label">Detection Window</div></div>
    </div>

    <div class="card">
        <h2>Findings by Severity</h2>
        {severity_bars if total_findings else '<p class="empty">No findings recorded.</p>'}
    </div>

    <div class="card">
        <h2>Alert Timeline</h2>
        {"<table><thead><tr><th>Time</th><th>File</th><th>Severity</th><th>Finding</th><th>Entropy</th></tr></thead><tbody>" + table_rows + "</tbody></table>" if rows else '<p class="empty">No alerts in this run.</p>'}
    </div>
    {log_html}
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Generate an HTML dashboard from a detection_report.json")
    parser.add_argument("report", nargs="?", default="detection_report.json")
    parser.add_argument("-o", "--output", default="dashboard.html")
    parser.add_argument("--log", default="detection_log.txt", help="Optional raw log file to embed")
    args = parser.parse_args()

    try:
        with open(args.report, "r") as f:
            report = json.load(f)
    except FileNotFoundError:
        print(f"Report not found: {args.report}")
        print("Run detector.py first to generate a detection_report.json")
        sys.exit(1)

    log_lines = None
    try:
        with open(args.log, "r") as f:
            log_lines = f.read().splitlines()
    except FileNotFoundError:
        pass

    html_out = build_dashboard(report, log_lines)
    with open(args.output, "w") as f:
        f.write(html_out)

    print(f"Dashboard written to {args.output}")


if __name__ == "__main__":
    main()
