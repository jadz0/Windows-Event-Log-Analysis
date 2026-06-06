import csv
import argparse
from collections import defaultdict, Counter
from pathlib import Path

SUSPICIOUS_TERMS = [
    'powershell.exe -enc',
    'powershell.exe -encodedcommand',
    'cmd.exe /c whoami',
    'rundll32.exe',
    'regsvr32.exe',
    'mshta.exe',
]

SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def load_events(path):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))


def detect_failed_logons(events):
    grouped = defaultdict(int)
    for e in events:
        if e.get('EventID') == '4625':
            key = (e.get('TargetUserName', 'unknown'), e.get('IpAddress', 'unknown'))
            grouped[key] += 1
    findings = []
    for (user, ip), count in sorted(grouped.items(), key=lambda x: x[1], reverse=True):
        if count >= 3:
            findings.append({
                'type': 'Repeated Failed Logons',
                'user': user,
                'source_ip': ip,
                'count': count,
                'severity': 'high' if count >= 5 else 'medium'
            })
    return findings


def detect_success_after_failures(events):
    fail_counts = defaultdict(int)
    successes = []
    for e in events:
        event_id = e.get('EventID')
        user = e.get('TargetUserName', 'unknown')
        ip = e.get('IpAddress', 'unknown')
        key = (user, ip)
        if event_id == '4625':
            fail_counts[key] += 1
        elif event_id == '4624' and fail_counts.get(key, 0) >= 3:
            successes.append({
                'type': 'Successful Logon After Failures',
                'user': user,
                'source_ip': ip,
                'prior_failures': fail_counts[key],
                'severity': 'high'
            })
    return successes


def detect_suspicious_processes(events):
    findings = []
    for e in events:
        if e.get('EventID') != '4688':
            continue
        command = (e.get('CommandLine') or '').lower()
        process = (e.get('NewProcessName') or '').lower()
        parent = (e.get('ParentProcessName') or '').lower()
        combined = f"{process} {command} {parent}"
        matches = [term for term in SUSPICIOUS_TERMS if term in combined]
        if matches:
            findings.append({
                'type': 'Suspicious Process Creation',
                'process': e.get('NewProcessName', 'unknown'),
                'parent_process': e.get('ParentProcessName', 'unknown'),
                'user': e.get('TargetUserName', 'unknown'),
                'indicator': matches[0],
                'severity': 'high'
            })
    return findings


def format_findings(findings):
    if not findings:
        return '========================================\n Windows Event Log Analysis Results\n========================================\n\nNo suspicious findings detected.'

    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f['severity'], 99), f['type']))
    counts = Counter(f['severity'] for f in findings)

    lines = [
        '========================================',
        ' Windows Event Log Analysis Results',
        '========================================',
        ''
    ]

    for finding in findings:
        lines.append(f"[{finding['severity'].upper()}] {finding['type']}")
        if finding['type'] == 'Repeated Failed Logons':
            lines.append(f"  User: {finding['user']}")
            lines.append(f"  Source IP: {finding['source_ip']}")
            lines.append(f"  Count: {finding['count']}")
        elif finding['type'] == 'Successful Logon After Failures':
            lines.append(f"  User: {finding['user']}")
            lines.append(f"  Source IP: {finding['source_ip']}")
            lines.append(f"  Prior Failures: {finding['prior_failures']}")
        elif finding['type'] == 'Suspicious Process Creation':
            lines.append(f"  User: {finding['user']}")
            lines.append(f"  Process: {finding['process']}")
            lines.append(f"  Parent: {finding['parent_process']}")
            lines.append(f"  Indicator: {finding['indicator']}")
        lines.append('')

    lines.append('Summary:')
    lines.append(f"- High: {counts.get('high', 0)}")
    lines.append(f"- Medium: {counts.get('medium', 0)}")
    lines.append(f"- Low: {counts.get('low', 0)}")
    lines.append(f"- Total Findings: {len(findings)}")
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Windows Event Log Analysis / Triage Tool')
    parser.add_argument('csv_file', help='Path to Windows event CSV file')
    parser.add_argument('--save', help='Path to save findings', default=None)
    args = parser.parse_args()

    events = load_events(args.csv_file)
    findings = []
    findings.extend(detect_failed_logons(events))
    findings.extend(detect_success_after_failures(events))
    findings.extend(detect_suspicious_processes(events))

    report = format_findings(findings)
    print(report)

    if args.save:
        Path(args.save).write_text(report, encoding='utf-8')


if __name__ == '__main__':
    main()
