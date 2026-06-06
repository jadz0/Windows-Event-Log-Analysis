# Windows Event Log Analysis

A GitHub-ready SOC project that analyzes exported Windows event data and flags suspicious authentication and process activity.

## Project Overview

This project demonstrates a simple Windows event log analysis workflow using Python and exported CSV event data.

The script reviews sample Windows events and detects:
- repeated failed logons
- successful logon after repeated failures
- suspicious process creation activity

This project is designed for beginner SOC / blue-team portfolio use and focuses on clear detection logic, readable output, and investigation-oriented thinking.

## Why This Project Matters

Windows event analysis is a core SOC analyst skill. Analysts regularly investigate failed authentication attempts, successful logons after suspicious activity, and unusual process execution. A small project like this helps demonstrate practical log analysis, basic detection logic, and blue-team thinking in a format that is easy to review on GitHub. [web:205]

This project uses common Windows Security event IDs:
- **4625** – failed logon
- **4624** – successful logon
- **4688** – process creation

## Skills Demonstrated

- Python scripting
- Log parsing
- Basic detection engineering
- Windows Security event awareness
- SOC-style triage logic
- Investigation-oriented documentation

## Project Structure

```text
windows-event-log-analysis/
├── README.md
├── windows_event_analyzer.py
├── samples/
│   └── windows_events.csv
├── output/
│   └── results.txt
├── docs/
│   ├── event-ids.md
│   ├── detection-logic.md
│   └── investigation-notes.md
└── Output.png
```

## Detection Logic

### 1. Repeated Failed Logons
The script counts failed logon events by user and source IP.
If the same user and IP reach 3 or more failed attempts, it creates a finding.

### 2. Successful Logon After Failures
The script checks whether a successful logon occurs after repeated failed logons for the same user and source IP.
This helps simulate a simple brute-force or credential-guessing follow-up detection.

### 3. Suspicious Process Creation
The script reviews process creation events and looks for suspicious command-line indicators such as:
- `powershell.exe -enc`
- `powershell.exe -encodedcommand`
- `cmd.exe /c whoami`
- `rundll32.exe`
- `regsvr32.exe`
- `mshta.exe`

## Requirements

This project uses only Python standard library modules.

```txt
# No external dependencies required
```

## How to Run

From inside the project folder:

```bash
python windows_event_analyzer.py samples/windows_events.csv --save output/results.txt
```

If your system uses `python3`, run:

```bash
python3 windows_event_analyzer.py samples/windows_events.csv --save output/results.txt
```

## Sample Output

```txt
========================================
 Windows Event Log Analysis Results
========================================

[HIGH] Successful Logon After Failures
  User: administrator
  Source IP: 10.10.10.50
  Prior Failures: 3

[HIGH] Suspicious Process Creation
  User: student
  Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Parent: C:\Windows\explorer.exe
  Indicator: powershell.exe -enc

[HIGH] Suspicious Process Creation
  User: student
  Process: C:\Windows\System32\cmd.exe
  Parent: C:\Windows\explorer.exe
  Indicator: cmd.exe /c whoami

[MEDIUM] Repeated Failed Logons
  User: administrator
  Source IP: 10.10.10.50
  Count: 3

[MEDIUM] Repeated Failed Logons
  User: backupsvc
  Source IP: 192.168.1.77
  Count: 3

Summary:
- High: 3
- Medium: 2
- Low: 0
- Total Findings: 5
```

## Files Included

- `windows_event_analyzer.py` – main analysis script
- `samples/windows_events.csv` – sample Windows event dataset
- `output/results.txt` – saved findings
- `docs/event-ids.md` – key event ID explanations
- `docs/detection-logic.md` – detection overview
- `docs/investigation-notes.md` – triage notes
