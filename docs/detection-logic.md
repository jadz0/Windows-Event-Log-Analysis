# Detection Logic

## 1. Repeated Failed Logons
The script counts Event ID 4625 entries by user and source IP.
If the count reaches 3 or more, it creates a finding.

## 2. Successful Logon After Failures
The script tracks repeated failed logons first.
If a successful Event ID 4624 appears later for the same user and source IP, it creates a high-severity finding.

## 3. Suspicious Process Creation
The script checks Event ID 4688 command-line data for suspicious indicators such as:
- powershell.exe -enc
- powershell.exe -encodedcommand
- cmd.exe /c whoami
- rundll32.exe
- regsvr32.exe
- mshta.exe
