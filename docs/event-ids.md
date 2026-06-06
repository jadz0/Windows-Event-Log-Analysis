# Windows Event IDs Used in This Project

## Event ID 4625 - Failed Logon
This event shows that an account logon attempt failed.

Why it matters:
- Useful for spotting brute-force attempts
- Useful for spotting password spraying or repeated bad credentials
- Helps analysts identify suspicious source IP addresses

## Event ID 4624 - Successful Logon
This event shows that an account successfully logged on.

Why it matters:
- Useful for validating whether failed logons were followed by a success
- Helps analysts identify possible account compromise after repeated failures
- Can be correlated with logon type and source IP

## Event ID 4688 - Process Creation
This event shows that a new process was created.

Why it matters:
- Useful for identifying suspicious process execution
- Helps analysts review command-line activity
- Helpful for spotting suspicious PowerShell or command shell behavior
