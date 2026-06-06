# Investigation Notes

## Repeated Failed Logons
Questions to ask:
- Is the source IP internal or external?
- Is the targeted account privileged?
- Did a successful login happen after the failures?
- Is the behavior normal for the user?

## Success After Failures
Questions to ask:
- Was the account compromised?
- Was this a user typing the wrong password several times?
- Did the source IP appear elsewhere in the logs?

## Suspicious Process Creation
Questions to ask:
- Who launched the process?
- What was the parent process?
- Was PowerShell encoded or hidden?
- Were there related file, registry, or network events?
