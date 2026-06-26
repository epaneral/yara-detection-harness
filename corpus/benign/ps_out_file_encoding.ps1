# Legitimate background admin task: run windowless (no console pop-up for a scheduled job)
# and write a process list to a file with an explicit text encoding. The encoding flag
# shares a prefix with the encoded-command flag and the window is suppressed, but there is
# no encoded payload -- the exact near-miss PS_Encoded_Hidden_Launcher must not fire on.
powershell -nop -w hidden -Command "Get-Process | Out-File -Encoding utf8 procs.txt"
