/*
   PowerShell abuse rules for generated-content scanning.
   Scope: text/code artifacts (not PE binaries). Synthetic corpus.
*/

rule PS_Download_Cradle_IEX
{
    meta:
        author      = "Elyse Paneral"
        description = "PowerShell download-and-execute cradle: Invoke-Expression over a remotely fetched string"
        family      = "powershell.cradle"
        severity    = "high"
        reference   = "Classic IEX (New-Object Net.WebClient).DownloadString pattern"
        date        = "2026-06"
    strings:
        $iex1 = "IEX" fullword ascii wide
        $iex2 = "Invoke-Expression" ascii wide nocase
        $dl1  = "DownloadString" ascii wide nocase
        $dl2  = "DownloadData" ascii wide nocase
    condition:
        // execution primitive AND remote-fetch primitive in the same artifact.
        // Stays off benign DownloadFile-to-disk admin scripts (no IEX / Invoke-Expression).
        ($iex1 or $iex2) and ($dl1 or $dl2)
}

rule PS_Encoded_Hidden_Launcher
{
    meta:
        author      = "Elyse Paneral"
        description = "PowerShell launched with an encoded command and a suppressed window"
        family      = "powershell.encoded"
        severity    = "high"
        reference   = "powershell -nop -w hidden -enc <base64>"
        date        = "2026-06"
    strings:
        $enc1   = "-enc" ascii wide nocase
        $enc2   = "-encodedcommand" ascii wide nocase
        $hide1  = "-w hidden" ascii wide nocase
        $hide2  = "-windowstyle hidden" ascii wide nocase
        $hide3  = "hidden" ascii wide nocase
        $nop    = "-nop" ascii wide nocase
    condition:
        // Encoded payload AND window/profile suppression. A base64 *config* decode
        // (benign) has neither -enc nor a hidden-window flag, so it won't trip.
        ($enc1 or $enc2) and ($hide1 or $hide2 or ($hide3 and $nop))
}
