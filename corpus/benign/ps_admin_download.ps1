# Legitimate ops script: download an installer to disk from a known domain, then log it.
$client = New-Object System.Net.WebClient
$url = "https://downloads.example.com/agent/setup.msi"
$client.DownloadFile($url, "$env:TEMP\setup.msi")
Write-Host "Downloaded agent installer to $env:TEMP\setup.msi"
