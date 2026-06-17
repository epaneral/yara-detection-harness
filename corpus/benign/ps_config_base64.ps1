# Legitimate script: decode a base64-encoded config string (no -enc, no hidden window).
$encoded = "eyJlbnYiOiJwcm9kIiwicmVnaW9uIjoidXMtZWFzdC0xIn0="
$json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
Write-Host "Loaded config: $json"
