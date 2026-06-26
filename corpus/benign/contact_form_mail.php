<?php
// Legitimate contact form: email a user-submitted message to support. Calls mail() (with a
// space before the paren) but never captures a posted password -- Phish_Credential_Exfil_PHP
// requires a captured password AND outbound mail, so the capture half is absent here.
$name = $_POST['name'];
$message = $_POST['message'];
mail ("support@example.com", "Contact from $name", $message);
echo "Thanks, we'll be in touch.";
?>
