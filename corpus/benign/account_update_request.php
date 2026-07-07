<?php
// Legitimate account-settings update: hash the submitted new secret and persist it.
// Shares the harvester's capture shape (a submitted credential read from a request
// superglobal) but never ships it anywhere -- there is no outbound mail, which is the
// exfil half the rule requires, so this stays a near-miss.
session_start();
$uid = $_SESSION['uid'];
$new = $_REQUEST[ 'password' ];
update_user_hash($uid, password_hash($new, PASSWORD_DEFAULT));
echo "Password updated.";
?>
