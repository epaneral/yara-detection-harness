<?php
// Legitimate login: validates against internal DB, posts same-origin, no outbound mail of creds.
session_start();
$user = $_POST['username'];
$pass = $_POST['password'];
if (verify_credentials($user, password_hash($pass, PASSWORD_DEFAULT))) {
    $_SESSION['uid'] = $user;
    header("Location: /dashboard");
}
?>
