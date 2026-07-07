<?php
// Legitimate gated download: a shared link carries a one-off passphrase in its query
// string; compare it against the stored token and stream the file on a match. Reads a
// credential from a request superglobal like the harvester does, but performs no outbound
// mail, so the exfil half the rule keys on is absent -- a near-miss, not a hit.
$supplied = $_GET['password'];
if (hash_equals(get_stored_token($_GET['file']), $supplied)) {
    stream_file($_GET['file']);
} else {
    http_response_code(403);
}
?>
