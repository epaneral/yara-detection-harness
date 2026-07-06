/*
   Phishing / credential-harvester rules for generated-content scanning.
   Scope: HTML/PHP/JS text artifacts. Synthetic corpus, fake recipients/tokens.
*/

rule Phish_Credential_Exfil_PHP
{
    meta:
        author      = "Elyse Paneral"
        description = "PHP that captures posted credentials and ships them out via mail()"
        family      = "phishing.harvester"
        severity    = "high"
        attack      = "T1056.003"
        reference   = "Credential-harvesting kit: $_POST['password'] -> mail(attacker)"
        date        = "2026-06"
    strings:
        // Case-sensitive: PHP superglobal names are. The regex widens past the bare
        // literal to close trivial evasions: \s* tolerates spaced brackets
        // ($_POST[ 'password' ]), the alternation catches $_REQUEST/$_GET (both carry
        // credential input, $_REQUEST aliasing POST), and the class covers either quote.
        $pw = /\$_(POST|REQUEST|GET)\s*\[\s*['"]password['"]\s*\]/ ascii
        // mail() is nocase: PHP function names are case-insensitive, so a kit
        // using Mail()/MAIL() would otherwise evade this rule. \s* tolerates the
        // legal "mail (" spacing PHP allows between name and paren.
        $mail    = /mail\s*\(/ nocase ascii
    condition:
        // Capturing a posted password is normal for any login. The exfil primitive
        // (mail() of the captured value) is what separates the kit from a benign
        // same-origin login handler.
        $pw and $mail
}

rule Phish_Telegram_Exfil
{
    meta:
        author      = "Elyse Paneral"
        description = "Telegram Bot API sendMessage used to exfiltrate captured credentials"
        family      = "phishing.exfil"
        severity    = "high"
        attack      = "T1567"
        reference   = "api.telegram.org/bot<token>/sendMessage carrying login/password"
        date        = "2026-06"
    strings:
        $tg       = "api.telegram.org/bot" ascii nocase
        $send     = "sendMessage" ascii nocase
        $cred1    = "password" ascii nocase
        $cred2    = "passwd" ascii nocase
        // "login" as a credential key: a : or = delimiter (login:, login=, "login":)
        // OR its URL-encoded forms (login%20 / login%3a / login%3d) as seen in
        // query-string exfil -- widened to catch a bare-separator value in a URL.
        // Still excludes a sign-in *alert* ("new login from ..."), where "login" is
        // followed by a literal space + prose rather than a value delimiter.
        $cred3    = /\blogin['"]?(\s*[:=]|%20|%3[ad])/ nocase ascii
        $cred4    = "cvv" ascii nocase
    condition:
        // Telegram is a legitimate notification channel; the credential context is the
        // gate. A deploy-status notifier -- or a login-alert notifier -- has the API
        // call but no credential keyword in a captured-value shape.
        $tg and $send and any of ($cred*)
}
