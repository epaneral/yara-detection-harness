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
        // Bare high-signal credential words -- rarely innocent substrings, so no
        // value-shape is needed to keep them off the benign corpus.
        $cred1    = "password" ascii nocase
        $cred2    = "passwd" ascii nocase
        $cred3    = "cvv" ascii nocase
        $cred4    = "cvc" ascii nocase
        // Ambiguous keys -- each is a common benign identifier or substring (a bot's own
        // TELEGRAM_BOT_TOKEN, a "new login from ..." alert, className / shopping), so each
        // is required in an exfil value-shape: KEY directly followed by : or = (query-param
        // or JSON key), or a URL-encoded delimiter (%20 / %3a / %3d). The no-space rule is
        // deliberate -- it keeps a benign "const token = ..." assignment and a literal-space
        // "new login to ..." alert from tripping the gate, while still catching key=value
        // and "key":"value" exfil.
        $key1     = /\blogin['"]?([:=]|%20|%3[ad])/ nocase ascii
        $key2     = /\btoken['"]?([:=]|%20|%3[ad])/ nocase ascii
        $key3     = /\botp['"]?([:=]|%20|%3[ad])/ nocase ascii
        $key4     = /\bpasscode['"]?([:=]|%20|%3[ad])/ nocase ascii
        $key5     = /\bpin['"]?([:=]|%20|%3[ad])/ nocase ascii
        $key6     = /\bsecret['"]?([:=]|%20|%3[ad])/ nocase ascii
        $key7     = /\bssn['"]?([:=]|%20|%3[ad])/ nocase ascii
    condition:
        // Telegram is a legitimate notification channel; a captured-credential value is the
        // gate. A deploy-status, login-alert, or token-rotation notifier has the API call
        // but no credential in an exfil value-shape.
        $tg and $send and (any of ($cred*) or any of ($key*))
}
