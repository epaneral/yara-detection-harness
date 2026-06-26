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
        // $_POST stays case-sensitive: PHP variable/superglobal names are too.
        $pw_post = "$_POST['password']" ascii
        $pw_post2 = "$_POST[\"password\"]" ascii
        // mail() is nocase: PHP function names are case-insensitive, so a kit
        // using Mail()/MAIL() would otherwise evade this rule.
        $mail    = "mail(" nocase ascii
    condition:
        // Capturing a posted password is normal for any login. The exfil primitive
        // (mail() of the captured value) is what separates the kit from a benign
        // same-origin login handler.
        ($pw_post or $pw_post2) and $mail
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
        $cred3    = "login" ascii nocase
        $cred4    = "cvv" ascii nocase
    condition:
        // Telegram is a legitimate notification channel; the credential context is the
        // gate. A deploy-status notifier has the API call but no credential keywords.
        $tg and $send and any of ($cred*)
}
