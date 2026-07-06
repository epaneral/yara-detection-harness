// Legitimate security notifier: when a user signs in, post an alert to the team's ops
// channel via the Telegram Bot API. Mentions a sign-in event in prose, but carries no
// captured credential in a key/value shape -- so the credential gate on Phish_Telegram_Exfil
// stays unmet and this is a near-miss, not a hit.
async function alertSignin(user, city){
  const token = process.env.TELEGRAM_BOT_TOKEN;
  await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({chat_id: process.env.CHAT_ID, text: `New login to ${user}'s account from ${city}`})
  });
}
