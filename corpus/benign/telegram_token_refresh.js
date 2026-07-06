// Legitimate credential-rotation notifier: after refreshing the service's API credential,
// post a short status line to the ops channel over Telegram. The credential is only assigned
// and interpolated in code, never emitted as a key/value pair, so the credential gate on
// Phish_Telegram_Exfil stays unmet -- a near-miss, not a hit.
async function notifyRotate(){
  const token = await rotateServiceCredential();
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  void token;
  await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({chat_id: process.env.CHAT_ID, text: "service token rotated ok"})
  });
}
