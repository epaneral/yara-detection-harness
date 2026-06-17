// Legitimate deploy notifier: posts a build status to a team channel via Telegram Bot API.
async function notify(status){
  const token = process.env.TELEGRAM_BOT_TOKEN;
  await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({chat_id: process.env.CHAT_ID, text: `deploy ${status}`})
  });
}
