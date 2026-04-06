function parseUrlEncoded(body) {
  const params = new URLSearchParams(body);
  const out = {};
  for (const [k, v] of params.entries()) out[k] = v;
  return out;
}

async function verifyTurnstile(token, ip) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return { ok: false, reason: "TURNSTILE_SECRET_KEY missing" };
  if (!token) return { ok: false, reason: "turnstile token missing" };

  const form = new URLSearchParams();
  form.set("secret", secret);
  form.set("response", token);
  if (ip) form.set("remoteip", ip);

  const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });

  const data = await resp.json().catch(() => null);
  if (!data?.success) return { ok: false, reason: "turnstile failed", data };
  return { ok: true };
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  const ip =
    (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim() ||
    (req.socket && req.socket.remoteAddress) ||
    "";

  const contentType = (req.headers["content-type"] || "").toString();
  let bodyRaw = "";
  try {
    bodyRaw = await new Promise((resolve, reject) => {
      let d = "";
      req.on("data", (c) => (d += c));
      req.on("end", () => resolve(d));
      req.on("error", reject);
    });
  } catch {
    return res.status(400).send("Bad Request");
  }

  const data =
    contentType.includes("application/json") ? JSON.parse(bodyRaw || "{}") : parseUrlEncoded(bodyRaw || "");

  // Honeypot: bots often fill hidden fields.
  if (data.company) return res.status(200).send("OK");

  const turnstileToken =
    data["cf-turnstile-response"] || data["turnstile-response"] || data["turnstile"] || data["captcha"] || "";

  const turnstile = await verifyTurnstile(turnstileToken, ip);
  if (!turnstile.ok) return res.status(400).send("Spam protection failed");

  const resendKey = process.env.RESEND_API_KEY;
  if (!resendKey) return res.status(500).send("Email not configured");
  const fromEmail = (process.env.CONTACT_FROM_EMAIL || "onboarding@resend.dev").toString();

  const firstName = (data["First-Name"] || "").toString().trim();
  const lastName = (data["Last-Name"] || "").toString().trim();
  const email = (data.email || "").toString().trim();
  const phone = (data.Phone || "").toString().trim();
  const budget = (data.Number || "").toString().trim();
  const message = (data.Message || "").toString().trim();

  if (!email || !message) return res.status(400).send("Missing required fields");

  const subject = `New Vaelor Finance inquiry${firstName || lastName ? ` — ${[firstName, lastName].filter(Boolean).join(" ")}` : ""}`;
  const text = [
    "New website inquiry",
    "",
    `Name: ${[firstName, lastName].filter(Boolean).join(" ") || "-"}`,
    `Email: ${email}`,
    `Phone: ${phone || "-"}`,
    `Budget: ${budget || "-"}`,
    "",
    "Message:",
    message,
    "",
    `IP: ${ip || "-"}`,
  ].join("\n");

  const to = ["sales@vaelorfinance.com", "stephen.rutikanga@vaelorfinance.com"];

  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${resendKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: `Vaelor Finance Website <${fromEmail}>`,
      to,
      reply_to: email,
      subject,
      text,
    }),
  });

  if (!resp.ok) {
    const errText = await resp.text().catch(() => "");
    // Log full error server-side for debugging.
    console.error("Resend send failed", { status: resp.status, body: errText });
    // Return a concise message to the client.
    return res.status(502).json({
      ok: false,
      error: "Email failed",
      status: resp.status,
    });
  }

  return res.status(200).json({ ok: true });
}

