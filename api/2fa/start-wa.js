const crypto = require("crypto");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function sign(data, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64url");
}

function hashCode(code, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(String(code))
    .digest("hex");
}

module.exports = function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  const secret = process.env.A2F_SECRET || "rahasia-test-ganti-nanti";

  const code = crypto.randomInt(100000, 999999).toString();

  const payload = {
    step: 1,
    codeHash: hashCode(code, secret),
    expiresAt: Date.now() + 5 * 60 * 1000,
    nonce: crypto.randomBytes(16).toString("hex")
  };

  const payloadText = JSON.stringify(payload);
  const payloadBase64 = base64url(payloadText);
  const signature = sign(payloadBase64, secret);

  const sessionId = `${payloadBase64}.${signature}`;

  return res.status(200).json({
    success: true,
    sessionId,
    debugCode: code,
    message: "Kode A2F WA tahap 1 dibuat. Untuk tes awal, kode masih muncul di debugCode."
  });
};
