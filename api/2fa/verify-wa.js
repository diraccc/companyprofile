const crypto = require("crypto");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
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

function safeEqual(a, b) {
  const bufferA = Buffer.from(String(a));
  const bufferB = Buffer.from(String(b));

  if (bufferA.length !== bufferB.length) {
    return false;
  }

  return crypto.timingSafeEqual(bufferA, bufferB);
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

  const { sessionId, code } = req.body || {};

  if (!sessionId || !code) {
    return res.status(400).json({
      success: false,
      error: "Session ID dan kode wajib diisi"
    });
  }

  const secret = process.env.A2F_SECRET || "rahasia-test-ganti-nanti";

  const parts = String(sessionId).split(".");

  if (parts.length !== 2) {
    return res.status(400).json({
      success: false,
      error: "Session A2F tidak valid"
    });
  }

  const payloadBase64 = parts[0];
  const signature = parts[1];

  const expectedSignature = sign(payloadBase64, secret);

  if (!safeEqual(signature, expectedSignature)) {
    return res.status(401).json({
      success: false,
      error: "Session A2F palsu atau rusak"
    });
  }

  let payload;

  try {
    const payloadText = Buffer.from(payloadBase64, "base64url").toString("utf8");
    payload = JSON.parse(payloadText);
  } catch (error) {
    return res.status(400).json({
      success: false,
      error: "Data session A2F rusak"
    });
  }

  if (payload.step !== 1) {
    return res.status(400).json({
      success: false,
      error: "Step A2F tidak sesuai"
    });
  }

  if (Date.now() > payload.expiresAt) {
    return res.status(400).json({
      success: false,
      error: "Kode A2F sudah expired"
    });
  }

  const inputHash = hashCode(code, secret);

  if (!safeEqual(inputHash, payload.codeHash)) {
    return res.status(401).json({
      success: false,
      error: "Kode A2F salah"
    });
  }

  return res.status(200).json({
    success: true,
    message: "Kode A2F WA tahap 1 benar",
    nextStep: 2
  });
};
