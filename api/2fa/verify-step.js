const crypto = require("crypto");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

function hashCode(code, secret) {
  return crypto.createHmac("sha256", secret).update(String(code)).digest("hex");
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

module.exports = function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  const { sessionId, code, step } = req.body || {};
  const stepNumber = Number(step);

  if (!sessionId || !code || ![2, 3].includes(stepNumber)) {
    return res.status(400).json({
      success: false,
      error: "Session, kode, dan step wajib benar"
    });
  }

  const secret = process.env.A2F_SECRET || "rahasia-test";
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
      error: "Session A2F palsu"
    });
  }

  let payload;

  try {
    payload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString("utf8"));
  } catch (error) {
    return res.status(400).json({
      success: false,
      error: "Data session rusak"
    });
  }

  if (payload.step !== stepNumber) {
    return res.status(400).json({
      success: false,
      error: "Step tidak sesuai"
    });
  }

  if (Date.now() > payload.expiresAt) {
    return res.status(400).json({
      success: false,
      error: "Kode sudah expired"
    });
  }

  const inputHash = hashCode(`${stepNumber}:${code}`, secret);

  if (!safeEqual(inputHash, payload.codeHash)) {
    return res.status(401).json({
      success: false,
      error: "Kode salah"
    });
  }

  return res.status(200).json({
    success: true,
    message: `Kode A2F tahap ${stepNumber} benar`,
    nextStep: stepNumber + 1
  });
};
