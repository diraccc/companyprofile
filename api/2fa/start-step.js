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

async function sendWhatsApp(code) {
  const token = process.env.FONNTE_TOKEN;
  const target = process.env.WA_ADMIN_NUMBER;

  if (!token) throw new Error("FONNTE_TOKEN belum diset");
  if (!target) throw new Error("WA_ADMIN_NUMBER belum diset");

  const body = new URLSearchParams();
  body.append("target", target);
  body.append("message", `Kode A2F tahap 3 kamu adalah: ${code}\n\nKode berlaku 5 menit.`);

  const response = await fetch("https://api.fonnte.com/send", {
    method: "POST",
    headers: {
      Authorization: token
    },
    body
  });

  const result = await response.text();

  if (!response.ok) {
    throw new Error(result || "Gagal kirim WhatsApp");
  }

  return result;
}

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  const { step } = req.body || {};
  const stepNumber = Number(step);

  if (![2, 3].includes(stepNumber)) {
    return res.status(400).json({
      success: false,
      error: "Step harus 2 atau 3"
    });
  }

  const secret = process.env.A2F_SECRET || "rahasia-test";
  const code = crypto.randomInt(100000, 999999).toString();

  const payload = {
    step: stepNumber,
    codeHash: hashCode(`${stepNumber}:${code}`, secret),
    expiresAt: Date.now() + 5 * 60 * 1000,
    nonce: crypto.randomBytes(16).toString("hex")
  };

  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign(payloadBase64, secret);
  const sessionId = `${payloadBase64}.${signature}`;

  if (stepNumber === 3) {
    try {
      await sendWhatsApp(code);

      return res.status(200).json({
        success: true,
        sessionId,
        step: 3,
        message: "Kode A2F tahap 3 sudah dikirim ke WhatsApp admin"
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal kirim WhatsApp"
      });
    }
  }

  return res.status(200).json({
    success: true,
    sessionId,
    debugCode: code,
    step: 2,
    message: "Kode A2F tahap 2 dibuat"
  });
};
