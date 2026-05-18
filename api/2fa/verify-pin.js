const crypto = require("crypto");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
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

  const { code } = req.body || {};

  if (!code) {
    return res.status(400).json({
      success: false,
      error: "Kode rahasia wajib diisi"
    });
  }

  const correctPin = process.env.A2F_PIN;

  if (!correctPin) {
    return res.status(500).json({
      success: false,
      error: "A2F_PIN belum diset di Vercel"
    });
  }

  const inputCode = String(code).trim();
  const savedCode = String(correctPin).trim();

  if (!safeEqual(inputCode, savedCode)) {
    return res.status(401).json({
      success: false,
      error: "Kode rahasia salah"
    });
  }

  return res.status(200).json({
    success: true,
    message: "Kode rahasia benar"
  });
};
