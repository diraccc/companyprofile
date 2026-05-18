const crypto = require("crypto");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let bytes = [];

  base32 = String(base32).replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();

  for (const char of base32) {
    const val = alphabet.indexOf(char);
    if (val === -1) throw new Error("Secret TOTP tidak valid");
    bits += val.toString(2).padStart(5, "0");
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return Buffer.from(bytes);
}

function generateTotp(secret, offset = 0) {
  const key = base32Decode(secret);
  const timeStep = Math.floor(Date.now() / 1000 / 30) + offset;

  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(0, 0);
  buffer.writeUInt32BE(timeStep, 4);

  const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
  const hOffset = hmac[hmac.length - 1] & 0xf;

  const code =
    ((hmac[hOffset] & 0x7f) << 24) |
    ((hmac[hOffset + 1] & 0xff) << 16) |
    ((hmac[hOffset + 2] & 0xff) << 8) |
    (hmac[hOffset + 3] & 0xff);

  return String(code % 1000000).padStart(6, "0");
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
      error: "Kode wajib diisi"
    });
  }

  const secret = process.env.TOTP_SECRET;

  if (!secret) {
    return res.status(500).json({
      success: false,
      error: "TOTP_SECRET belum diset di Vercel"
    });
  }

  const inputCode = String(code).replace(/\s+/g, "");

  const validCodes = [
    generateTotp(secret, -1),
    generateTotp(secret, 0),
    generateTotp(secret, 1)
  ];

  if (!validCodes.includes(inputCode)) {
    return res.status(401).json({
      success: false,
      error: "Kode Authenticator salah"
    });
  }

  return res.status(200).json({
    success: true,
    message: "Kode Authenticator benar"
  });
};
