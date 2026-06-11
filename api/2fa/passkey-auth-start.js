const crypto = require("crypto");
const { generateAuthenticationOptions } = require("@simplewebauthn/server");

function getAllowedOrigins() {
  const fromEnv = String(process.env.A2F_ALLOWED_ORIGINS || process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  return fromEnv.length ? fromEnv : [
    "https://diracgroup.store",
    "https://www.diracgroup.store",
    "https://companyprofilee-expk.vercel.app",
    "https://companyprofilee-ochre.vercel.app"
  ];
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return getAllowedOrigins().includes(origin);
}

function setCors(req, res) {
  const origin = String((req && req.headers && req.headers.origin) || "");
  if (isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin || "https://diracgroup.store");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
  return isAllowedOrigin(origin);
}

function getA2fSecret() {
  const secret = String(process.env.A2F_SECRET || "").trim();
  if (!secret || secret === "rahasia-test" || secret.length < 32) {
    const err = new Error("A2F_SECRET production wajib diset minimal 32 karakter acak.");
    err.statusCode = 500;
    throw err;
  }
  return secret;
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

module.exports = async function handler(req, res) {
  const corsOk = setCors(req, res);

  if (req.method === "OPTIONS") return res.status(corsOk ? 200 : 403).end();
  if (!corsOk) return res.status(403).json({ success: false, error: "Origin tidak diizinkan" });

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  const rpID = process.env.PASSKEY_RP_ID || "diracgroup.store";
  const secret = getA2fSecret();
  const credentialJson = process.env.PASSKEY_CREDENTIAL_JSON;

  if (!credentialJson) {
    return res.status(500).json({
      success: false,
      error: "PASSKEY_CREDENTIAL_JSON belum diset di Vercel"
    });
  }

  const credential = JSON.parse(credentialJson);

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: "preferred",
    allowCredentials: [
      {
        id: credential.id,
        type: "public-key",
        transports: credential.transports || []
      }
    ]
  });

  const payload = {
    challenge: options.challenge,
    createdAt: Date.now()
  };

  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign(payloadBase64, secret);
  const session = `${payloadBase64}.${signature}`;

  return res.status(200).json({
    success: true,
    options,
    session
  });
};
// redeploy trigger
