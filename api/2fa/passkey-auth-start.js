const crypto = require("crypto");
const { generateAuthenticationOptions } = require("@simplewebauthn/server");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
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

  const rpID = process.env.PASSKEY_RP_ID || "diracgroup.store";
  const secret = process.env.A2F_SECRET || "rahasia-test";
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
