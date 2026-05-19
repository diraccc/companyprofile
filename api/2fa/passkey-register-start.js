const crypto = require("crypto");
const { generateRegistrationOptions } = require("@simplewebauthn/server");

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

  const options = await generateRegistrationOptions({
    rpName: "Dirac Admin",
    rpID,
    userName: "admin@diracgroup.store",
    userDisplayName: "Dirac Admin",
    attestationType: "none",
    supportedAlgorithmIDs: [-7, -257],
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred"
    }
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
