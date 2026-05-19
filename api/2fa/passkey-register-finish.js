const {
  verifyRegistrationResponse
} = require("@simplewebauthn/server");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function base64urlToBuffer(value) {
  return Buffer.from(String(value), "base64url");
}

function bufferToBase64url(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

function parseSession(session) {
  const secret = process.env.A2F_SECRET || "rahasia-test";
  const crypto = require("crypto");

  const [payloadBase64, signature] = String(session || "").split(".");
  if (!payloadBase64 || !signature) throw new Error("Session passkey tidak valid");

  const expected = crypto
    .createHmac("sha256", secret)
    .update(payloadBase64)
    .digest("base64url");

  if (signature !== expected) throw new Error("Session passkey palsu");

  return JSON.parse(base64urlToBuffer(payloadBase64).toString("utf8"));
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

  try {
    const { response, session } = req.body || {};
    const data = parseSession(session);

    const rpID = process.env.PASSKEY_RP_ID || "diracgroup.store";
    const origin = process.env.PASSKEY_ORIGIN || "https://diracgroup.store";

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: data.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID
    });

    if (!verification.verified) {
      return res.status(401).json({
        success: false,
        error: "Pendaftaran passkey gagal"
      });
    }

    const credential = verification.registrationInfo.credential;

    return res.status(200).json({
      success: true,
      message: "Passkey berhasil dibuat. Simpan PASSKEY_CREDENTIAL_JSON ke Vercel.",
      credentialJson: JSON.stringify({
        id: credential.id,
        publicKey: bufferToBase64url(credential.publicKey),
        counter: credential.counter,
        transports: response.response?.transports || []
      })
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message || "Gagal verifikasi passkey"
    });
  }
};
