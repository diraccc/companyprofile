const crypto = require("crypto");
const { verifyAuthenticationResponse } = require("@simplewebauthn/server");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function base64urlToBuffer(value) {
  return Buffer.from(String(value), "base64url");
}

function parseSession(session) {
  const secret = process.env.A2F_SECRET || "rahasia-test";
  const [payloadBase64, signature] = String(session || "").split(".");

  if (!payloadBase64 || !signature) {
    throw new Error("Session passkey tidak valid");
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(payloadBase64)
    .digest("base64url");

  if (signature !== expected) {
    throw new Error("Session passkey palsu");
  }

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
    const credentialJson = process.env.PASSKEY_CREDENTIAL_JSON;

    if (!credentialJson) {
      return res.status(500).json({
        success: false,
        error: "PASSKEY_CREDENTIAL_JSON belum diset di Vercel"
      });
    }

    const saved = JSON.parse(credentialJson);

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: data.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: saved.id,
        publicKey: base64urlToBuffer(saved.publicKey),
        counter: saved.counter || 0,
        transports: saved.transports || []
      }
    });

    if (!verification.verified) {
      return res.status(401).json({
        success: false,
        error: "Passkey salah atau ditolak"
      });
    }

    return res.status(200).json({
      success: true,
      message: "Passkey benar"
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message || "Gagal verifikasi passkey"
    });
  }
};
