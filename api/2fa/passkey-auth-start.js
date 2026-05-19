const crypto = require("crypto");
const {
  generateAuthenticationOptions,
  generateRegistrationOptions
} = require("@simplewebauthn/server");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function sign(data, secret) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
}

function readSavedCredentials() {
  const manyCredentialsJson = process.env.PASSKEY_CREDENTIALS_JSON;
  const singleCredentialJson = process.env.PASSKEY_CREDENTIAL_JSON;

  if (manyCredentialsJson) {
    const parsed = JSON.parse(manyCredentialsJson);
    if (!Array.isArray(parsed)) {
      throw new Error("PASSKEY_CREDENTIALS_JSON harus berbentuk array");
    }
    return parsed;
  }

  if (singleCredentialJson) {
    return [JSON.parse(singleCredentialJson)];
  }

  return [];
}

function makeSession(payload) {
  const secret = process.env.A2F_SECRET || "rahasia-test";
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign(payloadBase64, secret);
  return `${payloadBase64}.${signature}`;
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
    const rpID = process.env.PASSKEY_RP_ID || "diracgroup.store";
    const rpName = process.env.PASSKEY_RP_NAME || "Dirac Group";
    const mode = req.body && req.body.mode === "register" ? "register" : "auth";

    const savedCredentials = readSavedCredentials();

    if (mode === "register") {
      const userName = process.env.PASSKEY_USER_NAME || "dirac-admin";
      const userDisplayName = process.env.PASSKEY_USER_DISPLAY_NAME || "Dirac Admin";

      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: Buffer.from(userName),
        userName,
        userDisplayName,
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred"
        },
        excludeCredentials: savedCredentials.map((credential) => ({
          id: credential.id,
          type: "public-key",
          transports: credential.transports || []
        }))
      });

      const session = makeSession({
        mode: "register",
        challenge: options.challenge,
        createdAt: Date.now()
      });

      return res.status(200).json({
        success: true,
        mode: "register",
        options,
        session
      });
    }

    if (!savedCredentials.length) {
      return res.status(500).json({
        success: false,
        error: "Belum ada passkey. Set PASSKEY_CREDENTIAL_JSON atau PASSKEY_CREDENTIALS_JSON di Vercel"
      });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: "preferred",
      allowCredentials: savedCredentials.map((credential) => ({
        id: credential.id,
        type: "public-key",
        transports: credential.transports || []
      }))
    });

    const session = makeSession({
      mode: "auth",
      challenge: options.challenge,
      createdAt: Date.now()
    });

    return res.status(200).json({
      success: true,
      mode: "auth",
      options,
      session
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message || "Gagal memulai passkey"
    });
  }
};
