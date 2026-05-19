const crypto = require("crypto");
const {
  verifyAuthenticationResponse,
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

function bufferToBase64url(value) {
  return Buffer.from(value).toString("base64url");
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

function findCredentialByResponseId(credentials, response) {
  const responseId = response && response.id ? String(response.id) : "";
  return credentials.find((credential) => String(credential.id) === responseId);
}

function buildCredentialFromRegistrationInfo(registrationInfo, response, deviceName) {
  const credential = registrationInfo.credential || {};

  const credentialId =
    credential.id ||
    (registrationInfo.credentialID
      ? bufferToBase64url(registrationInfo.credentialID)
      : response.id);

  const publicKey =
    credential.publicKey ||
    registrationInfo.credentialPublicKey;

  if (!credentialId || !publicKey) {
    throw new Error("Data passkey baru tidak lengkap");
  }

  return {
    name: deviceName || "Passkey cadangan",
    id: credentialId,
    publicKey: bufferToBase64url(publicKey),
    counter: credential.counter || registrationInfo.counter || 0,
    transports:
      response &&
      response.response &&
      Array.isArray(response.response.transports)
        ? response.response.transports
        : [],
    createdAt: new Date().toISOString()
  };
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
    const { response, session, deviceName } = req.body || {};
    const data = parseSession(session);

    const rpID = process.env.PASSKEY_RP_ID || "diracgroup.store";
    const origin = process.env.PASSKEY_ORIGIN || "https://diracgroup.store";
    const savedCredentials = readSavedCredentials();

    if (data.mode === "register") {
      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: data.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false
      });

      if (!verification.verified) {
        return res.status(401).json({
          success: false,
          error: "Pendaftaran passkey ditolak"
        });
      }

      const newCredential = buildCredentialFromRegistrationInfo(
        verification.registrationInfo,
        response,
        deviceName
      );

      const updatedCredentials = [
        ...savedCredentials.filter((credential) => credential.id !== newCredential.id),
        newCredential
      ];

      return res.status(200).json({
        success: true,
        mode: "register",
        message: "Passkey cadangan berhasil dibuat",
        credential: newCredential,
        credentialsJson: JSON.stringify(updatedCredentials, null, 2)
      });
    }

    if (!savedCredentials.length) {
      return res.status(500).json({
        success: false,
        error: "Belum ada passkey. Set PASSKEY_CREDENTIAL_JSON atau PASSKEY_CREDENTIALS_JSON di Vercel"
      });
    }

    const saved = findCredentialByResponseId(savedCredentials, response);

    if (!saved) {
      return res.status(401).json({
        success: false,
        error: "Passkey ini belum terdaftar"
      });
    }

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
      mode: "auth",
      message: "Passkey benar"
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message || "Gagal verifikasi passkey"
    });
  }
};
