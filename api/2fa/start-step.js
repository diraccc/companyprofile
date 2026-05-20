const crypto = require("crypto");
const admin = require("firebase-admin");
const argon2 = require("argon2");

const ONE_TIME_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ONE_TIME_RECOVERY_RANDOM_LENGTH = 50;
const ARGON2ID_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
  hashLength: 32
});

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

function makeSession(payload, secret) {
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign(payloadBase64, secret);
  return `${payloadBase64}.${signature}`;
}

function getFirebaseDb() {
  if (!admin.apps.length) {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    const privateKey = String(process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n");

    if (!projectId || !clientEmail || !privateKey) {
      throw new Error("ENV Firebase Admin belum lengkap");
    }

    admin.initializeApp({
      credential: admin.credential.cert({
        projectId,
        clientEmail,
        privateKey
      })
    });
  }

  return admin.firestore();
}

function getAdminUid() {
  const uid = String(process.env.A2F_ADMIN_UID || "").trim();

  if (!uid) {
    throw new Error("A2F_ADMIN_UID belum diset");
  }

  return uid;
}

async function verifyAdminIdToken(idToken) {
  const token = String(idToken || "").trim();

  if (!token) {
    throw new Error("ID token admin wajib dikirim");
  }

  getFirebaseDb();
  const decoded = await admin.auth().verifyIdToken(token);
  const expectedUid = getAdminUid();

  if (decoded.uid !== expectedUid) {
    throw new Error("Akun ini tidak diizinkan membuat recovery code");
  }

  return decoded;
}

function normalizeOneTimeRecoveryCode(code) {
  return String(code || "").trim().toUpperCase().replace(/[\s-]+/g, "");
}

function getOneTimeRecoveryLookupHash(code, secret) {
  const normalized = normalizeOneTimeRecoveryCode(code);
  return crypto.createHmac("sha256", secret).update(`one-time-recovery-lookup:${normalized}`).digest("hex");
}

async function hashOneTimeRecoveryCodeArgon2id(code) {
  const normalized = normalizeOneTimeRecoveryCode(code);
  return argon2.hash(normalized, ARGON2ID_OPTIONS);
}

function generateRandomRecoveryBody(length = ONE_TIME_RECOVERY_RANDOM_LENGTH) {
  const bytes = crypto.randomBytes(length);
  let body = "";

  for (const byte of bytes) {
    body += ONE_TIME_RECOVERY_ALPHABET[byte & 31];
  }

  return body;
}

function formatOneTimeRecoveryCode(body) {
  const groups = String(body).match(/.{1,5}/g) || [];
  return `DG-RCV-${groups.join("-")}`;
}

function generateOneTimeRecoveryCode() {
  return formatOneTimeRecoveryCode(generateRandomRecoveryBody());
}

async function generateOneTimeRecoveryCodes(reqBody) {
  const secret = process.env.A2F_SECRET || "rahasia-test";
  const decoded = await verifyAdminIdToken(reqBody && reqBody.idToken);
  const countRaw = Number(reqBody && reqBody.count);
  const count = Number.isFinite(countRaw) ? Math.min(20, Math.max(1, Math.floor(countRaw))) : 10;
  const db = getFirebaseDb();
  const batch = db.batch();
  const codes = [];
  const now = Date.now();

  while (codes.length < count) {
    const code = generateOneTimeRecoveryCode();
    const lookupHash = getOneTimeRecoveryLookupHash(code, secret);
    const argon2Hash = await hashOneTimeRecoveryCodeArgon2id(code);
    const ref = db.collection("a2fRecoveryCodes").doc(lookupHash);

    codes.push(code);
    batch.set(ref, {
      lookupHash,
      argon2Hash,
      hashType: "argon2id",
      hashParams: {
        memoryCost: ARGON2ID_OPTIONS.memoryCost,
        timeCost: ARGON2ID_OPTIONS.timeCost,
        parallelism: ARGON2ID_OPTIONS.parallelism,
        hashLength: ARGON2ID_OPTIONS.hashLength
      },
      codeFormat: "DG-RCV-10x5",
      randomLength: ONE_TIME_RECOVERY_RANDOM_LENGTH,
      used: false,
      revoked: false,
      label: `Recovery code ${codes.length}`,
      codePreview: code.slice(-5),
      createdByUid: decoded.uid,
      createdByEmail: decoded.email || process.env.A2F_ADMIN_EMAIL || "",
      createdAtMs: now,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      usedAtMs: null,
      usedAt: null,
      usedByUid: null,
      usedByEmail: null
    }, { merge: false });
  }

  await batch.commit();

  return codes;
}

async function sendEmailOtp(code) {
  const apiKey = process.env.BREVO_API_KEY;
  const adminEmail = process.env.A2F_ADMIN_EMAIL;
  const senderEmail = process.env.A2F_SENDER_EMAIL;

  if (!apiKey) throw new Error("BREVO_API_KEY belum diset");
  if (!adminEmail) throw new Error("A2F_ADMIN_EMAIL belum diset");
  if (!senderEmail) throw new Error("A2F_SENDER_EMAIL belum diset");

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": apiKey,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      sender: {
        name: "Dirac Admin",
        email: senderEmail
      },
      to: [
        {
          email: adminEmail,
          name: "Admin"
        }
      ],
      subject: "Kode A2F Tahap 3 Dirac Admin",
      htmlContent: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Kode A2F Tahap 3</h2>
          <p>Kode verifikasi kamu:</p>
          <div style="font-size:28px;font-weight:700;letter-spacing:4px">
            ${code}
          </div>
          <p>Kode berlaku 5 menit.</p>
          <p>Jika kamu tidak login, abaikan email ini.</p>
        </div>
      `,
      textContent: `Kode A2F tahap 3 kamu adalah: ${code}. Kode berlaku 5 menit.`
    })
  });

  const result = await response.text();

  if (!response.ok) {
    throw new Error(result || "Gagal kirim email OTP");
  }

  return result;
}

async function sendRecoveryEmailOtp(code, stepNumber) {
  const apiKey = process.env.BREVO_API_KEY;
  const adminEmail = process.env.A2F_RECOVERY_EMAIL || process.env.A2F_ADMIN_EMAIL;
  const senderEmail = process.env.A2F_SENDER_EMAIL;
  const recoveryStep = stepNumber - 5;

  if (!apiKey) throw new Error("BREVO_API_KEY belum diset");
  if (!adminEmail) throw new Error("A2F_RECOVERY_EMAIL atau A2F_ADMIN_EMAIL belum diset");
  if (!senderEmail) throw new Error("A2F_SENDER_EMAIL belum diset");

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "api-key": apiKey,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      sender: {
        name: "Dirac Admin",
        email: senderEmail
      },
      to: [
        {
          email: adminEmail,
          name: "Admin"
        }
      ],
      subject: `Kode Recovery Face ID Tahap ${recoveryStep} Dirac Admin`,
      htmlContent: `
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Kode Recovery Face ID Tahap ${recoveryStep}</h2>
          <p>Kode recovery kamu:</p>
          <div style="font-size:28px;font-weight:700;letter-spacing:4px">
            ${code}
          </div>
          <p>Kode berlaku 5 menit.</p>
          <p>Jika kamu tidak sedang recovery Face ID, abaikan email ini dan cek keamanan akun.</p>
        </div>
      `,
      textContent: `Kode Recovery Face ID tahap ${recoveryStep} kamu adalah: ${code}. Kode berlaku 5 menit.`
    })
  });

  const result = await response.text();

  if (!response.ok) {
    throw new Error(result || "Gagal kirim email recovery OTP");
  }

  return result;
}

function getRecoveryTotpSecret() {
  const envName = "A2F_RECOVERY_TOTP_SECRET_2";
  const secret = String(process.env[envName] || "").replace(/\s+/g, "").trim();

  if (!secret) {
    throw new Error(`${envName} belum diset di Vercel`);
  }

  if (secret.length < 16) {
    throw new Error(`${envName} terlalu pendek. Gunakan secret Base32 dari Authenticator.`);
  }

  return { envName };
}

function getRecoveryLocalCode(stepNumber) {
  const config = {
    8: {
      envName: "A2F_RECOVERY_STEP3_CODE",
      label: "Recovery Face ID tahap 3"
    },
    9: {
      envName: "A2F_RECOVERY_STEP4_CODE",
      label: "Recovery Face ID tahap 4"
    }
  };

  const item = config[stepNumber];
  if (!item) {
    throw new Error("Step recovery lokal tidak valid");
  }

  const code = String(process.env[item.envName] || "").trim();

  if (!code) {
    throw new Error(`${item.envName} belum diset di Vercel`);
  }

  if (code.length < 12 || code.length > 96) {
    throw new Error(`${item.envName} harus 12 sampai 96 karakter`);
  }

  return { code, label: item.label, envName: item.envName };
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

  const { step, action } = req.body || {};

  if (action === "generate-recovery-codes") {
    try {
      const codes = await generateOneTimeRecoveryCodes(req.body || {});

      return res.status(200).json({
        success: true,
        action,
        codes,
        count: codes.length,
        message: "Recovery code sekali pakai berhasil dibuat. Simpan sekarang karena kode asli tidak disimpan di server."
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal membuat recovery code sekali pakai"
      });
    }
  }

  const stepNumber = Number(step);
  const allowedSteps = [2, 3, 6, 7, 8, 9, 10];

  if (!allowedSteps.includes(stepNumber)) {
    return res.status(400).json({
      success: false,
      error: "Step harus 2, 3, 6, 7, 8, 9, atau 10"
    });
  }

  const secret = process.env.A2F_SECRET || "rahasia-test";
  const code = crypto.randomInt(100000, 999999).toString();

  const payload = {
    step: stepNumber,
    flow: stepNumber >= 6 ? "face-recovery" : "normal",
    codeHash: hashCode(`${stepNumber}:${code}`, secret),
    expiresAt: Date.now() + 5 * 60 * 1000,
    nonce: crypto.randomBytes(16).toString("hex")
  };

  if (stepNumber === 3) {
    const sessionId = makeSession(payload, secret);

    try {
      await sendEmailOtp(code);

      return res.status(200).json({
        success: true,
        sessionId,
        step: 3,
        message: "Kode A2F tahap 3 sudah dikirim ke email admin"
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal kirim email OTP"
      });
    }
  }

  if (stepNumber === 6) {
    const sessionId = makeSession(payload, secret);

    try {
      await sendRecoveryEmailOtp(code, stepNumber);

      return res.status(200).json({
        success: true,
        sessionId,
        step: stepNumber,
        recoveryStep: 1,
        delivery: "email",
        message: "Kode Recovery Face ID tahap 1 sudah dikirim ke email admin"
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal kirim email recovery OTP"
      });
    }
  }

  if (stepNumber === 7) {
    try {
      getRecoveryTotpSecret();

      const totpPayload = {
        ...payload,
        method: "recovery-totp",
        codeHash: hashCode(`${stepNumber}:recovery-totp`, secret)
      };
      const sessionId = makeSession(totpPayload, secret);

      return res.status(200).json({
        success: true,
        sessionId,
        step: stepNumber,
        recoveryStep: 2,
        delivery: "authenticator",
        message: "Recovery Face ID tahap 2 siap. Buka Authenticator recovery dan masukkan kode 6 digit."
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal menyiapkan Authenticator recovery"
      });
    }
  }

  if (stepNumber === 8 || stepNumber === 9) {
    try {
      const localRecovery = getRecoveryLocalCode(stepNumber);
      payload.method = "local-secret";
      payload.codeHash = hashCode(`${stepNumber}:${localRecovery.code}`, secret);

      const sessionId = makeSession(payload, secret);

      return res.status(200).json({
        success: true,
        sessionId,
        step: stepNumber,
        recoveryStep: stepNumber - 5,
        delivery: "local-secret",
        message: `${localRecovery.label} siap. Tidak ada email dikirim. Masukkan kode rahasia yang tersimpan di Vercel.`
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        error: error.message || "Gagal membuat kode recovery lokal"
      });
    }
  }

  if (stepNumber === 10) {
    payload.method = "one-time-recovery-code";
    payload.codeHash = hashCode(`${stepNumber}:one-time-recovery-code`, secret);

    const sessionId = makeSession(payload, secret);

    return res.status(200).json({
      success: true,
      sessionId,
      step: stepNumber,
      recoveryStep: 5,
      delivery: "one-time-code",
      message: "Recovery Face ID tahap 5 siap. Masukkan recovery code sekali pakai. Setelah benar, kode langsung hangus."
    });
  }

  const sessionId = makeSession(payload, secret);

  return res.status(200).json({
    success: true,
    sessionId,
    debugCode: code,
    step: 2,
    message: "Kode A2F tahap 2 dibuat"
  });
};
