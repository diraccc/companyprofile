const crypto = require("crypto");

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

  const { step } = req.body || {};
  const stepNumber = Number(step);
  const allowedSteps = [2, 3, 6, 7, 8, 9];

  if (!allowedSteps.includes(stepNumber)) {
    return res.status(400).json({
      success: false,
      error: "Step harus 2, 3, 6, 7, 8, atau 9"
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

  const sessionId = makeSession(payload, secret);

  return res.status(200).json({
    success: true,
    sessionId,
    debugCode: code,
    step: 2,
    message: "Kode A2F tahap 2 dibuat"
  });
};
