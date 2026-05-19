const { generateRegistrationOptions } = require("@simplewebauthn/server");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
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

  const options = await generateRegistrationOptions({
    rpName: "Dirac Admin",
    rpID,
    userName: "admin@diracgroup.store",
    userDisplayName: "Dirac Admin",
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred"
    }
  });

  return res.status(200).json({
    success: true,
    options
  });
};
