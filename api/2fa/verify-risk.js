const crypto = require("crypto");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A, B);
}

function getJakartaHour() {
  const parts = new Intl.DateTimeFormat("id-ID", {
    timeZone: "Asia/Jakarta",
    hour: "2-digit",
    hour12: false
  }).formatToParts(new Date());

  const hour = parts.find((p) => p.type === "hour")?.value;
  return Number(hour);
}

function isHourAllowed(hour, start, end) {
  if (start <= end) {
    return hour >= start && hour <= end;
  }

  return hour >= start || hour <= end;
}

module.exports = function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method tidak diizinkan"
    });
  }

  const { deviceToken } = req.body || {};

  const start = Number(process.env.A2F_TIME_START || 6);
  const end = Number(process.env.A2F_TIME_END || 23);
  const trustedToken = process.env.A2F_DEVICE_TOKEN;

  if (!trustedToken) {
    return res.status(500).json({
      success: false,
      error: "A2F_DEVICE_TOKEN belum diset di Vercel"
    });
  }

  const currentHour = getJakartaHour();

  if (!isHourAllowed(currentHour, start, end)) {
    return res.status(403).json({
      success: false,
      error: `Login ditolak. Diizinkan hanya jam ${start}:00 sampai ${end}:59 WIB.`
    });
  }

  if (!deviceToken) {
    return res.status(401).json({
      success: false,
      error: "Device belum dipercaya. Masukkan device token admin."
    });
  }

  if (!safeEqual(String(deviceToken).trim(), String(trustedToken).trim())) {
    return res.status(401).json({
      success: false,
      error: "Device token salah. Device tidak dipercaya."
    });
  }

  return res.status(200).json({
    success: true,
    message: "Device trusted dan waktu login diizinkan",
    currentHour,
    timeRange: `${start}:00-${end}:59 WIB`
  });
};
