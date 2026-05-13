const RAJAONGKIR_BASE_URL = "https://rajaongkir.komerce.id/api/v1";

function readBody(req) {
  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }

  return req.body || {};
}

function cleanText(value, fallback = "") {
  if (value === null || value === undefined) return fallback;

  if (typeof value === "object") {
    if (value.message) return cleanText(value.message, fallback);
    if (value.status) return cleanText(value.status, fallback);
    if (value.text) return cleanText(value.text, fallback);
    if (value.name) return cleanText(value.name, fallback);
    return fallback;
  }

  const text = String(value).trim();
  return text || fallback;
}

function normalizeCourier(courier) {
  const key = cleanText(courier).toLowerCase();

  const map = {
    jne: "jne",
    jnt: "jnt",
    "j&t": "jnt",
    sicepat: "sicepat",
    anteraja: "anteraja",
    pos: "pos",
    tiki: "tiki",
    wahana: "wahana",
    ninja: "ninja",
    lion: "lion",
    sap: "sap",
    ide: "ide",
    first: "first"
  };

  return map[key] || key;
}

function mapStatus(payload) {
  const data = payload?.data || {};
  const summary = data.summary || {};
  const delivery = data.delivery_status || {};
  const delivered = data.delivered === true;

  const raw = [
    summary.status,
    delivery.status,
    delivery.pod_receiver,
    ...(Array.isArray(data.manifest)
      ? data.manifest.map((item) => item.manifest_description)
      : [])
  ]
    .filter(Boolean)
    .join(" | ")
    .toLowerCase();

  if (
    delivered ||
    /delivered|terkirim|telah diterima|sudah diterima|diterima oleh|received|pod/.test(raw)
  ) {
    return "Paket telah diterima";
  }

  if (/kurir|antar|diantar|with delivery courier|out for delivery/.test(raw)) {
    return "Paket sedang dikirim kurir";
  }

  if (/tiba|destination|kota tujuan|hub tujuan/.test(raw)) {
    return "Paket tiba di kota tujuan";
  }

  if (/transit|perjalanan|dikirim|departed|forwarded|manifest/.test(raw)) {
    return "Paket dalam perjalanan";
  }

  if (/pickup|picked up|received at|diterima ekspedisi|accepted/.test(raw)) {
    return "Paket diterima ekspedisi";
  }

  if (/created|booking|entry|pending/.test(raw)) {
    return "Paket dibuat";
  }

  return cleanText(summary.status || delivery.status, "Status tidak tersedia");
}

function normalizeRajaOngkir(payload, input) {
  const data = payload?.data || {};
  const summary = data.summary || {};
  const details = data.details || {};
  const delivery = data.delivery_status || {};
  const manifest = Array.isArray(data.manifest) ? data.manifest : [];

  const statusText = mapStatus(payload);

  return {
    success: true,

    summary: {
      awb:
        summary.waybill_number ||
        details.waybill_number ||
        input.awb,

      courier:
        summary.courier_name ||
        summary.courier_code ||
        input.courier,

      status: statusText,
      status_text: statusText,

      waybill_date:
        summary.waybill_date ||
        details.waybill_date ||
        "",

      estimate:
        summary.estimate ||
        summary.estimation ||
        ""
    },

    delivery_status: {
      status: statusText,
      pod_receiver:
        delivery.pod_receiver ||
        details.receiver_name ||
        summary.receiver_name ||
        "",
      pod_date: delivery.pod_date || "",
      pod_time: delivery.pod_time || ""
    },

    details: {
      origin:
        summary.origin ||
        details.origin ||
        details.shipper_city ||
        "",

      destination:
        summary.destination ||
        details.destination ||
        details.receiver_city ||
        ""
    },

    manifest: manifest.map((item) => ({
      manifest_description:
        item.manifest_description ||
        item.description ||
        "Aktivitas pengiriman",

      city_name:
        item.city_name ||
        item.city ||
        "Lokasi tidak tersedia",

      manifest_date:
        item.manifest_date ||
        item.date ||
        "Waktu tidak tersedia",

      manifest_time:
        item.manifest_time ||
        item.time ||
        ""
    })),

    raw_rajaongkir: payload
  };
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed. Gunakan POST."
    });
  }

  try {
    const apiKey = process.env.RAJAONGKIR_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        success: false,
        message: "RAJAONGKIR_API_KEY belum diset di Vercel Environment Variables."
      });
    }

    const body = readBody(req);

    const awb = cleanText(
      body.awb ||
      body.resi ||
      body.tracking_number
    );

    const courier = normalizeCourier(
      body.courier ||
      body.slug
    );

    const lastPhoneNumber = cleanText(
      body.last_phone_number ||
      body.phone_last ||
      body.phoneLast
    );

    if (!awb) {
      return res.status(400).json({
        success: false,
        message: "Nomor resi tidak boleh kosong."
      });
    }

    if (!courier) {
      return res.status(400).json({
        success: false,
        message: "Ekspedisi tidak boleh kosong."
      });
    }

    const params = new URLSearchParams();
    params.set("awb", awb);
    params.set("courier", courier);

    if (lastPhoneNumber) {
      params.set("last_phone_number", lastPhoneNumber);
    }

    const response = await fetch(
      `${RAJAONGKIR_BASE_URL}/track/waybill?${params.toString()}`,
      {
        method: "POST",
        headers: {
          key: apiKey,
          Accept: "application/json"
        }
      }
    );

    const payload = await response.json().catch(() => null);

    if (!payload) {
      return res.status(502).json({
        success: false,
        message: "RajaOngkir tidak mengirim response JSON yang valid."
      });
    }

    const metaCode = Number(payload?.meta?.code || response.status);
    const metaStatus = cleanText(payload?.meta?.status).toLowerCase();
    const metaMessage = cleanText(payload?.meta?.message);

    if (!response.ok || metaCode >= 400 || metaStatus === "error" || payload?.data === null) {
      return res.status(metaCode >= 400 ? metaCode : 400).json({
        success: false,
        message:
          metaMessage ||
          "Resi tidak ditemukan atau ekspedisi tidak sesuai.",
        raw_rajaongkir: payload
      });
    }

    return res.status(200).json(
      normalizeRajaOngkir(payload, {
        awb,
        courier
      })
    );
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message || "Terjadi kesalahan saat cek resi."
    });
  }
}
