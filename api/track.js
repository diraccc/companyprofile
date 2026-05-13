const AFTERSHIP_BASE_URL = "https://api.aftership.com/tracking/2026-01";

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
    if (value.name) return cleanText(value.name, fallback);
    if (value.value) return cleanText(value.value, fallback);
    if (value.text) return cleanText(value.text, fallback);
    return fallback;
  }

  const text = String(value).trim();
  return text || fallback;
}

function getSlug(courier) {
  const key = cleanText(courier).toLowerCase();

  if (key === "spx") return "spx";
  if (key === "shopee") return "spx";
  if (key === "shopee-express") return "spx";
  if (key === "shopee express") return "spx";

  // Selain SPX biarkan AfterShip auto-detect.
  return "";
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function afterShipRequest(path, options) {
  const response = await fetch(`${AFTERSHIP_BASE_URL}${path}`, options);
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message =
      payload?.message ||
      payload?.error ||
      payload?.meta?.message ||
      payload?.errors?.[0]?.message ||
      `AfterShip error ${response.status}`;

    const error = new Error(message);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }

  return payload;
}

function extractTracking(payload) {
  if (payload?.data?.tracking) return payload.data.tracking;
  if (Array.isArray(payload?.data?.trackings)) return payload.data.trackings[0] || null;
  if (payload?.tracking) return payload.tracking;
  if (Array.isArray(payload?.trackings)) return payload.trackings[0] || null;
  if (Array.isArray(payload?.data)) return payload.data[0] || null;
  return payload?.data || payload || null;
}

function isUsefulTracking(tracking) {
  if (!tracking) return false;

  const tag = cleanText(tracking.tag).toLowerCase();
  const subtag = cleanText(tracking.subtag).toLowerCase();
  const checkpoints = Array.isArray(tracking.checkpoints) ? tracking.checkpoints : [];

  if (tag === "delivered") return true;
  if (subtag.includes("delivered")) return true;
  if (checkpoints.length > 0) return true;

  return false;
}

function mapStatus(tracking) {
  const tag = cleanText(tracking?.tag);
  const subtag = cleanText(tracking?.subtag);
  const subtagMessage = cleanText(tracking?.subtag_message);

  const checkpoints = Array.isArray(tracking?.checkpoints) ? tracking.checkpoints : [];
  const latestCheckpoint = checkpoints[checkpoints.length - 1] || {};
  const latestMessage = cleanText(
    latestCheckpoint.checkpoint_message ||
    latestCheckpoint.message ||
    latestCheckpoint.subtag_message ||
    latestCheckpoint.tag
  );

  const text = `${tag} ${subtag} ${subtagMessage} ${latestMessage}`.toLowerCase();

  if (/delivered|terkirim|telah diterima|received by|your parcel has been delivered/.test(text)) {
    return "Paket telah diterima";
  }

  if (/outfordelivery|out for delivery|being delivered by courier|with courier|kurir|diantar/.test(text)) {
    return "Paket sedang dikirim kurir";
  }

  if (/intransit|transit|departed|forwarded|perjalanan|menuju|on the way/.test(text)) {
    return "Paket dalam perjalanan";
  }

  if (/availableforpickup|available for pickup|siap diambil/.test(text)) {
    return "Paket siap diambil";
  }

  if (/attemptfail|attempt fail|failed/.test(text)) {
    return "Percobaan pengiriman gagal";
  }

  if (/exception|return/.test(text)) {
    return "Pengiriman terkendala";
  }

  if (/inforeceived|info received|pending|created/.test(text)) {
    return "Paket sedang diproses";
  }

  return cleanText(subtagMessage || tag || latestMessage, "Status tidak tersedia");
}

function mapCheckpoint(checkpoint) {
  return {
    manifest_description:
      cleanText(
        checkpoint.checkpoint_message ||
        checkpoint.message ||
        checkpoint.subtag_message ||
        checkpoint.tag,
        "Aktivitas pengiriman"
      ),

    city_name:
      cleanText(
        checkpoint.location ||
        checkpoint.city ||
        checkpoint.state ||
        checkpoint.country_region ||
        checkpoint.country_name,
        "Lokasi tidak tersedia"
      ),

    manifest_date:
      cleanText(
        checkpoint.checkpoint_time ||
        checkpoint.created_at ||
        checkpoint.updated_at,
        "Waktu tidak tersedia"
      ),

    manifest_time: ""
  };
}

function normalizeAfterShip(tracking, input) {
  const checkpoints = Array.isArray(tracking?.checkpoints) ? tracking.checkpoints : [];
  const latestCheckpoint = checkpoints[checkpoints.length - 1] || {};
  const statusText = mapStatus(tracking);

  return {
    success: true,

    summary: {
      awb: cleanText(tracking?.tracking_number, input.awb),
      courier: cleanText(tracking?.slug, input.courier || "AfterShip"),
      status: statusText,
      status_text: statusText,
      waybill_date:
        cleanText(
          tracking?.shipment_pickup_date ||
          tracking?.created_at ||
          latestCheckpoint.checkpoint_time,
          ""
        ),
      estimate:
        cleanText(
          tracking?.courier_estimated_delivery_date?.estimated_delivery_date ||
          tracking?.estimated_delivery_date ||
          tracking?.expected_delivery ||
          tracking?.aftership_estimated_delivery_date,
          ""
        )
    },

    delivery_status: {
      status: statusText,
      pod_receiver:
        cleanText(
          tracking?.signed_by ||
          tracking?.customer_name,
          ""
        )
    },

    details: {
      origin:
        cleanText(
          tracking?.origin_city ||
          tracking?.origin_state ||
          tracking?.origin_country_region ||
          tracking?.origin_country_iso3,
          ""
        ),

      destination:
        cleanText(
          tracking?.destination_city ||
          tracking?.destination_state ||
          tracking?.destination_country_region ||
          tracking?.destination_country_iso3,
          ""
        )
    },

    manifest: checkpoints.slice().reverse().map(mapCheckpoint),

    raw_aftership: tracking
  };
}

async function getExistingTracking({ apiKey, awb, courier }) {
  const slug = getSlug(courier);

  const params = new URLSearchParams();
  params.set("tracking_numbers", awb);
  params.set("limit", "1");

  if (slug) {
    params.set("slug", slug);
  }

  const payload = await afterShipRequest(`/trackings?${params.toString()}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      "as-api-key": apiKey
    }
  });

  return extractTracking(payload);
}

async function createTracking({ apiKey, awb, courier }) {
  const slug = getSlug(courier);

  const body = {
    tracking_number: awb,
    title: awb
  };

  if (slug) {
    body.slug = slug;
  }

  const payload = await afterShipRequest("/trackings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "as-api-key": apiKey
    },
    body: JSON.stringify(body)
  });

  return extractTracking(payload);
}

async function getBestTrackingData({ apiKey, awb, courier }) {
  // 1. Cek data yang sudah ada dulu.
  let tracking = await getExistingTracking({ apiKey, awb, courier }).catch(() => null);

  if (isUsefulTracking(tracking)) {
    return tracking;
  }

  // 2. Kalau belum ada, baru create tracking.
  try {
    tracking = await createTracking({ apiKey, awb, courier });
  } catch (error) {
    const msg = cleanText(error.message).toLowerCase();

    // Kalau tracking sudah pernah dibuat, ambil ulang data existing.
    if (!msg.includes("already") && !msg.includes("duplicate") && !msg.includes("exist")) {
      throw error;
    }
  }

  // 3. Setelah create, jangan langsung percaya response pertama.
  //    Tunggu dan ambil ulang supaya tidak berhenti di Pending/Paket dibuat.
  for (let attempt = 0; attempt < 4; attempt++) {
    await sleep(1200);

    const refreshed = await getExistingTracking({ apiKey, awb, courier }).catch(() => null);

    if (isUsefulTracking(refreshed)) {
      return refreshed;
    }

    if (refreshed) {
      tracking = refreshed;
    }
  }

  return tracking;
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
    const apiKey = process.env.AFTERSHIP_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        success: false,
        message: "AFTERSHIP_API_KEY belum diset di Vercel Environment Variables."
      });
    }

    const body = readBody(req);

    const awb = cleanText(
      body.awb ||
      body.resi ||
      body.tracking_number
    );

    const courier = cleanText(
      body.courier ||
      body.slug
    );

    if (!awb) {
      return res.status(400).json({
        success: false,
        message: "Nomor resi tidak boleh kosong."
      });
    }

    const tracking = await getBestTrackingData({
      apiKey,
      awb,
      courier
    });

    if (!tracking) {
      return res.status(404).json({
        success: false,
        message: "Data tracking belum ditemukan dari AfterShip."
      });
    }

    return res.status(200).json(
      normalizeAfterShip(tracking, {
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
