const AFTERSHIP_BASE_URL = "https://api.aftership.com/tracking/2026-01";

const FORCE_SLUG_MAP = {
  spx: "spx",
  shopee: "spx",
  "shopee-express": "spx",
  "shopee express": "spx"
};

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
  const text = String(value).trim();
  return text || fallback;
}

function normalizeCourierSlug(courier) {
  const key = cleanText(courier).toLowerCase();
  return FORCE_SLUG_MAP[key] || "";
}

function getAfterShipTracking(payload) {
  return (
    payload?.data?.tracking ||
    payload?.tracking ||
    payload?.data ||
    payload ||
    {}
  );
}

function mapStatus(tag, subtag, message) {
  const raw = `${tag || ""} ${subtag || ""} ${message || ""}`.toLowerCase();

  if (raw.includes("delivered")) return "Paket telah diterima";
  if (raw.includes("outfordelivery") || raw.includes("out for delivery")) return "Paket sedang dikirim kurir";
  if (raw.includes("intransit") || raw.includes("transit")) return "Paket dalam perjalanan";
  if (raw.includes("availableforpickup")) return "Paket siap diambil";
  if (raw.includes("exception") || raw.includes("failed")) return "Pengiriman terkendala";
  if (raw.includes("pending") || raw.includes("info")) return "Paket sedang diproses";

  return cleanText(message || tag || subtag, "Status tidak tersedia");
}

function mapCheckpoint(checkpoint) {
  return {
    manifest_description:
      checkpoint.checkpoint_message ||
      checkpoint.message ||
      checkpoint.subtag_message ||
      checkpoint.tag ||
      "Aktivitas pengiriman",

    city_name:
      checkpoint.location ||
      checkpoint.city ||
      checkpoint.state ||
      checkpoint.country_region ||
      checkpoint.country_name ||
      "Lokasi tidak tersedia",

    manifest_date:
      checkpoint.checkpoint_time ||
      checkpoint.created_at ||
      checkpoint.updated_at ||
      "Waktu tidak tersedia",

    manifest_time: ""
  };
}

function normalizeAfterShipResponse(tracking, input) {
  const checkpoints = Array.isArray(tracking.checkpoints)
    ? tracking.checkpoints
    : [];

  const latestCheckpoint = checkpoints[checkpoints.length - 1] || {};
  const statusText = mapStatus(
    tracking.tag,
    tracking.subtag,
    tracking.subtag_message
  );

  return {
    success: true,

    summary: {
      awb: tracking.tracking_number || input.awb,
      courier: tracking.slug || input.courier || "AfterShip",
      status: statusText,
      status_text: statusText,
      waybill_date:
        tracking.shipment_pickup_date ||
        tracking.created_at ||
        latestCheckpoint.checkpoint_time ||
        "",
      estimate:
        tracking.estimated_delivery_date ||
        tracking.expected_delivery ||
        tracking.aftership_estimated_delivery_date ||
        tracking.courier_estimated_delivery_date?.estimated_delivery_date ||
        ""
    },

    delivery_status: {
      status: statusText,
      pod_receiver:
        tracking.signed_by ||
        tracking.customer_name ||
        ""
    },

    details: {
      origin:
        tracking.origin_city ||
        tracking.origin_state ||
        tracking.origin_country_region ||
        tracking.origin_country_iso3 ||
        "",

      destination:
        tracking.destination_city ||
        tracking.destination_state ||
        tracking.destination_country_region ||
        tracking.destination_country_iso3 ||
        ""
    },

    manifest: checkpoints.slice().reverse().map(mapCheckpoint),

    raw_aftership: tracking
  };
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

async function createTracking({ apiKey, awb, courier }) {
  const slug = normalizeCourierSlug(courier);

  const body = {
    tracking_number: awb,
    title: awb
  };

  // Untuk SPX/Shopee Express, slug dipaksa "spx".
  // Untuk kurir lain, slug dikosongkan agar AfterShip auto-detect.
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

  return getAfterShipTracking(payload);
}

async function getTracking({ apiKey, slug, awb }) {
  const safeSlug = encodeURIComponent(slug);
  const safeAwb = encodeURIComponent(awb);

  const payload = await afterShipRequest(`/trackings/${safeSlug}/${safeAwb}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      "as-api-key": apiKey
    }
  });

  return getAfterShipTracking(payload);
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
    const awb = cleanText(body.awb || body.resi || body.tracking_number);
    const courier = cleanText(body.courier || body.slug);

    if (!awb) {
      return res.status(400).json({
        success: false,
        message: "Nomor resi tidak boleh kosong."
      });
    }

    let tracking;

    try {
      tracking = await createTracking({ apiKey, awb, courier });
    } catch (error) {
      const message = cleanText(error.message).toLowerCase();

      // Kalau tracking sudah pernah dibuat di AfterShip, ambil data existing.
      if (
        error.status === 400 &&
        (message.includes("already exists") ||
          message.includes("duplicate") ||
          message.includes("tracking already exists"))
      ) {
        const slug = normalizeCourierSlug(courier);

        if (!slug) {
          throw new Error("Tracking sudah ada, tetapi slug kurir tidak tersedia untuk mengambil ulang data.");
        }

        tracking = await getTracking({ apiKey, slug, awb });
      } else {
        throw error;
      }
    }

    return res.status(200).json(
      normalizeAfterShipResponse(tracking, {
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
