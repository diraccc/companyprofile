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
  const text = String(value).trim();
  return text || fallback;
}

function getSlug(courier) {
  const key = cleanText(courier).toLowerCase();

  if (key === "spx") return "spx";
  if (key === "shopee") return "spx";
  if (key === "shopee-express") return "spx";
  if (key === "shopee express") return "spx";

  // Untuk kurir selain SPX, biarkan AfterShip auto-detect.
  return "";
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
  if (payload?.tracking) return payload.tracking;
  if (payload?.data?.trackings?.[0]) return payload.data.trackings[0];
  if (payload?.trackings?.[0]) return payload.trackings[0];
  if (Array.isArray(payload?.data) && payload.data[0]) return payload.data[0];
  return payload?.data || payload || {};
}

function mapStatus(tag, subtag, subtagMessage) {
  const text = `${tag || ""} ${subtag || ""} ${subtagMessage || ""}`.toLowerCase();

  if (text.includes("delivered")) return "Paket telah diterima";
  if (text.includes("outfordelivery") || text.includes("out for delivery")) return "Paket sedang dikirim kurir";
  if (text.includes("intransit") || text.includes("transit")) return "Paket dalam perjalanan";
  if (text.includes("inforeceived")) return "Data pengiriman diterima";
  if (text.includes("pending")) return "Paket sedang diproses";
  if (text.includes("availableforpickup")) return "Paket siap diambil";
  if (text.includes("attemptfail")) return "Percobaan pengiriman gagal";
  if (text.includes("exception")) return "Pengiriman terkendala";
  if (text.includes("expired")) return "Tracking kedaluwarsa";

  return cleanText(subtagMessage || tag || subtag, "Status tidak tersedia");
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

function normalizeAfterShip(tracking, input) {
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
        tracking.courier_estimated_delivery_date?.estimated_delivery_date ||
        tracking.estimated_delivery_date ||
        tracking.expected_delivery ||
        tracking.aftership_estimated_delivery_date ||
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

async function createTracking({ apiKey, awb, courier }) {
  const slug = getSlug(courier);

  const body = {
    tracking_number: awb,
    title: awb
  };

  // SPX wajib pakai slug spx.
  // Selain SPX dikosongkan agar AfterShip auto-detect.
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

async function findExistingTracking({ apiKey, awb, courier }) {
  const slug = getSlug(courier);

  const params = new URLSearchParams();
  params.set("tracking_numbers", awb);

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

  const tracking = extractTracking(payload);

  if (!tracking || !tracking.tracking_number) {
    throw new Error("Tracking sudah pernah dibuat, tetapi data existing tidak ditemukan.");
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

    let tracking;

    try {
      tracking = await createTracking({
        apiKey,
        awb,
        courier
      });
    } catch (error) {
      const errorText = cleanText(error.message).toLowerCase();

      if (
        errorText.includes("already") ||
        errorText.includes("duplicate") ||
        errorText.includes("exist")
      ) {
        tracking = await findExistingTracking({
          apiKey,
          awb,
          courier
        });
      } else {
        throw error;
      }
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
