module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { awb, courier, last_phone_number } = req.body || {};

  if (!awb || !courier) {
    return res.status(400).json({
      error: "Nomor resi dan kurir wajib diisi"
    });
  }

  const params = new URLSearchParams({
    awb,
    courier
  });

  if (last_phone_number) {
    params.append("last_phone_number", last_phone_number);
  }

  const response = await fetch(
    `https://rajaongkir.komerce.id/api/v1/track/waybill?${params.toString()}`,
    {
      method: "POST",
      headers: {
        key: process.env.RAJAONGKIR_API_KEY
      }
    }
  );

  const data = await response.json();

  return res.status(response.status).json(data);
};
