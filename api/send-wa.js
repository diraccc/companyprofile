export default async function handler(req, res) {
  try {
    const target = req.body?.target || "6287892523968";
    const message = req.body?.message || "TEST BERHASIL";
    const token = process.env.FONNTE_TOKEN;

    console.log("TOKEN:", token ? "ADA" : "KOSONG");

    const params = new URLSearchParams();
    params.append("target", target);
    params.append("message", message);

    const response = await fetch("https://api.fonnte.com/send", {
      method: "POST",
      headers: {
        Authorization: token,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: params.toString()
    });

    const data = await response.json();
    console.log("RESPONSE FONNTE:", data);
    return res.status(200).json(data);

  } catch (err) {
    console.error("ERROR:", err.message);
    return res.status(500).json({ error: err.message });
  }
}
