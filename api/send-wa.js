export default async function handler(req, res) {

  // hanya izinkan POST
  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {

    // ambil data dari frontend
    const { target, message } = req.body;

    // kirim ke Fonnte
    const response = await fetch("https://api.fonnte.com/send", {
      method: "POST",
      headers: {
        "Authorization": process.env.FONNTE_TOKEN,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        target,
        message
      })
    });

    const data = await response.json();

    // kirim hasil balik ke frontend
    return res.status(200).json(data);

  } catch (error) {

    return res.status(500).json({
      error: error.message
    });

  }
}
