export default async function handler(req, res) {
  const { target, message } = req.body;

  const formData = new FormData();
  formData.append("target", target || "6287892523968");
  formData.append("message", message || "TEST BERHASIL");

  const response = await fetch("https://api.fonnte.com/send", {
    method: "POST",
    headers: {
      Authorization: process.env.FONNTE_TOKEN,
      // ❌ Hapus Content-Type, biar FormData yang atur otomatis
    },
    body: formData
  });

  const data = await response.json();
  return res.status(200).json(data);
}
