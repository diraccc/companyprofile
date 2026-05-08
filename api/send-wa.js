export default async function handler(req, res) {

  const response = await fetch("https://api.fonnte.com/send", {
    method: "POST",
    headers: {
      Authorization: process.env.FONNTE_TOKEN,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      target: "6287892523968",
      message: "TEST BERHASIL"
    })
  });

  const data = await response.json();

  return res.status(200).json(data);
}
