require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const mysql = require("mysql2");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static("uploads"));

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.log("Error DB:", err);
    return;
  }
  console.log("Base de datos conectada");
});


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage });

/* =========================
   HOME
========================= */
app.get("/", (req, res) => {
  res.send("Backend TVU funcionando ");
});

/* =========================
   ANALIZADOR URL
========================= */
function analyzeUrl(rawUrl) {
  const razones = [];
  let puntuacion = 0;

  const input = rawUrl.trim();
  let parsed;

  try {
    parsed = new URL(input.startsWith("http") ? input : "http://" + input);
  } catch {
    return {
      riesgo: "alto",
      puntuacion: 90,
      resumen: "La URL no tiene un formato válido.",
      razones: ["No se pudo interpretar como una URL válida"],
      recomendacion: "Verifica que el enlace esté completo y bien escrito.",
    };
  }

  const protocolo = parsed.protocol;
  const hostname = parsed.hostname;
  const pathname = parsed.pathname;
  const fullUrl = input;

  if (protocolo === "http:") {
    puntuacion += 30;
    razones.push("Usa HTTP en vez de HTTPS — la conexión no está cifrada.");
  }

  const partes = hostname.split(".");
  if (partes.length > 4) {
    puntuacion += 20;
    razones.push(
      `Demasiados subdominios (${partes.length - 2}) — táctica común para disfrazar el dominio real.`
    );
  } else if (partes.length === 4) {
    puntuacion += 10;
    razones.push(
      "Tiene subdominios adicionales que pueden intentar imitar un sitio legítimo."
    );
  }

  if (fullUrl.length > 100) {
    puntuacion += 15;
    razones.push(
      `URL muy larga (${fullUrl.length} caracteres) — los enlaces legítimos suelen ser cortos.`
    );
  }

  const dominioBase = partes.slice(-2).join(".");
  const guiones = (dominioBase.match(/-/g) || []).length;

  if (guiones >= 2) {
    puntuacion += 20;
    razones.push(
      `El dominio tiene ${guiones} guiones — patrón frecuente en sitios falsos.`
    );
  } else if (guiones === 1) {
    puntuacion += 5;
    razones.push(
      "El dominio contiene un guion, lo cual puede ser sospechoso."
    );
  }

  const palabrasPhishing = [
    "login",
    "signin",
    "verify",
    "account",
    "secure",
    "update",
    "banking",
    "password",
    "credential",
    "confirm",
    "wallet",
    "paypal",
    "amazon",
    "google",
    "microsoft",
    "apple",
    "facebook",
    "seguro",
    "banco",
    "clave",
    "verificar",
    "actualizar",
  ];

  const urlLower = fullUrl.toLowerCase();
  const encontradas = palabrasPhishing.filter((p) =>
    urlLower.includes(p)
  );

  if (encontradas.length >= 2) {
    puntuacion += 25;
    razones.push(
      `Contiene palabras sospechosas: "${encontradas.join('", "')}".`
    );
  } else if (encontradas.length === 1) {
    puntuacion += 10;
    razones.push(
      `Contiene palabra sospechosa "${encontradas[0]}".`
    );
  }

  const caracteresRaros = /[àáâãäåæçèéêëìíîïðñòóôõöùúûüýþÿ@]/i;
  if (caracteresRaros.test(hostname)) {
    puntuacion += 30;
    razones.push(
      "El dominio contiene caracteres especiales sospechosos."
    );
  }

  const esIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  if (esIp) {
    puntuacion += 35;
    razones.push(
      "El enlace usa IP directa en vez de dominio."
    );
  }

  puntuacion = Math.min(puntuacion, 100);

  let riesgo = "seguro";
  let resumen = "No se encontraron señales de riesgo.";
  let recomendacion =
    "El enlace parece seguro.";

  if (puntuacion >= 60) {
    riesgo = "alto";
    resumen =
      "Este enlace presenta múltiples señales de phishing.";
    recomendacion =
      "No ingreses datos personales ni hagas clic.";
  } else if (puntuacion >= 35) {
    riesgo = "medio";
    resumen =
      "El enlace tiene características sospechosas.";
    recomendacion =
      "Verifica la fuente antes de interactuar.";
  } else if (puntuacion >= 10) {
    riesgo = "bajo";
    resumen =
      "El enlace parece mayormente seguro.";
    recomendacion =
      "Procede con precaución.";
  }

  if (razones.length === 0) {
    razones.push("Usa HTTPS correctamente.");
    razones.push("No contiene patrones sospechosos.");
    razones.push("Estructura normal.");
  }

  return {
    riesgo,
    puntuacion,
    resumen,
    razones,
    recomendacion,
  };
}


app.post("/api/analyze", (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({
      error: "URL requerida",
    });
  }

  const result = analyzeUrl(url);
  return res.json(result);
});


app.post(
  "/api/reports",
  upload.single("file"),
  (req, res) => {
    try {
      const {
        senderEmail,
        subject,
        suspiciousLink,
        priority,
        comments,
      } = req.body;

      const filePath = req.file
        ? req.file.path
        : null;

      const sql = `
        INSERT INTO reportes
        (
          correo_remitente,
          asunto,
          enlace_sospechoso,
          prioridad,
          comentarios,
          ruta_archivo
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `;

      db.query(
        sql,
        [
          senderEmail || null,
          subject || null,
          suspiciousLink || null,
          priority || "Media",
          comments || null,
          filePath,
        ],
        (err, result) => {
          if (err) {
            console.log(err);
            return res.status(500).json({
              message:
                "Error guardando reporte",
            });
          }

          res.status(201).json({
            message:
              "Reporte enviado correctamente",
            id: result.insertId,
          });
        }
      );
    } catch (error) {
      console.log(error);
      res.status(500).json({
        message:
          "Error interno del servidor",
      });
    }
  }
);


app.listen(PORT, () => {
  console.log(
    `Servidor TVU corriendo en http://localhost:${PORT}`
  );
});