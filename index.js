const express = require("express");
const cors = require("cors");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Backend TVU funcionando ✓");
});

// ── Reglas heurísticas ─────────────────────────────────────

function analyzeUrl(rawUrl) {
  const razones = [];
  let puntuacion = 0;

  // Normalizar: agregar protocolo si falta para poder parsear
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

  const protocolo = parsed.protocol;          // "http:" o "https:"
  const hostname  = parsed.hostname;          // "sub.dominio.com"
  const pathname  = parsed.pathname;          // "/ruta/página"
  const fullUrl   = input;

  // ── Regla 1: HTTP sin S ──────────────────────────────────
  if (protocolo === "http:") {
    puntuacion += 30;
    razones.push("Usa HTTP en vez de HTTPS — la conexión no está cifrada.");
  }

  // ── Regla 2: Muchos subdominios ──────────────────────────
  const partes = hostname.split(".");
  if (partes.length > 4) {
    puntuacion += 20;
    razones.push(`Demasiados subdominios (${partes.length - 2}) — táctica común para disfrazar el dominio real.`);
  } else if (partes.length === 4) {
    puntuacion += 10;
    razones.push("Tiene subdominios adicionales que pueden intentar imitar un sitio legítimo.");
  }

  // ── Regla 3: URL muy larga ───────────────────────────────
  if (fullUrl.length > 100) {
    puntuacion += 15;
    razones.push(`URL muy larga (${fullUrl.length} caracteres) — los enlaces legítimos suelen ser cortos.`);
  }

  // ── Regla 4: Guiones excesivos en el dominio ─────────────
  const dominioBase = partes.slice(-2).join(".");
  const guiones = (dominioBase.match(/-/g) || []).length;
  if (guiones >= 2) {
    puntuacion += 20;
    razones.push(`El dominio tiene ${guiones} guiones — patrón frecuente en sitios falsos (ej: banco-seguro-login.com).`);
  } else if (guiones === 1) {
    puntuacion += 5;
    razones.push("El dominio contiene un guion, lo cual puede ser sospechoso según el contexto.");
  }

  // ── Regla 5: Palabras clave de phishing ──────────────────
  const palabrasPhishing = [
    "login", "signin", "verify", "account", "secure", "update",
    "banking", "password", "credential", "confirm", "wallet",
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "seguro", "banco", "clave", "verificar", "actualizar", "soporte",
  ];
  const urlLower = fullUrl.toLowerCase();
  const encontradas = palabrasPhishing.filter((p) => urlLower.includes(p));
  if (encontradas.length >= 2) {
    puntuacion += 25;
    razones.push(`Contiene palabras de alerta: "${encontradas.join('", "')}".`);
  } else if (encontradas.length === 1) {
    puntuacion += 10;
    razones.push(`Contiene la palabra sospechosa "${encontradas[0]}".`);
  }

  // ── Regla 6: Caracteres engañosos (homógrafos) ───────────
  const caracteresRaros = /[àáâãäåæçèéêëìíîïðñòóôõöùúûüýþÿ@]/i;
  if (caracteresRaros.test(hostname)) {
    puntuacion += 30;
    razones.push("El dominio contiene caracteres especiales o no estándar que imitan letras normales.");
  }

  // ── Regla 7: IP en vez de dominio ────────────────────────
  const esIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  if (esIp) {
    puntuacion += 35;
    razones.push("El enlace usa una dirección IP directa en vez de un nombre de dominio — muy inusual en sitios legítimos.");
  }

  // ── Regla 8: Extensión de dominio sospechosa ─────────────
  const tldSospechosos = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan", ".work"];
  const tldActual = "." + partes[partes.length - 1];
  if (tldSospechosos.includes(tldActual)) {
    puntuacion += 20;
    razones.push(`Extensión de dominio "${tldActual}" es frecuentemente usada en sitios maliciosos por ser gratuita.`);
  }

  // ── Regla 9: Ruta con palabras sensibles ─────────────────
  const rutaSospechosa = /(login|verify|update|password|account|secure|admin|wp-admin)/i;
  if (rutaSospechosa.test(pathname)) {
    puntuacion += 10;
    razones.push("La ruta del enlace contiene palabras asociadas a páginas de acceso o administración.");
  }

  // ── Regla 10: Doble punto en dominio (typosquatting) ─────
  if (/\.{2,}/.test(hostname)) {
    puntuacion += 25;
    razones.push("El dominio tiene puntos consecutivos — formato inválido o intento de confusión.");
  }

  // ── Calcular nivel ───────────────────────────────────────
  puntuacion = Math.min(puntuacion, 100);

  let riesgo;
  let resumen;
  let recomendacion;

  if (puntuacion >= 60) {
    riesgo = "alto";
    resumen = "Este enlace presenta múltiples señales de phishing o fraude.";
    recomendacion = "No ingreses datos personales ni hagas clic en este enlace. Repórtalo si lo recibiste por mensaje.";
  } else if (puntuacion >= 35) {
    riesgo = "medio";
    resumen = "El enlace tiene algunas características sospechosas que merecen atención.";
    recomendacion = "Procede con cautela. Verifica la fuente antes de ingresar cualquier dato.";
  } else if (puntuacion >= 10) {
    riesgo = "bajo";
    resumen = "El enlace parece mayormente seguro pero tiene algún punto menor a considerar.";
    recomendacion = "En general es seguro, pero revisa que el sitio sea el que esperabas visitar.";
  } else {
    riesgo = "seguro";
    resumen = "No se encontraron señales de riesgo en este enlace.";
    recomendacion = "El enlace parece seguro. Siempre mantén precaución al ingresar datos sensibles.";
  }

  if (razones.length === 0) {
    razones.push("Usa HTTPS correctamente.");
    razones.push("No contiene patrones de phishing conocidos.");
    razones.push("Estructura de dominio normal.");
  }

  return { riesgo, puntuacion, resumen, razones, recomendacion };
}

// ── Endpoint ───────────────────────────────────────────────
app.post("/api/analyze", (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "URL requerida" });
  }

  const result = analyzeUrl(url);
  return res.json(result);
});

app.listen(PORT, () => {
  console.log(`Servidor TVU corriendo en http://localhost:${PORT}`);
});