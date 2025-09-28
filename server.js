import express from "express";
import axios from "axios";
import cors from "cors";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";

const app = express();
app.use(cors());
app.use(express.json());

// ----------------- Config -----------------
const OLLAMA_URL = "http://127.0.0.1:11434/api/generate";
const OLLAMA_TIMEOUT_MS = 120000; // 2 minutos
const REQUESTS_LOG_PATH = "requests.log";

// memória simples para buscar por execId
let ultimoResultado = null;
const resultadosPorId = {}; // { execId: parsedResponse }

// ----------------- Util helpers -----------------

/**
 * Extrai o primeiro objeto JSON válido de uma string.
 */
function extractJsonObject(text) {
  if (!text || typeof text !== "string") return null;

  const firstCurly = text.indexOf("{");
  if (firstCurly === -1) return null;

  let inString = false;
  let escape = false;
  let depth = 0;

  for (let i = firstCurly; i < text.length; i++) {
    const ch = text[i];

    if (escape) {
      escape = false;
      continue;
    }

    if (ch === "\\") {
      escape = true;
      continue;
    }

    if (ch === '"') {
      inString = !inString;
      continue;
    }

    if (inString) continue;

    if (ch === "{") {
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) {
        return text.slice(firstCurly, i + 1);
      }
    }
  }
  return null;
}

/**
 * Normaliza/coage campos esperados no parsedResponse.
 */
function coerceResponseFields(parsed) {
  if (!parsed || typeof parsed !== "object") return parsed;

  try {
    if (parsed.dos_attack_probability !== undefined && parsed.dos_attack_probability !== null) {
      let raw = parsed.dos_attack_probability;
      if (typeof raw === "string") raw = raw.replace("%", "").trim();
      const num = Number(raw);
      parsed.dos_attack_probability = Number.isFinite(num) ? Math.max(0, Math.min(100, num)) : null;
    }
  } catch {
    parsed.dos_attack_probability = null;
  }

  try {
    parsed.justification = parsed.justification !== undefined && parsed.justification !== null
      ? String(parsed.justification)
      : "";
  } catch {
    parsed.justification = "";
  }

  try {
    parsed.ip_origin = parsed.ip_origin !== undefined && parsed.ip_origin !== null
      ? String(parsed.ip_origin)
      : null;
  } catch {
    parsed.ip_origin = null;
  }

  return parsed;
}

/**
 * Grava log bonito em requests.log (append).
 */
function appendRequestsLog(obj) {
  try {
    fs.appendFileSync(REQUESTS_LOG_PATH, JSON.stringify(obj, null, 2) + ",\n");
  } catch (e) {
    console.error("Falha ao gravar requests.log:", e);
  }
}

/**
 * Tenta parsear uma string em JSON, auto-fechando chaves se necessário.
 */
function tryParseWithAutoClose(text, maxFill = 5) {
  const out = { parsed: null, repairedText: null, reason: null };
  if (!text || typeof text !== "string") {
    out.reason = "no_text";
    return out;
  }

  const trimmed = text.trim();
  try {
    out.parsed = JSON.parse(trimmed);
    out.reason = "parsed_direct";
    return out;
  } catch {
    const extracted = extractJsonObject(trimmed);
    if (!extracted) {
      out.reason = "no_object_found";
      return out;
    }
    try {
      out.parsed = JSON.parse(extracted);
      out.repairedText = extracted;
      out.reason = "parsed_extracted";
      return out;
    } catch {
      for (let i = 1; i <= maxFill; i++) {
        const candidate = extracted + "}".repeat(i);
        try {
          out.parsed = JSON.parse(candidate);
          out.repairedText = candidate;
          out.reason = `auto_closed_${i}`;
          return out;
        } catch {}
      }
      out.reason = "could_not_parse_after_autoclose";
      return out;
    }
  }
}

/**
 * Se parse local falhar, pede ao Ollama para completar/corrigir o JSON truncado.
 */
async function requestJsonRepairFromOllama(rawText, maxRetries = 2) {
  const repairPrompt = `
The text below is a JSON object that was cut off. Please RETURN ONLY the complete JSON object, with no explanation or extra text.
Do not add additional fields — only close and correct the object as intended. If unsure, try your best to produce a syntactically valid JSON object matching the content.

RAW:
${rawText}
`;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const resp = await axios.post(
        OLLAMA_URL,
        { model: "llama3", prompt: repairPrompt, stream: false },
        { timeout: OLLAMA_TIMEOUT_MS }
      );
      const text = resp && resp.data && resp.data.response ? String(resp.data.response) : "";
      const extracted = extractJsonObject(text);
      if (extracted) {
        try {
          const parsed = JSON.parse(extracted);
          return { parsed, raw: text };
        } catch {
          const tryAuto = tryParseWithAutoClose(text, 6);
          if (tryAuto.parsed) return { parsed: tryAuto.parsed, raw: text };
        }
      } else {
        try {
          const parsedDirect = JSON.parse(text.trim());
          return { parsed: parsedDirect, raw: text };
        } catch {}
      }
    } catch (err) {
      console.error("Error calling Ollama for JSON repair:", err?.message || err);
    }
  }
  return { parsed: null, raw: rawText };
}

// ----------------- Endpoints -----------------

app.post("/ia", async (req, res) => {
  const execId = uuidv4();
  const t0 = Date.now();
  const cpuStart = process.cpuUsage();
  const memStart = process.memoryUsage();

  try {
    // prompt com exemplo JSON
    const promptMessage = `
Analyze the following network packets and determine the probability that this is a DoS attack.
Respond strictly with a single JSON object (no extra text). The JSON must follow exactly this structure:

Example output:
{
  "dos_attack_probability": 75,
  "justification": "Example justification here...",
  "ip_origin": "192.168.56.2"
}

Network packets to be analyzed:

${JSON.stringify(req.body, null, 2)}
`;

    const t1 = Date.now();

    const response = await axios.post(
      OLLAMA_URL,
      { model: "llama3", prompt: promptMessage, stream: false },
      { timeout: OLLAMA_TIMEOUT_MS }
    );

    const t2 = Date.now();

    const respData = response && response.data && response.data.response ? String(response.data.response) : "";

    // --------- Parsing robusto ---------
    let parsedResponse = null;
    let repairInfo = { method: null, note: null };

    const tryLocal = tryParseWithAutoClose(respData, 6);
    if (tryLocal.parsed) {
      parsedResponse = tryLocal.parsed;
      repairInfo.method = tryLocal.reason;
      repairInfo.note = tryLocal.repairedText ? "repaired_text_present" : "direct";
    } else {
      const repairResult = await requestJsonRepairFromOllama(respData, 2);
      if (repairResult.parsed) {
        parsedResponse = repairResult.parsed;
        repairInfo.method = "ollama_repair";
      } else {
        parsedResponse = {
          error: "IA_response_not_json",
          raw: respData.length > 20000 ? respData.slice(0, 20000) + "...(truncated)" : respData,
          repairInfo
        };
        repairInfo.method = "fallback_saved_raw";
      }
    }

    parsedResponse = coerceResponseFields(parsedResponse);

    const t3 = Date.now();
    const elapsedSeconds = ((t3 - t0) / 1000).toFixed(3);
    const cpuDelta = process.cpuUsage(cpuStart);
    const memEnd = process.memoryUsage();

    const logData = {
      id: execId,
      datetime: new Date().toISOString(),
      timings: {
        buildPrompt: ((t1 - t0) / 1000).toFixed(3),
        inference: ((t2 - t1) / 1000).toFixed(3),
        parse: ((t3 - t2) / 1000).toFixed(3),
        total: elapsedSeconds
      },
      cpu: {
        user: (cpuDelta.user / 1000).toFixed(3) + " ms",
        system: (cpuDelta.system / 1000).toFixed(3) + " ms",
        total: ((cpuDelta.user + cpuDelta.system) / 1000).toFixed(3) + " ms"
      },
      memory: {
        startMB: (memStart.heapUsed / 1024 / 1024).toFixed(2),
        endMB: (memEnd.heapUsed / 1024 / 1024).toFixed(2),
        rssMB: (memEnd.rss / 1024 / 1024).toFixed(2)
      },
      request: req.body,
      response: parsedResponse
    };

    appendRequestsLog(logData);
    ultimoResultado = parsedResponse;
    resultadosPorId[execId] = parsedResponse;

    return res.json({ execId, result: parsedResponse });
  } catch (e) {
    console.error("Erro ao processar a requisição:", e);
    const errObj = { error: "internal_server_error", message: String(e) };
    appendRequestsLog({ id: uuidv4(), datetime: new Date().toISOString(), error: errObj });
    return res.status(500).json({ error: "Erro interno ao processar a solicitação." });
  }
});

app.get("/ultima_analise", (req, res) => {
  if (ultimoResultado) return res.json(ultimoResultado);
  return res.status(404).json({ error: "Nenhum resultado disponível ainda" });
});

app.get("/analise/:id", (req, res) => {
  const id = req.params.id;
  if (resultadosPorId[id]) return res.json(resultadosPorId[id]);
  return res.status(404).json({ error: "not_found" });
});

app.get("/analise_raw/:id", (req, res) => {
  const id = req.params.id;
  const result = resultadosPorId[id];
  if (!result) return res.status(404).json({ error: "not_found" });
  if (result && result.raw) return res.json({ id, raw: result.raw });
  return res.status(404).json({ error: "raw_not_found" });
});

app.listen(3000, "0.0.0.0", () => {
  console.log("Server running on port 3000");
});
