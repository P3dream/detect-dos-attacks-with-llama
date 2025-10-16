import express from "express";
import cors from "cors";
import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import ollama from 'ollama';
import { z } from 'zod';
import { encode } from 'gpt-tokenizer';
import { zodToJsonSchema } from 'zod-to-json-schema';

const app = express();
app.use(cors());
app.use(express.json());

// ----------------- Config -----------------
const REQUESTS_LOG_PATH = "requests.log";
const resultadosPorId = {}; // memória simples

// ----------------- Schema -----------------
const Analisis = z.object({
  dos_attack_probability: z.number(),
  justification: z.string(),
  ip_origin: z.array(z.string())
});

const schema = zodToJsonSchema(Analisis, "Analisis");

// Criar versão compatível com Ollama
const schemaForOllama = {
  $ref: "#/definitions/Analisis",
  definitions: schema.definitions,
  $schema: "http://json-schema.org/draft-07/schema#"
};

// ----------------- Helpers -----------------
function appendRequestsLog(obj) {
  try {
    fs.appendFileSync(REQUESTS_LOG_PATH, JSON.stringify(obj, null, 2) + ",\n");
  } catch (e) {
    console.error("Falha ao gravar requests.log:", e);
  }
}

// ----------------- Endpoint principal -----------------
app.post("/ia", async (req, res) => {
  const execId = uuidv4();
  const t0 = Date.now();
  const cpuStart = process.cpuUsage();
  const memStart = process.memoryUsage();

  try {
    // Limitar JSON a um tamanho seguro
    const packetsData = JSON.stringify(req.body);

    const promptMessage = `
Analyze the following network packets and determine the probability (0-100) of a DoS attack.
<Rules>
Return STRICTLY a single JSON object:
{
  "dos_attack_probability": 0,
  "justification": "string",
  "ip_origin": ["x.x.x.x"]
}
- If data is insufficient, set "dos_attack_probability": 0 and explain in "justification".
- Use only packet features provided (packet rate, SYN/ACK ratio, repeated payloads, ICMP/UDP flood, multiple source ports, TTL anomalies, fragmentation, etc.)
- If multiple candidate IPs exist, list all IPs with strongest evidence; if none, use an empty array.
</Rules>
<packets>
${packetsData}
</packets>
`;

    // ---------- Debug do input ----------
    const tokenCount = encode(promptMessage).length;
    console.log(`📥 Prompt length: ${promptMessage.length} chars`);
    console.log(`🔢 Token count: ${tokenCount}`);
    fs.writeFileSync("last_prompt_sent.txt", promptMessage);

    fs.writeFileSync(
      "last_full_payload_sent.json",
      JSON.stringify(
        {
          model: "llama3.1",
          stream: false,
          format: schemaForOllama,
          messages: [
            {
              role: "system",
              content: "You are a network security analyst specialized in detecting DoS attacks. Always respond only with valid JSON matching the given schema."
            },
            {
              role: "user",
              content: promptMessage
            }
          ]
        },
        null,
        2
      )
    );

    // ---------- Envio ao modelo ----------
    const response = await ollama.chat({
      model: "llama3.1",
      stream: false,
      messages: [
        {
          role: "system",
          content: "You are a network security analyst specialized in detecting DoS attacks. Always respond only with valid JSON matching the given schema."
        },
        {
          role: "user",
          content: promptMessage
        }
      ],
    });

    // ---------- Parsing da resposta ----------
    console.log("🧠 Raw Ollama response:", response?.message?.content);
    let content = (response?.message?.content || "").trim();

    let result;
    try {
      result = Analisis.parse(JSON.parse(content));
    } catch {
      // Se JSON vier escapado ou parcial
      const match = content.match(/\{[\s\S]*\}/);
      if (!match) throw new Error("Não encontrei JSON na resposta do Ollama.");
      result = Analisis.parse(JSON.parse(match[0]));
    }

    console.log("✅ Parsed result:", result);

    // ---------- Métricas ----------
    const t3 = Date.now();
    const elapsedSeconds = ((t3 - t0) / 1000).toFixed(3);
    const cpuDelta = process.cpuUsage(cpuStart);
    const memEnd = process.memoryUsage();

    const logData = {
      id: execId,
      datetime: new Date().toISOString(),
      timings: { total: elapsedSeconds },
      cpu: {
        total: ((cpuDelta.user + cpuDelta.system) / 1000).toFixed(3) + " ms"
      },
      memory: {
        startMB: (memStart.heapUsed / 1024 / 1024).toFixed(2),
        endMB: (memEnd.heapUsed / 1024 / 1024).toFixed(2),
      },
      requestTokens: tokenCount,
      requestChars: promptMessage.length,
      request: req.body,
      response: result
    };

    appendRequestsLog(logData);
    resultadosPorId[execId] = result;

    res.json({ execId, result });

  } catch (e) {
    console.error("❌ Erro ao processar a requisição:", e);
    appendRequestsLog({
      id: uuidv4(),
      datetime: new Date().toISOString(),
      error: String(e)
    });
    res.status(500).json({ error: "Erro interno ao processar a solicitação." });
  }
});

// ----------------- Endpoints auxiliares -----------------
app.get("/test", (req, res) => {
  res.send("API is running. Use POST /ia to analyze data.");
});

app.get("/analise/:id", (req, res) => {
  const result = resultadosPorId[req.params.id];
  if (!result) return res.status(404).json({ error: "not_found" });
  res.json(result);
});

// ----------------- Inicialização -----------------
app.listen(3000, "0.0.0.0", () => {
  console.log("🚀 Server running on port 3000");
});
