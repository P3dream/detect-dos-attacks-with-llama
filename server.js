import express from "express";
import axios from "axios";
import cors from "cors"; 

const app = express();

app.use(cors());
app.use(express.json());

app.post("/ia", async (req, res) => {
    try {
        const promptMessage = `
        Analyze the following network packets and determine the probability that this is a DoS attack.
        Respond **strictly** in JSON format **without any additional text or explanation**. The JSON response must follow this exact structure: 
        {
            "dos_attack_probability": (a number between 0 and 100 indicating the likelihood of a DoS attack),
            "justification": "(a detailed explanation of the analysis based on packet characteristics such as frequency, size, source IP behavior, and protocol anomalies)",
            "ip_origin": "the IP address of the sender of the packets if the attack probability is greater than 60%",
            "time": "time spent MUST BE A STRING OF THE NUMBER OF SECONDS IT TOOK TO PROCESS THIS REQUEST"
        }
        Network packets to be analyzed:

        ${JSON.stringify(req.body, null, 2)}
        `;

        const response = await axios.post("http://127.0.0.1:11434/api/generate", {
            model: "llama3",
            prompt: promptMessage,
            stream: false,
        });

        // console.log({
        //     model: "llama3",
        //     prompt: promptMessage,
        //     stream: false,
        // });

        const respData = response.data.response.trim();

        console.log("A resposta foi:");
        console.log(respData);

        // Tenta converter a resposta para JSON
        try {
            // const parsedResponse = JSON.parse(respData);
            // res.json(parsedResponse);
        } catch (e) {
            console.error("Erro ao converter resposta para JSON:", e);
            res.status(500).json({ error: "Resposta da IA não está em um formato JSON válido." });
        }
    } catch (e) {
        console.error("Erro ao processar a requisição:", e);
        res.status(500).json({ error: "Erro interno ao processar a solicitação." });
    }
});

app.post("/teste", async (req, res) => {
    console.log(req);
    res.send("ok");
});

app.listen(3000, "0.0.0.0", () => {
    console.log("Server running on port 3000");
});
