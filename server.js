require('dotenv').config();
const express = require("express");
const cors = require("cors");
const fetch = require("node-fetch");
const OpenAI = require("openai");

// supabase client
// backend/supabaseClient.js
const { createClient } = require("@supabase/supabase-js");

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = supabase;


const app = express();
app.use(cors());
app.use(express.json());

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const WHOIS_API_KEY = process.env.WHOIS_API_KEY;

//report feedback

app.post("/report", async (req, res) => {
  const { url, monaScore, aiRiskLevel, userVote, comment } = req.body;

  if (!url || !userVote) {
    return res.status(400).json({ error: "URL and userVote are required" });
  }

  try {
    const { data, error } = await supabase
      .from("reports")
      .insert([
        {
          url,
          monaScore,
          aiRiskLevel,
          userVote,
          comment
        }
      ]);

    if (error) throw error;
   
    
    res.json({ success: true, report: data});

    
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save report" });
  }
});


// 🧠 AI TEXT SCAM ANALYSIS
async function aiAnalyzeText(message) {
  const prompt = `
You are TrustMona AI, specialized in detecting scam messages.
Analyze the following text message.

Look for:
- Fake job offers
- Requests for upfront fees
- WhatsApp / Telegram scams
- Impersonation
- Crypto or investment fraud

Return ONLY valid JSON:
{
  "risk_level": "low | medium | high",
  "risk_score": 0-100,
  "reasons": ["short reason 1", "short reason 2"]
}

Message:
"""${message}"""
`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0
    });

    const text = response.choices[0].message.content.trim();

    try {
      return JSON.parse(text);
    } catch {
      return {
        risk_level: "medium",
        risk_score: 40,
        reasons: ["AI output could not be parsed"]
      };
    }

  } catch (err) {
    console.error("AI text scan error:", err.message);
    return {
      risk_level: "medium",
      risk_score: 40,
      reasons: ["AI service unavailable"]
    };
  }
}



// Safe AI scam analysis
async function aiAnalyze(url) {
  const prompt = `
You are a TrustMOna cybersecurity AI.
Analyze the following link and determine if it is a scam.
Return ONLY a JSON object like this:
{
  "risk_level": "low",
  "risk_score": 0,
  "reasons": ["reason1","reason2"]
}
Link: ${url}
`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0
    });

    // Safe parsing
    const text = response.choices[0].message.content.trim();

    try {
      return JSON.parse(text);
    } catch (parseErr) {
      console.error("AI JSON parse error:", text);
      return { risk_level: "medium", risk_score: 30, reasons: ["AI output parse failed"] };
    }

  } catch (err) {
    console.error("OpenAI API error:", err.message);
    return { risk_level: "medium", risk_score: 30, reasons: ["AI API request failed"] };
  }
}



  // 📩 SCAN MESSAGE / JOB TEXT
app.post("/scan-text", async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: "Message text required" });

  const aiResult = await aiAnalyzeText(message);

  const finalScore = Math.max(0, 100 - aiResult.risk_score);

  res.json({
    brand: "TrustMona",
    status:
      finalScore < 40 ? "🚨 High Scam Risk" :
      finalScore < 70 ? "⚠️ Medium Risk" :
      "✅ Low Risk",
    monaScore: finalScore,
    aiRiskLevel: aiResult.risk_level,
    reasons: aiResult.reasons,
    type: "message_scan",
    poweredBy: "TrustMona AI"
  });
});


// MAIN SCAN ENDPOINT
app.post("/scan", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  let risk = 0;
  let reasons = [];

  const domain = url.replace(/^https?:\/\//, "").split("/")[0];


  // WHOIS DOMAIN AGE
  try {
    const whoisRes = await fetch(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOIS_API_KEY}&domainName=${domain}&outputFormat=JSON`
    );
    const whoisData = await whoisRes.json();
    const created = whoisData.WhoisRecord?.createdDate;

    if (created) {
      const age = (Date.now() - new Date(created)) / (1000 * 60 * 60 * 24 * 365);
      if (age < 1) {
        risk += 25;
        reasons.push("Very new domain");
      } else {
        reasons.push(`Domain age: ${age.toFixed(1)} years`);
      }
    }
  } catch {
    reasons.push("Domain age unavailable");
  }

  // AI ANALYSIS
  const aiResult = await aiAnalyze(url);
  risk += aiResult.risk_score * 0.6;

  // FINAL SCORE
  const finalScore = Math.max(0, 100 - risk);

  res.json({
    brand: "TrustMona",
    domain,
    status:
      finalScore < 40 ? "🚨 High Scam Risk" :
      finalScore < 70 ? "⚠️ Medium Risk" :
      "✅ Low Risk",
    monaScore: Math.round(finalScore),
    aiRiskLevel: aiResult.risk_level,
    reasons: [...reasons, ...aiResult.reasons],
    poweredBy: "TrustMona AI"
  });
});

app.listen(process.env.PORT||3000, () => console.log(`TrustMona REAL AI running on port ${process.env.PORT||3000}`));
