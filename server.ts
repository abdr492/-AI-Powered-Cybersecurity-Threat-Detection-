import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize the Google GenAI SDK. 
// Uses process.env.GEMINI_API_KEY. It must NOT be exposed to the browser.
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY || "",
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build",
    },
  },
});

// AI Analyze Endpoint for Incident Forensics & Analysis
app.post("/api/analyze-logs", async (req, res) => {
  try {
    const { logs, attackType } = req.body;
    
    if (!logs) {
      return res.status(400).json({ error: "Logs text is required." });
    }

    if (!process.env.GEMINI_API_KEY) {
      // Return beautiful simulated AI analysis when API is not configured yet
      return res.json(getMockAIResponse(attackType || "general"));
    }

    const prompt = `
      You are an elite Enterprise Cybersecurity Threat Detection and Cyber Forensics AI model.
      Analyze the following network logs / logs trace of type "${attackType || "general"}" for anomalous employee/system behavior, lateral movement, or malicious indicators:
      
      "${logs}"

      Provide your structured output formatted matching this JSON schema exactly:
      {
        "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "threatTitle": "Short, striking threat category name",
        "probabilityScore": 0-100 (percentage),
        "forensicsSummary": "Expert security narrative detailing step-by-step chronology of the event, files accessed or protocols abused.",
        "maliciousNodes": ["list of IP addresses, ports, or Hostnames implicated in malicious actions"],
        "lateralMovement": [
          {
            "from": "IP/host origin",
            "to": "IP/host target",
            "protocol": "e.g., SMB, RDP, SSH, Kerberos",
            "reason": "Descriptive reason or footprint left",
            "maliceIndicator": "percentage indicator or classification"
          }
        ],
        "abnormalLogins": [
          {
            "user": "Affected Username",
            "sourceIp": "Source IP address",
            "location": "Detected anomaly geolocation or workstation name",
            "unusualFactors": "E.g., Impossible travel, credential stuffing, anomalous hour usage"
          }
        ],
        "complianceViolations": [
          {
            "framework": "GDPR" | "HIPAA" | "SOC2" | "PCI-DSS" | "NIST",
            "clause": "E.g., Article 32: Security of manual/automated treatment",
            "threatLevel": "High" | "Medium" | "Low",
            "status": "NON-COMPLIANT" | "RISK-ALERT"
          }
        ],
        "predictiveRiskState": "Predictive scenario for the next 30 days if this compromise goes unmitigated.",
        "recommendedMitigations": [
          "Detailed, specific mitigation actionable point 1",
          "Detailed, specific mitigation actionable point 2",
          "Detailed, specific mitigation actionable point 3"
        ]
      }
    `;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            severity: { type: Type.STRING, description: "Threat criticality level" },
            threatTitle: { type: Type.STRING, description: "Title representing the threat" },
            probabilityScore: { type: Type.INTEGER, description: "Probability percentage" },
            forensicsSummary: { type: Type.STRING, description: "Security forensic summary detailing timeline" },
            maliciousNodes: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Implicated nodes"
            },
            lateralMovement: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  from: { type: Type.STRING },
                  to: { type: Type.STRING },
                  protocol: { type: Type.STRING },
                  reason: { type: Type.STRING },
                  maliceIndicator: { type: Type.STRING },
                },
              },
            },
            abnormalLogins: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  user: { type: Type.STRING },
                  sourceIp: { type: Type.STRING },
                  location: { type: Type.STRING },
                  unusualFactors: { type: Type.STRING },
                },
              },
            },
            complianceViolations: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  framework: { type: Type.STRING },
                  clause: { type: Type.STRING },
                  threatLevel: { type: Type.STRING },
                  status: { type: Type.STRING },
                },
              },
            },
            predictiveRiskState: { type: Type.STRING, description: "30-day outlook prediction" },
            recommendedMitigations: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Step-by-step mitigation instructions"
            },
          },
          required: [
            "severity",
            "threatTitle",
            "probabilityScore",
            "forensicsSummary",
            "maliciousNodes",
            "lateralMovement",
            "abnormalLogins",
            "complianceViolations",
            "predictiveRiskState",
            "recommendedMitigations"
          ],
        },
      },
    });

    const outputText = response.text;
    if (!outputText) {
      throw new Error("Empty response from AI engine.");
    }
    const parsed = JSON.parse(outputText);
    res.json(parsed);
  } catch (error: any) {
    console.error("AI Forensics Error:", error);
    res.status(500).json({ 
      error: "Error processing logs with AI engine.", 
      message: error.message || String(error) 
    });
  }
});

// endpoint for custom Playbook & Automation generation
app.post("/api/generate-workflow", async (req, res) => {
  try {
    const { threatTitle, category, affectedNodes, mitigationGuide, userRole } = req.body;
    
    if (userRole === "auditor") {
      return res.status(403).json({ error: "Access denied: Auditors are not permitted to execute or format tactical mitigations." });
    }

    if (!process.env.GEMINI_API_KEY) {
      return res.json({
        playbookType: "Ansible Playbook / Nginx Security Directives",
        script: getMockAutomationScript(category || "general", affectedNodes || ["10.0.1.15"]),
        explanation: "Automated mitigation playbook generated to quarantine implicated endpoints and drop illegitimate requests."
      });
    }

    const prompt = `
      You are an automated Cybersecurity Orchestration engine.
      Create a fully-functioning, usable, highly-polished Security mitigation script or SOAR playbook for the following incident:
      - Threat Title: ${threatTitle || "Anomalous lateral traffic"}
      - Category: ${category || "General Threat"}
      - Target Nodes/IPs: ${JSON.stringify(affectedNodes || [])}
      - Core Recommendation: ${JSON.stringify(mitigationGuide || "")}

      Provide a structured JSON output with the following format matching this schema exactly:
      {
        "playbookType": "e.g., Ansible Quarantine Script | Nginx Access Ban Code | Kubernetes NetworkPolicy Manifest",
        "script": "The actual executable CLI, config or YAML script blocks. Keep it authentic and correctly commented.",
        "explanation": "A concise, technical breakdown explaining the mechanism used to neutralize the threat."
      }
    `;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            playbookType: { type: Type.STRING },
            script: { type: Type.STRING },
            explanation: { type: Type.STRING }
          },
          required: ["playbookType", "script", "explanation"]
        }
      }
    });

    const outputText = response.text;
    if (!outputText) {
      throw new Error("No automation playbook generated.");
    }
    res.json(JSON.parse(outputText));
  } catch (error: any) {
    console.error("Automation Workflow generation error:", error);
    res.status(500).json({ 
      error: "Error generating automation workflow.", 
      message: error.message || String(error)
    });
  }
});

// Serve Vite App Setup
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`AI Threat Detection dev server live at port ${PORT}`);
  });
}

startServer();

// Mock high-quality fallback generator when Gemini API Key is missing:
function getMockAIResponse(attackType: string) {
  const base = {
    severity: "HIGH",
    threatTitle: "Critical AD Lateral Propagation Pattern",
    probabilityScore: 94,
    forensicsSummary: "Simulated response: Node 10.150.2.45 executed high-privilege RPC requests targeting Domain Controller, coupled with rapid anomalous kerberos ticketing.",
    maliciousNodes: ["10.150.2.45", "10.150.1.10"],
    lateralMovement: [
      { from: "10.150.2.45", to: "10.150.1.10", protocol: "SMB/p445", reason: "Anomalous remote service task spawning", maliceIndicator: "92%" },
      { from: "10.150.1.10", to: "1 domain-srv", protocol: "RPC/Kerberos", reason: "Gold ticket bypass technique candidate", maliceIndicator: "89%" }
    ],
    abnormalLogins: [
      { user: "r_administrator", sourceIp: "10.150.2.45", location: "Frankfurt Sub-DC VPN", unusualFactors: "Impossible physical travel relative to previous geolocation inside SF admin center." }
    ],
    complianceViolations: [
      { framework: "GDPR", clause: "Article 32 Security controls failure", threatLevel: "High", status: "NON-COMPLIANT" },
      { framework: "PCI-DSS", clause: "Section 10.2 Logging anomalies untoward latency", threatLevel: "Medium", status: "RISK-ALERT" }
    ],
    predictiveRiskState: "High-probability lateral infection targeting active customer master databases likely within 48 hours unless active credentials revoked.",
    recommendedMitigations: [
      "Quarantine IP 10.150.2.45 inside localized network container.",
      "Revoke domain service account admin privileges immediately.",
      "Deploy custom ingress rules rejecting SMB v1 dialect on VLAN 12."
    ]
  };

  if (attackType === "bruteforce") {
    base.threatTitle = "SSH Brute-Force & Credential Stuffing";
    base.severity = "MEDIUM";
    base.probabilityScore = 88;
    base.forensicsSummary = "Host 192.168.1.104 attempted more than 400 SSH linkages in 12 seconds with rotating username arrays, resulting in 1 final successful root login.";
    base.maliciousNodes = ["192.168.1.104", "192.168.1.1"];
    base.lateralMovement = [
      { from: "192.168.1.104", to: "192.168.1.1", protocol: "SSH/p22", reason: "Repetitive failed login sequence followed by interactive shell initiation", maliceIndicator: "95%" }
    ];
  } else if (attackType === "dns_exfilt") {
    base.threatTitle = "Covert DNS Tunnel Data Exfiltration";
    base.severity = "CRITICAL";
    base.probabilityScore = 97;
    base.forensicsSummary = "Internal host is generating massive volumes of external DNS TXT queries carrying encoded Base64 sequences directed toward rogue authoritative registrar namespaces.";
    base.maliciousNodes = ["10.0.4.52", "external-rogue-ns.xyz"];
    base.lateralMovement = [
      { from: "10.0.4.52", to: "external-rogue-ns.xyz", protocol: "DNS/p53", reason: "Subdomain length averages above 64 characters carrying binary payloads", maliceIndicator: "99%" }
    ];
  } else if (attackType === "ransomware") {
    base.threatTitle = "WannaCry-Vibe SMB Lateral Encryption Spread";
    base.severity = "CRITICAL";
    base.probabilityScore = 99;
    base.forensicsSummary = "Widespread synchronous file-renaming sequences (extending with rogue markers) tracked concurrently on local endpoints. Direct exploitation of MS17-010 vulnerability guessed.";
    base.maliciousNodes = ["192.168.5.21", "192.168.5.55", "192.168.5.120"];
    base.lateralMovement = [
      { from: "192.168.5.21", to: "192.168.5.55", protocol: "SMB/p445", reason: "DoublePulsar payload validation payload injection", maliceIndicator: "98%" },
      { from: "192.168.5.21", to: "192.168.5.120", protocol: "SMB/p445", reason: "EternalBlue scan scan packet repetition", maliceIndicator: "98%" }
    ],
    base.recommendedMitigations = [
      "Sever core internal domain bridge networks immediately to prevent multi-segment distribution.",
      "Enforce port 445 network block rules router-wide.",
      "Isolate critical system hypervisors and inspect volume shadow copies."
    ];
  } else if (attackType === "sqli") {
    base.threatTitle = "WAF SQL Injection & Blind Privilege Escalation";
    base.severity = "HIGH";
    base.probabilityScore = 91;
    base.forensicsSummary = "External edge login endpoint hit with extensive UNION SELECT logic payloads targeting master db structures, attempting schema classification bypass.";
    base.maliciousNodes = ["84.32.190.4", "10.0.2.14"];
    base.lateralMovement = [
      { from: "84.32.190.4", to: "10.0.2.14", protocol: "HTTPS/p443", reason: "Raw DB statements injected behind user input parameters", maliceIndicator: "95%" }
    ];
  }

  return base;
}

function getMockAutomationScript(category: string, nodes: string[]) {
  const nodeP = nodes[0] || "10.0.1.15";
  return `#!/bin/bash
# AI Generated Mitigation Playbook for Security Incident Response
# Target Threat: ${category.toUpperCase()} Quarantine Rules
# Timestamp: ${new Date().toISOString()}

echo "=== INITIATING AUTOMATED THREAT MITIGATION SCRIPT ==="
echo "Targeted Malicious Host: ${nodeP}"

# 1. Isolate the target host using local iptables or firewalld rules
if command -v iptables &> /dev/null; then
    echo "[+] Dropping all inbound and outbound traffic to route: ${nodeP}"
    iptables -A INPUT -s ${nodeP} -j DROP
    iptables -A OUTPUT -d ${nodeP} -j DROP
    iptables -A FORWARD -s ${nodeP} -j DROP
    iptables -A FORWARD -d ${nodeP} -j DROP
elif command -v ufw &> /dev/null; then
    echo "[+] Enforcing UFW quarantine rules..."
    ufw deny from ${nodeP} to any
    ufw deny to ${nodeP}
else
    echo "[-] iptables/ufw not found on security proxy. Manual proxy block required."
fi

# 2. Block outbound rogue domain endpoints inside local hosts configuration
echo "[+] Appending local hosts block for compromised namespaces..."
echo "127.0.0.1 external-rogue-ns.xyz" >> /etc/hosts

# 3. Trigger SIEM Webhook payload structure
echo "[+] Directing JSON Webhook payload to SIEM Controller Endpoint..."
curl -X POST -H "Content-Type: application/json" \\
     -d '{"event":"AI_AUTOPLAYBOOK_ENGAGED", "quarantined_ip":"${nodeP}", "severity":"CRITICAL"}' \\
     https://siem-collector.internal.secure/api/v1/alerts

echo "=== QUARANTINE COMPLETE === "
echo "Please inspect forensic trails in compliance audits."`;
}
