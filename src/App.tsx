import React, { useState, useEffect, useRef } from "react";
import {
  Shield,
  Brain,
  Terminal,
  Server,
  Users,
  Radio,
  UserCheck,
  Zap,
  Flame,
  Sliders,
  RotateCw,
  TrendingUp,
  AlertTriangle,
  Play,
  FileSpreadsheet,
  Download,
  Fingerprint,
  Lock,
  Workflow,
  Search,
  Globe,
  Settings,
  Cpu,
  CornerDownRight,
  Clipboard,
  Check,
  AlertOctagon,
  Activity,
  Compass,
  Layers,
  FileText
} from "lucide-react";

import { RoleHeader } from "./components/RoleHeader";
import { UserRole, NetworkNode, NetworkLink, ThreatAlert, AIForensicReport, PlaybookWorkflow } from "./types";
import {
  INITIAL_NODES,
  INITIAL_LINKS,
  INITIAL_ALERTS,
  ATTACK_LOG_NARRATIVES,
  COMPLIANCE_FRAMEWORKS_DATA,
  SIEM_INTEGRATIONS
} from "./data";

export default function App() {
  // RBAC Privileges
  const [role, setRole] = useState<UserRole>("admin");

  // Threat & Scenario metrics
  const [activeScenario, setActiveScenario] = useState<"general" | "bruteforce" | "dns_exfilt" | "ransomware" | "sqli">("general");
  const [nodes, setNodes] = useState<NetworkNode[]>(INITIAL_NODES);
  const [links, setLinks] = useState<NetworkLink[]>(INITIAL_LINKS);
  const [alerts, setAlerts] = useState<ThreatAlert[]>(INITIAL_ALERTS);

  // SIEM Platform Live Sync Status
  const [siemConnected, setSiemConnected] = useState<boolean>(true);

  // Active Interactive Selection
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>("srv-app-01");
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>("alert-101");

  // Dynamic Telemetry Metrics
  const [infiltrationRisk, setInfiltrationRisk] = useState<number>(12.4);
  const [modelAccuracy, setModelAccuracy] = useState<number>(99.88);
  const [totalTraffic, setTotalTraffic] = useState<number>(8492024);
  const [blockedThreatsCount, setBlockedThreatsCount] = useState<number>(142);
  const [unmanagedSeverity, setUnmanagedSeverity] = useState<string>("Normal");

  // AI Forensic Report Generator
  const [customLogs, setCustomLogs] = useState<string>(ATTACK_LOG_NARRATIVES.general);
  const [generatingReport, setGeneratingReport] = useState<boolean>(false);
  const [forensicReport, setForensicReport] = useState<AIForensicReport | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);

  // AI Security Workflow Playbook
  const [generatingPlaybook, setGeneratingPlaybook] = useState<boolean>(false);
  const [playbookWorkflow, setPlaybookWorkflow] = useState<PlaybookWorkflow | null>(null);
  const [playbookError, setPlaybookError] = useState<string | null>(null);
  const [copiedPlaybook, setCopiedPlaybook] = useState<boolean>(false);

  // Realtime Chart Metrics Animation
  const [chartHistory, setChartHistory] = useState<number[]>([12, 18, 15, 23, 19, 32, 28, 41, 38, 45, 50, 42]);
  const [scanDensity, setScanDensity] = useState<number>(4522);

  // Threat Density Heatmap States
  const [showHeatmap, setShowHeatmap] = useState<boolean>(true);
  const [heatmapMode, setHeatmapMode] = useState<"fuzzy" | "topo" | "matrix" | "hybrid">("hybrid");
  const [heatmapIntensity, setHeatmapIntensity] = useState<number>(1.2);
  const [heatmapSettingsExpanded, setHeatmapSettingsExpanded] = useState<boolean>(true);

  // Predictive Lateral Movement Trend Overlay States
  const [showPredictiveOverlay, setShowPredictiveOverlay] = useState<boolean>(true);
  const [predictiveHopDepth, setPredictiveHopDepth] = useState<1 | 2>(2);
  const [predictiveRootType, setPredictiveRootType] = useState<"all_threats" | "selected_only">("all_threats");
  const [shieldedNodeIds, setShieldedNodeIds] = useState<string[]>([]);
  const [predictivePanelExpanded, setPredictivePanelExpanded] = useState<boolean>(true);

  // Active Interactive Section Dashboard Tab State
  const [activeTab, setActiveTab] = useState<"topology" | "incidents" | "forensics" | "compliance">("topology");

  // Dynamically calculate high-risk lateral movement projection paths
  const getPredictiveLateralPaths = () => {
    if (!showPredictiveOverlay) return { lateralLinks: [], vulnerableTargets: [] };

    // 1. Identify root source nodes of infection/threat
    const rootNodes = nodes.filter((node) => {
      if (predictiveRootType === "selected_only") {
        return node.id === selectedNodeId && (node.severity === "Malicious" || node.severity === "Suspicious" || node.score > 30);
      } else {
        return node.severity === "Malicious" || node.severity === "Suspicious" || node.score > 40;
      }
    });

    const lateralLinksSet = new Set<string>(); // "source-target" keys
    const vulnerableTargetsMap = new Map<string, { nodeId: string; sourceNodeId: string; hop: number; maxRisk: number }>();

    // Helper to find connections
    const getConnections = (nodeId: string) => {
      return links.filter((link) => {
        // Must be active connection
        if (!link.isActive) return false;
        return link.source === nodeId || link.target === nodeId;
      });
    };

    // First hop tracking
    rootNodes.forEach((root) => {
      const activeLinks = getConnections(root.id);
      activeLinks.forEach((link) => {
        const targetId = link.source === root.id ? link.target : link.source;
        // Skip if target is already shielded
        if (shieldedNodeIds.includes(targetId)) return;
        // Skip link if target has the same ID
        if (targetId === root.id) return;
        
        const targetNode = nodes.find(n => n.id === targetId);
        if (!targetNode) return;

        // Calculate risk
        const baseRisk = root.score;
        const targetRisk = Math.round(baseRisk * 0.85);

        // Record connection
        const linkKey = [root.id, targetId].sort().join("::");
        lateralLinksSet.add(linkKey);

        const current = vulnerableTargetsMap.get(targetId);
        if (!current || current.maxRisk < targetRisk) {
          vulnerableTargetsMap.set(targetId, {
            nodeId: targetId,
            sourceNodeId: root.id,
            hop: 1,
            maxRisk: targetRisk
          });
        }
      });
    });

    // Second hop tracking (if predictiveHopDepth is 2)
    if (predictiveHopDepth === 2) {
      // Create a snapshot of 1-hop targets
      const firstHopTargets = Array.from(vulnerableTargetsMap.values()).filter(t => t.hop === 1);
      firstHopTargets.forEach((firstHop) => {
        // If the first hop node itself is shielded, don't propagate
        if (shieldedNodeIds.includes(firstHop.nodeId)) return;

        const activeLinks = getConnections(firstHop.nodeId);
        activeLinks.forEach((link) => {
          const targetId = link.source === firstHop.nodeId ? link.target : link.source;
          // Skip if going back to root nodes or target itself is a root node
          if (rootNodes.some(r => r.id === targetId)) return;
          // Skip if target is shielded
          if (shieldedNodeIds.includes(targetId)) return;
          if (targetId === firstHop.nodeId) return;

          const targetNode = nodes.find(n => n.id === targetId);
          if (!targetNode) return;

          // Compute risk for 2nd hop
          const targetRisk = Math.round(firstHop.maxRisk * 0.65);

          // Add path if it doesn't already exist or has higher priority
          const linkKey = [firstHop.nodeId, targetId].sort().join("::");
          lateralLinksSet.add(linkKey);

          const current = vulnerableTargetsMap.get(targetId);
          if (!current || current.maxRisk < targetRisk) {
            vulnerableTargetsMap.set(targetId, {
              nodeId: targetId,
              sourceNodeId: firstHop.nodeId,
              hop: 2,
              maxRisk: targetRisk
            });
          }
        });
      });
    }

    const lateralLinks = Array.from(lateralLinksSet).map((key) => {
      const [u, v] = key.split("::");
      return { source: u, target: v };
    });

    const vulnerableTargets = Array.from(vulnerableTargetsMap.values()).map((t) => {
      const nodeObj = nodes.find(n => n.id === t.nodeId);
      return {
        ...t,
        label: nodeObj?.label || t.nodeId,
        ip: nodeObj?.ip || "0.0.0.0",
        type: nodeObj?.type || "Workstation",
        severity: nodeObj?.severity || "Normal"
      };
    }).sort((a, b) => b.maxRisk - a.maxRisk);

    return { lateralLinks, vulnerableTargets };
  };

  // Computes the top 3 highest threat enterprise network subnets dynamically
  const getTopSectors = () => {
    const sectorScores: { name: string; combined: number; status: string }[] = [];
    for (let r = 0; r < 3; r++) {
      for (let c = 0; c < 4; c++) {
        const xMin = c * 150;
        const yMin = r * 160;
        const title = [
          "Zone Alpha (Edge Perimeter)",
          "Zone Beta (App Cluster Core)",
          "Zone Gamma (Ingress Controllers)",
          "Zone Delta (Databases Pool)",
          "Sector Epsilon (User Client LAN)",
          "Sector Zeta (Domain Services AD)",
          "Sector Eta (Backup Storage Vault)",
          "Sector Theta (Shared distributed Volumes)",
          "Cluster Iota (Compliance Monitoring Hub)",
          "Cluster Kappa (Staging CI/CD Pipelines)",
          "Cluster Lambda (SOAR Quarantine Sandbox)",
          "Cluster Sigma (Offline Storage Cold Archive)"
        ][r * 4 + c] || `Sector C${c}:R${r}`;

        const nearbyNodes = nodes.filter(n => n.x >= xMin && n.x < xMin + 150 && n.y >= yMin && n.y < yMin + 160);
        const maxScore = nearbyNodes.length > 0 ? Math.max(...nearbyNodes.map(n => n.score)) : 0;
        const sumScores = nearbyNodes.reduce((acc, curr) => acc + curr.score, 0);
        const density = Math.min(100, Math.round(nearbyNodes.length > 0 ? sumScores / nearbyNodes.length : 0));
        const combined = Math.max(maxScore, density);
        const status = combined > 60 ? "CRITICAL" : combined > 25 ? "ELEVATED" : "OPTIMAL";
        
        if (combined > 0) {
          sectorScores.push({ name: title, combined, status });
        }
      }
    }
    return sectorScores.sort((a, b) => b.combined - a.combined).slice(0, 3);
  };

  // Visual simulation tracking variables
  const containerRef = useRef<SVGSVGElement | null>(null);
  const [isDraggingNodeId, setIsDraggingNodeId] = useState<string | null>(null);

  // 1. Force-directed Graph Physics Engine
  useEffect(() => {
    let animationFrameId: number;

    const tick = () => {
      setNodes((prevNodes) => {
        // Center coordinates of the 4K architectural visual area inside the node stage
        const centerX = 300;
        const centerY = 240;

        // Gravity pull to center
        const gravity = 0.04;
        const repulsionForce = 450;
        const springLength = 110;
        const springStrength = 0.05;

        // Clone current coordinate arrays to safely compute forces
        const updated = prevNodes.map((n) => ({
          ...n,
          fx: n.id === isDraggingNodeId ? n.fx : null,
          fy: n.id === isDraggingNodeId ? n.fy : null
        }));

        // Calculate electrostatic node-to-node repulsion
        for (let i = 0; i < updated.length; i++) {
          for (let j = i + 1; j < updated.length; j++) {
            const dx = updated[j].x - updated[i].x;
            const dy = updated[j].y - updated[i].y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;

            if (dist < 280) {
              const force = repulsionForce / (dist * dist);
              const forceX = (dx / dist) * force;
              const forceY = (dy / dist) * force;

              // Distribute forces opposite to each other
              if (updated[i].id !== isDraggingNodeId) {
                updated[i].vx -= forceX;
                updated[i].vy -= forceY;
              }
              if (updated[j].id !== isDraggingNodeId) {
                updated[j].vx += forceX;
                updated[j].vy += forceY;
              }
            }
          }
        }

        // Calculate spring attraction forces along current links
        links.forEach((link) => {
          const sourceNode = updated.find((n) => n.id === link.source);
          const targetNode = updated.find((n) => n.id === link.target);

          if (sourceNode && targetNode) {
            const dx = targetNode.x - sourceNode.x;
            const dy = targetNode.y - sourceNode.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const force = (dist - springLength) * springStrength;

            const forceX = (dx / dist) * force;
            const forceY = (dy / dist) * force;

            if (sourceNode.id !== isDraggingNodeId) {
              sourceNode.vx += forceX;
              sourceNode.vy += forceY;
            }
            if (targetNode.id !== isDraggingNodeId) {
              targetNode.vx -= forceX;
              targetNode.vy -= forceY;
            }
          }
        });

        // Resolve positions with damping & center gravity boundary logs
        return updated.map((n) => {
          if (n.id === isDraggingNodeId) {
            // Under user drag control: follow the drag coords
            return {
              ...n,
              vx: 0,
              vy: 0,
              x: n.fx !== undefined && n.fx !== null ? n.fx : n.x,
              y: n.fy !== undefined && n.fy !== null ? n.fy : n.y
            };
          }

          // Apply center gravity
          const dxToCenter = centerX - n.x;
          const dyToCenter = centerY - n.y;
          n.vx += dxToCenter * gravity;
          n.vy += dyToCenter * gravity;

          // Apply damping (friction)
          n.vx *= 0.72;
          n.vy *= 0.72;

          // Step update
          let newX = n.x + n.vx;
          let newY = n.y + n.vy;

          // Enforce stage boundaries (600 width, 480 height)
          newX = Math.max(25, Math.min(575, newX));
          newY = Math.max(25, Math.min(455, newY));

          return {
            ...n,
            x: newX,
            y: newY
          };
        });
      });

      animationFrameId = requestAnimationFrame(tick);
    };

    animationFrameId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animationFrameId);
  }, [links, isDraggingNodeId]);

  // 2. Scenario Trigger Switcher (Simulates Live Cyber Attacks on Node coordinates & threat severities)
  const handleLoadScenario = (scenario: typeof activeScenario) => {
    setActiveScenario(scenario);
    setCustomLogs(ATTACK_LOG_NARRATIVES[scenario]);
    setForensicReport(null);
    setPlaybookWorkflow(null);
    setReportError(null);

    // Dynamic metrics alteration
    let risk = 12.4;
    let accuracy = 99.88;
    let anomalyScoreOffset = 0;

    const modifiedNodes = INITIAL_NODES.map((n) => {
      // Deep clone objects
      const item = { ...n, isCompromised: false, severity: "Normal" as "Normal" | "Suspicious" | "Malicious", score: Math.floor(Math.random() * 8) + 3 };
      
      if (scenario === "bruteforce") {
        risk = 48.6;
        accuracy = 98.45;
        if (item.id === "user-alice") {
          item.severity = "Malicious";
          item.score = 92;
          item.isCompromised = true;
          item.details = "ATTACK ROOT: Executed brute force attempt stream toward Domain Controller & file repos.";
        }
        if (item.id === "dc-01") {
          item.severity = "Suspicious";
          item.score = 64;
          item.details = "TARGET: Host under active credentials credential stuffing attempts.";
        }
      } else if (scenario === "dns_exfilt") {
        risk = 74.2;
        accuracy = 97.10;
        if (item.id === "user-bob") {
          item.severity = "Malicious";
          item.score = 98;
          item.isCompromised = true;
          item.details = "EXFILTRATION SOURCE: Tunneling internal database credentials via rogue Base64 TXT DNS packets.";
        }
        if (item.id === "fw-01") {
          item.severity = "Suspicious";
          item.score = 55;
        }
      } else if (scenario === "ransomware") {
        risk = 94.8;
        accuracy = 96.02;
        if (item.id === "srv-file-02") {
          item.severity = "Malicious";
          item.score = 99;
          item.isCompromised = true;
          item.details = "RANSOMWARE epicenter: Active volume shadow encryption in action (.locked files recursively spawning).";
        }
        if (item.id === "user-alice") {
          item.severity = "Malicious";
          item.score = 95;
          item.isCompromised = true;
        }
        if (item.id === "db-prod") {
          item.severity = "Suspicious";
          item.score = 70;
        }
      } else if (scenario === "sqli") {
        risk = 82.1;
        accuracy = 98.90;
        if (item.id === "ext-attacker") {
          item.severity = "Malicious";
          item.score = 94;
          item.details = "EXPLOIT COMMANDER: Transmitting custom UNION database syntax packages via edge WAF bypass.";
        }
        if (item.id === "srv-app-01") {
          item.severity = "Suspicious";
          item.score = 78;
          item.details = "REFLECTOR NODE: App endpoint executing un-sanitized dynamic SQL query arguments.";
        }
        if (item.id === "db-prod") {
          item.severity = "Suspicious";
          item.score = 81;
        }
      }

      return item;
    });

    setNodes(modifiedNodes);
    setInfiltrationRisk(risk);
    setModelAccuracy(accuracy);

    // Modify active alerts list
    if (scenario === "general") {
      setAlerts(INITIAL_ALERTS);
      setUnmanagedSeverity("Normal");
    } else {
      const scenarioAlert: ThreatAlert = {
        id: `alert-spec-${Date.now()}`,
        timestamp: new Date().toISOString(),
        threatTitle: getScenarioAlertTitle(scenario),
        sourceNode: scenario === "sqli" ? "ext-attacker" : (scenario === "bruteforce" ? "user-alice" : (scenario === "dns_exfilt" ? "user-bob" : "user-alice")),
        targetNode: scenario === "sqli" ? "srv-app-01" : "dc-01",
        protocol: scenario === "bruteforce" ? "SSH/22" : (scenario === "dns_exfilt" ? "DNS/53" : (scenario === "ransomware" ? "SMB/445" : "HTTPS/443")),
        severity: "Red",
        category: getScenarioAlertCategory(scenario),
        status: "Active",
        score: Math.floor(risk),
        description: `CRITICAL AI TRACE DETECTED: Anomalous footprint signatures indicate automated ${scenario} campaigns in progress.`
      };
      setAlerts([scenarioAlert, ...INITIAL_ALERTS]);
      setSelectedAlertId(scenarioAlert.id);
      setUnmanagedSeverity("Malicious");
    }
  };

  const getScenarioAlertTitle = (sc: string) => {
    switch (sc) {
      case "bruteforce": return "SSH Root Dictionary Bruteforce Campaign";
      case "dns_exfilt": return "Covert DNS Tunnel High-Entropy Exfiltration";
      case "ransomware": return "Synchronous WannaCry Ransomware Encryption Spread";
      case "sqli": return "WAF Bypassed Blind SQL Database Injection";
      default: return "Anomalous Intrusion Pattern";
    }
  };

  const getScenarioAlertCategory = (sc: string) => {
    switch (sc) {
      case "bruteforce": return "Brute Force";
      case "dns_exfilt": return "DNS Tunneling";
      case "ransomware": return "Ransomware Lateral Spread";
      case "sqli": return "SQL Injection";
      default: return "Anomalous Portscan";
    }
  };

  // 3. Mouse interaction event controllers for Node Drags
  const handleNodeMouseDown = (nodeId: string, event: React.MouseEvent<SVGCircleElement>) => {
    event.preventDefault();
    setIsDraggingNodeId(nodeId);
    setSelectedNodeId(nodeId);

    const rect = containerRef.current?.getBoundingClientRect();
    if (rect) {
      const mouseX = event.clientX - rect.left;
      const mouseY = event.clientY - rect.top;

      setNodes((current) =>
        current.map((n) =>
          n.id === nodeId
            ? { ...n, fx: mouseX, fy: mouseY, x: mouseX, y: mouseY }
            : n
        )
      );
    }
  };

  const handleNodeMouseMove = (event: React.MouseEvent<SVGSVGElement>) => {
    if (isDraggingNodeId) {
      const rect = containerRef.current?.getBoundingClientRect();
      if (rect) {
        const mouseX = event.clientX - rect.left;
        const mouseY = event.clientY - rect.top;

        setNodes((current) =>
          current.map((n) =>
            n.id === isDraggingNodeId
              ? { ...n, fx: mouseX, fy: mouseY, x: mouseX, y: mouseY }
              : n
          )
        );
      }
    }
  };

  const handleNodeMouseUp = () => {
    if (isDraggingNodeId) {
      setNodes((current) =>
        current.map((n) =>
          n.id === isDraggingNodeId
            ? { ...n, fx: null, fy: null }
            : n
        )
      );
      setIsDraggingNodeId(null);
    }
  };

  // 4. Incident mitigations execution logs triggers
  const executeIsolation = (nodeId: string) => {
    if (role === "auditor") {
      alert("RBAC Limitation: Compliance Auditor cannot issue tactical firewall isolation requests.");
      return;
    }
    setNodes((current) =>
      current.map((n) =>
        n.id === nodeId
          ? {
              ...n,
              severity: "Normal",
              score: 2,
              ip: "0.0.0.0",
              details: `QUARANTINED Host is locked in Sandboxed isolated VLAN subnet. Access Revoked.`,
              isCompromised: false
            }
          : n
      )
    );
    // Increase blocked count
    setBlockedThreatsCount((prev) => prev + 1);
  };

  const executeKillTraffic = (nodeId: string) => {
    if (role === "auditor") {
      alert("RBAC Limitation: Compliance Auditor cannot drop active network sessions.");
      return;
    }
    // Set matching links state to inactive
    setLinks((current) =>
      current.map((lnk) =>
        lnk.source === nodeId || lnk.target === nodeId
          ? { ...lnk, isActive: false, bytesTransferred: 0 }
          : lnk
      )
    );
    setBlockedThreatsCount((prev) => prev + 1);
  };

  const toggleShieldNode = (nodeId: string) => {
    if (role === "auditor") {
      alert("RBAC Limitation: Compliance Auditor cannot deploy defensive network shields.");
      return;
    }
    setShieldedNodeIds((prev) => 
      prev.includes(nodeId) 
        ? prev.filter((id) => id !== nodeId) 
        : [...prev, nodeId]
    );
  };

  const severActiveConnection = (targetId: string, sourceId: string) => {
    if (role === "auditor") {
      alert("RBAC Limitation: Compliance Auditor cannot drop network paths.");
      return;
    }
    setLinks((prev) =>
      prev.map((lnk) =>
        (lnk.source === sourceId && lnk.target === targetId) ||
        (lnk.source === targetId && lnk.target === sourceId)
          ? { ...lnk, isActive: false }
          : lnk
      )
    );
    setBlockedThreatsCount((prev) => prev + 1);
  };

  // Direct dynamic scenarios metric refresh API simulation
  const handleManualMetricsRefresh = () => {
    // Generate subtle offsets to keep visual panels realistic
    setTotalTraffic((prev) => prev + Math.floor(Math.random() * 8000) - 2000);
    setScanDensity((prev) => prev + Math.floor(Math.random() * 200) - 100);
    setChartHistory((prev) => {
      const n = [...prev.slice(1)];
      n.push(Math.floor(Math.random() * 30) + 15);
      return n;
    });
  };

  // 5. Server-side AI Log analyst request call via Gemini API endpoint
  const performAILogsForensics = async () => {
    setGeneratingReport(true);
    setForensicReport(null);
    setReportError(null);

    try {
      const response = await fetch("/api/analyze-logs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          logs: customLogs,
          attackType: activeScenario
        })
      });

      if (!response.ok) {
        throw new Error(`AI Gateway responded with error code: ${response.status}`);
      }

      const reportData: AIForensicReport = await response.json();
      setForensicReport(reportData);

      // Mutate the nodes on the threat graph based on the AI feedback!
      if (reportData.maliciousNodes && reportData.maliciousNodes.length > 0) {
        setNodes((current) =>
          current.map((n) => {
            const isAnalyzedMalicious = reportData.maliciousNodes.some(
              (ipAddr) => n.ip === ipAddr || ipAddr.includes(n.ip)
            );
            if (isAnalyzedMalicious) {
              return {
                ...n,
                severity: "Malicious",
                score: reportData.probabilityScore || 95,
                details: `AI DETECTED MALICIOUS SOURCE IP: ${reportData.threatTitle}. ${reportData.forensicsSummary}`
              };
            }
            return n;
          })
        );
      }
    } catch (err: any) {
      console.error(err);
      setReportError(err.message || String(err));
    } finally {
      setGeneratingReport(false);
    }
  };

  // 6. Direct server post endpoint to trigger Ansible/Nginx quarantine scripts
  const generateMitigationWorkflowCode = async () => {
    if (role === "auditor") {
      setPlaybookError("Access denied: auditors are restricted from generating deployment mitigations.");
      return;
    }
    setGeneratingPlaybook(true);
    setPlaybookWorkflow(null);
    setPlaybookError(null);

    const selectedNodeObj = nodes.find((n) => n.id === selectedNodeId);

    try {
      const response = await fetch("/api/generate-workflow", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          threatTitle: forensicReport?.threatTitle || getScenarioAlertTitle(activeScenario),
          category: activeScenario,
          affectedNodes: selectedNodeObj ? [selectedNodeObj.ip] : ["10.150.2.45"],
          mitigationGuide: forensicReport?.recommendedMitigations?.[0] || "Isolate target VLAN bridges",
          userRole: role
        })
      });

      if (!response.ok) {
        const errRaw = await response.json();
        throw new Error(errRaw.error || "Gateway orchestration timeout.");
      }

      const payload: PlaybookWorkflow = await response.json();
      setPlaybookWorkflow(payload);
    } catch (e: any) {
      setPlaybookError(e.message || String(e));
    } finally {
      setGeneratingPlaybook(false);
    }
  };

  const copyPlaybookToClipboard = () => {
    if (playbookWorkflow?.script) {
      navigator.clipboard.writeText(playbookWorkflow.script);
      setCopiedPlaybook(true);
      setTimeout(() => setCopiedPlaybook(false), 2000);
    }
  };

  // CSV Compliant Auditor Logs Generator
  const handleExportCSVReport = () => {
    const headers = "Timestamp,Threat Class,Source Node,Target Entity,Protocol,Severity Rating,Status Code\n";
    const bodyRows = alerts
      .map(
        (a) =>
          `"${a.timestamp}","${a.category}","${a.sourceNode}","${a.targetNode}","${a.protocol}","${a.severity}","${a.status}"`
      )
      .join("\n");

    const blob = new Blob([headers + bodyRows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const linkObj = document.createElement("a");
    linkObj.href = url;
    linkObj.download = `Aegis_Compliance_Report_${activeScenario}_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(linkObj);
    linkObj.click();
    document.body.removeChild(linkObj);
  };

  const selectedNodeObj = nodes.find((n) => n.id === selectedNodeId);
  const selectedAlertObj = alerts.find((a) => a.id === selectedAlertId) || alerts[0];
  const { lateralLinks, vulnerableTargets } = getPredictiveLateralPaths();

  return (
    <div className="min-h-screen bg-[#050506] text-[#e0e0e0] font-sans flex flex-col selection:bg-cyan-950 selection:text-cyan-300">
      
      {/* Dynamic RBAC Global Header widget */}
      <RoleHeader
        currentRole={role}
        setRole={setRole}
        systemStatus={
          activeScenario === "general"
            ? "OPTIMAL"
            : forensicReport
            ? "MITIGATION_ENGAGED"
            : "ATTACK_SUSPECTED"
        }
        siemConnected={siemConnected}
        onToggleSiem={() => setSiemConnected((prev) => !prev)}
        onRefreshMetrics={handleManualMetricsRefresh}
      />

      {/* Dynamic Cyber Command Center Tabs */}
      <div className="bg-[#09090f] border-b border-[#161620] px-6 py-2.5 flex flex-wrap items-center justify-between gap-4 select-none">
        <div className="flex items-center gap-2 overflow-x-auto scrollbar-none">
          {[
            { id: "topology", label: "Network Topology Map", icon: Globe, badge: "Live Map", color: "text-cyan-400" },
            { id: "incidents", label: "Simulator & Telemetry", icon: Terminal, badge: activeScenario.toUpperCase(), color: "text-orange-400" },
            { id: "forensics", label: "AI Forensics & Alerts", icon: Brain, badge: `${alerts.length} Alerts`, color: "text-purple-400" },
            { id: "compliance", label: "GRC & SOAR Runbooks", icon: Workflow, badge: "NIST Sp.800", color: "text-emerald-400" },
          ].map((tab) => {
            const IconComp = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                id={`tab-btn-${tab.id}`}
                className={`px-4 py-2 font-mono text-xs font-semibold uppercase tracking-wider rounded border transition-all flex items-center gap-2 cursor-pointer ${
                  isActive
                    ? "bg-slate-900/80 border-[#1a1a2a] text-white shadow-[0_0_15px_rgba(6,182,212,0.1)] font-bold"
                    : "bg-[#06060a]/45 border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/20"
                }`}
              >
                <IconComp className={`w-3.5 h-3.5 ${isActive ? tab.color : "text-slate-500"}`} />
                <span>{tab.label}</span>
                <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded ${
                  isActive ? "bg-cyan-950 text-cyan-400 border border-cyan-800/40" : "bg-indigo-950/20 text-slate-500"
                }`}>
                  {tab.badge}
                </span>
              </button>
            );
          })}
        </div>
        
        <div className="hidden lg:flex items-center gap-4 text-xs font-mono text-slate-500">
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span>SIEM STATUS: LIVE SYNC</span>
          </span>
          <span className="text-slate-700">|</span>
          <span>PRIVILEGE: <strong className="text-slate-300 font-bold uppercase">{role}</strong></span>
        </div>
      </div>

      {/* Main Grid Viewport matching the Sophisticated Dark architectural spec */}
      <div className={`flex-1 grid grid-cols-1 md:grid-cols-12 overflow-hidden ${
        activeTab === "compliance" ? "hidden" : ""
      }`}>
        
        {/* LEFT COLUMN: TELEMETRY & PREDICTIVE ANALYTICS VIEWPORTS */}
        <aside className={`${
          activeTab === "incidents"
            ? "col-span-12 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-6 overflow-y-auto"
            : "hidden"
        } border-r border-[#1a1a20] bg-[#08080c] flex flex-col`}>
          
          {/* Active attack vectors switch trigger (Simulate incidents) */}
          <div className="p-4 border-b border-[#1a1a20]">
            <h2 className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center justify-between">
              <span>Incident Simulator</span>
              <span className="text-[9px] bg-red-950 text-red-400 px-2 py-0.5 rounded border border-red-900/40">Enterprises Mode</span>
            </h2>
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => handleLoadScenario("general")}
                id="scenario-btn-general"
                className={`py-1.5 px-2 font-mono text-xs rounded border transition-all text-left flex flex-col justify-between ${
                  activeScenario === "general"
                    ? "bg-cyan-950/25 border-cyan-500/50 text-cyan-400"
                    : "bg-slate-900/50 border-gray-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <span className="font-bold">Normal Base</span>
                <span className="text-[9px] text-slate-500">Normal operations</span>
              </button>
              <button
                onClick={() => handleLoadScenario("bruteforce")}
                id="scenario-btn-bruteforce"
                className={`py-1.5 px-2 font-mono text-xs rounded border transition-all text-left flex flex-col justify-between ${
                  activeScenario === "bruteforce"
                    ? "bg-red-950/25 border-red-500/50 text-red-400"
                    : "bg-slate-900/50 border-gray-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <span className="font-bold">SSH Bruteforce</span>
                <span className="text-[9px] text-slate-500">Auth floods</span>
              </button>
              <button
                onClick={() => handleLoadScenario("dns_exfilt")}
                id="scenario-btn-dns_exfilt"
                className={`py-1.5 px-2 font-mono text-xs rounded border transition-all text-left flex flex-col justify-between ${
                  activeScenario === "dns_exfilt"
                    ? "bg-[#251b12] border-yellow-600/50 text-yellow-500"
                    : "bg-slate-900/50 border-gray-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <span className="font-bold">DNS Exfiltrate</span>
                <span className="text-[9px] text-slate-500">TXT Query payload</span>
              </button>
              <button
                onClick={() => handleLoadScenario("ransomware")}
                id="scenario-btn-ransomware"
                className={`py-1.5 px-2 font-mono text-xs rounded border transition-all text-left flex flex-col justify-between ${
                  activeScenario === "ransomware"
                    ? "bg-red-950/40 border-red-700/50 text-red-300"
                    : "bg-slate-900/50 border-gray-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <span className="font-bold">Ransomware</span>
                <span className="text-[9px] text-slate-500">SMB file payload</span>
              </button>
              <button
                onClick={() => handleLoadScenario("sqli")}
                id="scenario-btn-sqli"
                className={`col-span-2 py-1.5 px-2 font-mono text-xs rounded border transition-all text-left flex justify-between items-center ${
                  activeScenario === "sqli"
                    ? "bg-purple-950/20 border-purple-500/50 text-purple-400"
                    : "bg-slate-900/50 border-gray-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <div className="flex flex-col">
                  <span className="font-bold">Blind SQL Injection Payload</span>
                  <span className="text-[9px] text-slate-500">Master schema mapping attempts</span>
                </div>
                <Zap className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Quick Metrics stats dashboard */}
          <div className="p-4 border-b border-[#1a1a20] space-y-4">
            <h2 className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest">
              Live Network Metrics
            </h2>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-[#0c0d13] border border-[#1d1d27] p-2.5 rounded">
                <div className="text-[10px] text-slate-400 font-mono">EGRESS TRAFFIC</div>
                <div className="text-sm font-bold tracking-tight text-white mt-0.5">
                  {(totalTraffic / 1000000).toFixed(2)} MB/s
                </div>
              </div>
              <div className="bg-[#0c0d13] border border-[#1d1d27] p-2.5 rounded">
                <div className="text-[10px] text-slate-400 font-mono">QUARANTINED NODES</div>
                <div className="text-sm font-bold tracking-tight text-cyan-400 mt-0.5">
                  {blockedThreatsCount} Hosts
                </div>
              </div>
            </div>

            {/* Infiltration Risk predictive gauge */}
            <div className="space-y-2.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">INFILTRATION RISK RATIO</span>
                <span className={`font-bold ${activeScenario === 'general' ? 'text-green-400' : 'text-red-400'}`}>
                  {infiltrationRisk.toFixed(1)}%
                </span>
              </div>
              <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-1000 ${
                    activeScenario === "general"
                      ? "bg-green-500"
                      : activeScenario === "bruteforce"
                      ? "bg-yellow-500"
                      : "bg-red-500"
                  }`}
                  style={{ width: `${infiltrationRisk}%` }}
                />
              </div>

              <div className="flex items-center justify-between text-xs font-mono pt-1">
                <span className="text-slate-400">DETECTING MODEL ACCURACY</span>
                <span className="text-cyan-400 font-bold">{modelAccuracy.toFixed(2)}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div
                  className="bg-cyan-500 h-full transition-all duration-1000"
                  style={{ width: `${modelAccuracy}%` }}
                />
              </div>
            </div>
          </div>

          {/* Historical Trends SVG chart rendering */}
          <div className="p-4 border-b border-[#1a1a20] flex-1">
            <h2 className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center justify-between">
              <span>Historical Trend Reports</span>
              <span className="text-[9px] text-cyan-400 font-mono">ANOMALIES/HR</span>
            </h2>

            <div className="h-28 w-full bg-[#0d0d14] rounded border border-[#1e1e28] p-2 flex flex-col justify-between relative overflow-hidden">
              <div className="absolute top-2 left-2 text-[9px] font-mono text-slate-500 flex gap-2">
                <span>PEAK CONCURRENT: 52 APW</span>
                <span>SCAN RATE: {scanDensity} pkts/s</span>
              </div>

              {/* Responsive SVG Sparkline Chart */}
              <div className="flex-1 mt-6">
                <svg className="w-full h-full overflow-visible" viewBox="0 0 100 40" preserveAspectRatio="none">
                  <path
                    d={`M ${chartHistory.map((val, idx) => `${(idx / (chartHistory.length - 1)) * 100} , ${40 - (val / 60) * 35}`).join(" L ")}`}
                    fill="none"
                    stroke="#00e5ff"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  {/* Fill area */}
                  <path
                    d={`M 0 , 40 L ${chartHistory.map((val, idx) => `${(idx / (chartHistory.length - 1)) * 100} , ${40 - (val / 60) * 35}`).join(" L ")} L 100 , 40 Z`}
                    fill="url(#sparkline-gradient)"
                    opacity="0.12"
                  />
                  <defs>
                    <linearGradient id="sparkline-gradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#00e5ff" />
                      <stop offset="100%" stopColor="#050506" />
                    </linearGradient>
                  </defs>
                </svg>
              </div>

              <div className="flex justify-between text-[9px] font-mono text-slate-600 border-t border-slate-900 pt-1">
                <span>02:00</span>
                <span>03:00</span>
                <span>04:00</span>
                <span>05:00</span>
                <span>06:00 (NOW)</span>
              </div>
            </div>

            {/* Abnormal login monitoring logs container */}
            <div className="mt-4 space-y-2">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                Implicated Login Attempts
              </div>

              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                <div className="p-2 bg-[#090b11] border border-gray-900 rounded hover:border-slate-800 text-[11px] font-mono flex justify-between items-center">
                  <div className="flex flex-col">
                    <span className="text-yellow-400 font-bold flex items-center gap-1">
                      <Fingerprint className="w-3 h-3 text-yellow-500" /> r_administrator
                    </span>
                    <span className="text-[9px] text-slate-500">IP: 10.150.2.45</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 bg-yellow-950/20 text-yellow-500 rounded border border-yellow-900/30">Anomalous Hour</span>
                </div>

                <div className="p-2 bg-[#090b11] border border-gray-900 rounded hover:border-slate-800 text-[11px] font-mono flex justify-between items-center">
                  <div className="flex flex-col">
                    <span className="text-red-400 font-bold flex items-center gap-1">
                      <Fingerprint className="w-3 h-3 text-red-500" /> user_audit
                    </span>
                    <span className="text-[9px] text-slate-500">IP: 84.32.190.4</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 bg-red-950/30 text-red-400 rounded border border-red-900/30">Impossible Travel</span>
                </div>

                <div className="p-2 bg-[#090b11] border border-gray-900 rounded hover:border-slate-800 text-[11px] font-mono flex justify-between items-center">
                  <div className="flex flex-col">
                    <span className="text-emerald-400 font-bold flex items-center gap-1">
                      <Fingerprint className="w-3 h-3" /> sys_ansible
                    </span>
                    <span className="text-[9px] text-slate-500">IP: 10.150.2.22</span>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 bg-emerald-950/20 text-emerald-400 rounded border border-emerald-900/30">Auto Authorized</span>
                </div>
              </div>
            </div>
          </div>
        </aside>

        {/* CENTER COLUMN: Radiant Interactive Force-Directed Graph stage */}
        <section className={`${
          activeTab === "topology" ? "col-span-12" : "hidden"
        } relative bg-[#040406] flex flex-col items-stretch border-r border-[#1a1a20]`}>
          {/* Subtle dotted grid overlay of Sophisticated Dark */}
          <div
            className="absolute inset-0 opacity-10 pointer-events-none"
            style={{
              backgroundImage: "radial-gradient(#2a2a35 1.5px, transparent 1.5px)",
              backgroundSize: "28px 28px"
            }}
          />

          {/* Top Stage Context Status */}
          <div className="p-4 border-b border-[#1a1a20] bg-[#07070a]/90 flex justify-between items-center z-10 backdrop-blur-sm">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
              <span className="text-xs uppercase font-mono text-slate-300">
                AI Behavior Anomaly Map (Primary Force Directed Engine)
              </span>
            </div>
            <div className="text-[10px] text-slate-500 font-mono tracking-wider flex items-center gap-2">
              <span>ACTIVE SCENARIO: <span className="text-cyan-400 font-bold">{activeScenario.toUpperCase()}</span></span>
              <span>•</span>
              <span className="animate-pulse text-emerald-400">● SIMULATING LIVE STREAM</span>
            </div>
          </div>

          {/* Interactive Graph Canvas Stage */}
          <div className="flex-1 min-h-[440px] relative overflow-hidden" style={{ cursor: isDraggingNodeId ? "grabbing" : "default" }}>
            <svg
              ref={containerRef}
              id="id-stage-cyber-graph"
              className="w-full h-full"
              viewBox="0 0 600 480"
              onMouseMove={handleNodeMouseMove}
              onMouseUp={handleNodeMouseUp}
              onMouseLeave={handleNodeMouseUp}
            >
              <defs>
                {/* Threat Heatmap radial glows centering active threat nodes */}
                <radialGradient id="heat-malicious-radial" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.45" />
                  <stop offset="35%" stopColor="#ef4444" stopOpacity="0.22" />
                  <stop offset="70%" stopColor="#991b1b" stopOpacity="0.06" />
                  <stop offset="100%" stopColor="#050506" stopOpacity="0" />
                </radialGradient>
                <radialGradient id="heat-suspicious-radial" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.4" />
                  <stop offset="40%" stopColor="#d97706" stopOpacity="0.18" />
                  <stop offset="75%" stopColor="#854d0e" stopOpacity="0.05" />
                  <stop offset="100%" stopColor="#050506" stopOpacity="0" />
                </radialGradient>
                <radialGradient id="heat-normal-radial" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#00e5ff" stopOpacity="0.15" />
                  <stop offset="50%" stopColor="#0891b2" stopOpacity="0.04" />
                  <stop offset="100%" stopColor="#050506" stopOpacity="0" />
                </radialGradient>
              </defs>

              {/* Threat Heatmap Grid (Matrix Sector overlay) */}
              {showHeatmap && (heatmapMode === "matrix" || heatmapMode === "hybrid") && (
                <g id="heatmap-matrix-grid" style={{ pointerEvents: "none" }}>
                  {[0, 1, 2].map((r) =>
                    [0, 1, 2, 3].map((c) => {
                      const xMin = c * 150;
                      const yMin = r * 160;
                      const width = 150;
                      const height = 160;
                      const idx = r * 4 + c;

                      const sectorName = [
                        ["Zone Alpha", "Edge Perimeter & Firewall WAN"],
                        ["Zone Beta", "Application Middleware Cluster"],
                        ["Zone Gamma", "Kubernetes Ingress Controllers"],
                        ["Zone Delta", "Production Databases Submesh"],
                        ["Sector Epsilon", "Corporate User Client LAN"],
                        ["Sector Zeta", "Active Directory & LDAP Domain"],
                        ["Sector Eta", "Enterprise Storage Backup Vault"],
                        ["Sector Theta", "Secure distributed PDF Systems"],
                        ["Cluster Iota", "SOC Security Information Auditing"],
                        ["Cluster Kappa", "Staging & DevOps CI/CD Nodes"],
                        ["Cluster Lambda", "SOAR Subnet Quarantine VLANs"],
                        ["Cluster Sigma", "Offline Cold Archive Repos"]
                      ][idx] || ["Active Segment Grid", "Tactical Coordinate Subnet"];

                      const nearbyNodes = nodes.filter(
                        (n) => n.x >= xMin && n.x < xMin + width && n.y >= yMin && n.y < yMin + height
                      );
                      const maxScore = nearbyNodes.length > 0 ? Math.max(...nearbyNodes.map((n) => n.score)) : 0;
                      const sumScores = nearbyNodes.reduce((acc, curr) => acc + curr.score, 0);
                      const density = Math.min(100, Math.round(nearbyNodes.length > 0 ? sumScores / nearbyNodes.length : 0));
                      const combinedHeat = Math.max(maxScore, density);

                      const isCritical = combinedHeat > 60 || nearbyNodes.some(n => n.severity === "Malicious");
                      const isWarning = combinedHeat > 25 || nearbyNodes.some(n => n.severity === "Suspicious");

                      // Define high-visual quality color highlights matching Sophisticated Dark
                      const cellBg = isCritical 
                        ? "rgba(220, 38, 38, 0.12)" 
                        : isWarning 
                        ? "rgba(234, 179, 8, 0.06)" 
                        : "rgba(6, 182, 212, 0.02)";
                      
                      const strokeColor = isCritical 
                        ? "rgba(220, 38, 38, 0.35)" 
                        : isWarning 
                        ? "rgba(234, 179, 8, 0.18)" 
                        : "rgba(41, 37, 36, 0.25)";

                      return (
                        <g key={`heatmap-cell-${c}-${r}`}>
                          <rect
                            x={xMin}
                            y={yMin}
                            width={width}
                            height={height}
                            fill={cellBg}
                            stroke={strokeColor}
                            strokeWidth="1"
                            strokeDasharray="4, 3"
                            className="transition-all duration-300"
                          />
                          
                          {/* Top Tag */}
                          <text
                            x={xMin + 8}
                            y={yMin + 14}
                            fill={isCritical ? "#f87171" : isWarning ? "#fbbf24" : "#475569"}
                            fontSize="7"
                            fontFamily="monospace"
                            className="font-mono tracking-wider opacity-60"
                          >
                            {`GRID-SEGMENT [C${c}:R${r}]`}
                          </text>

                          {/* Primary Sector Title */}
                          <text
                            x={xMin + 8}
                            y={yMin + 26}
                            fill={isCritical ? "#ffffff" : isWarning ? "#cbd5e1" : "#64748b"}
                            fontSize="8"
                            fontWeight="bold"
                            fontFamily="sans-serif"
                            className="tracking-tight"
                          >
                            {sectorName[0]}
                          </text>

                          {/* Sector Description */}
                          <text
                            x={xMin + 8}
                            y={yMin + 36}
                            fill={isCritical ? "#fca5a5" : isWarning ? "#cbd5e1" : "#475569"}
                            fontSize="7"
                            fontFamily="sans-serif"
                            className="opacity-80"
                          >
                            {sectorName[1]}
                          </text>

                          {/* Anomaly concentration readout */}
                          <text
                            x={xMin + 8}
                            y={yMin + 152}
                            fill={isCritical ? "#f87171" : isWarning ? "#fbbf24" : "#06b6d4"}
                            fontSize="9"
                            fontFamily="monospace"
                            fontWeight="bold"
                            className="font-mono"
                          >
                            {`HOTSPOT ENERGY: ${combinedHeat}%`}
                          </text>

                          {/* Quantitative Status indicator */}
                          <text
                            x={xMin + width - 8}
                            y={yMin + 152}
                            textAnchor="end"
                            fill={isCritical ? "#ef4444" : isWarning ? "#f59e0b" : "#10b981"}
                            fontSize="7.5"
                            fontFamily="monospace"
                            fontWeight="bold"
                            className="font-mono"
                          >
                            {isCritical ? "CRITICAL RISK" : isWarning ? "ELEVATED ALERT" : "OK"}
                          </text>
                        </g>
                      );
                    })
                  )}
                </g>
              )}

              {/* Dynamic Thermal glowing field backlighting */}
              {showHeatmap && (heatmapMode === "fuzzy" || heatmapMode === "hybrid") && (
                <g id="heatmap-fuzzy-glow-group" style={{ pointerEvents: "none" }}>
                  {nodes.map((n) => {
                    if (n.score < 10 && n.severity === "Normal") return null;
                    const gradientId = n.severity === "Malicious" 
                      ? "heat-malicious-radial" 
                      : n.severity === "Suspicious" 
                      ? "heat-suspicious-radial" 
                      : "heat-normal-radial";
                    const radius = Math.max(30, n.score * heatmapIntensity * 1.5);
                    return (
                      <circle
                        key={`heatmap-radial-${n.id}`}
                        cx={n.x}
                        cy={n.y}
                        r={radius}
                        fill={`url(#${gradientId})`}
                        className="transition-all duration-300"
                      />
                    );
                  })}
                </g>
              )}

              {/* Global Anomaly Heatmap Layer: 3D-Effect Topographical Gradient */}
              {showHeatmap && (heatmapMode === "topo" || heatmapMode === "hybrid") && (
                <g id="heatmap-topo-3d-group" style={{ pointerEvents: "none" }}>
                  {nodes.map((n) => {
                    const isHighRisk = n.score > 12 || n.severity === "Malicious" || n.severity === "Suspicious";
                    if (!isHighRisk) return null;

                    // Base foot radius of the 3D topographical extrusion cone, dynamically linked to anomaly score
                    const baseRadius = Math.max(25, n.score * heatmapIntensity * 1.55);

                    // Multi-elevation peak thermal colors representing topographical elevation limits
                    let colors = {
                      base: "#06b6d4",   // cyan-500
                      mid: "#3b82f6",    // blue-500
                      high: "#4f46e5",   // indigo-600
                      peak: "#a855f7",   // purple-500
                      tip: "#f43f5e"     // rose-500
                    };

                    if (n.severity === "Malicious") {
                      colors = {
                        base: "#ef4444", // red-500
                        mid: "#ea580c",  // orange-600
                        high: "#d97706", // amber-600
                        peak: "#b45309", // amber-700
                        tip: "#ffffff"   // superheated white peak
                      };
                    } else if (n.severity === "Suspicious") {
                      colors = {
                        base: "#f59e0b", // amber-500
                        mid: "#ea580c",  // orange-600
                        high: "#d97706", // amber-600
                        peak: "#eab308", // yellow-500
                        tip: "#ffffff"   // yellow peak core
                      };
                    }

                    // Define discrete contour elevations: level elevation, scaling factor and perspective visual offset dy
                    const elements = [
                      { rxScale: 1.0, ryScale: 0.65, dy: 0, opacity: 0.08, strokeOpacity: 0.15, color: colors.base },
                      { rxScale: 0.8, ryScale: 0.52, dy: -4, opacity: 0.14, strokeOpacity: 0.28, color: colors.mid },
                      { rxScale: 0.6, ryScale: 0.39, dy: -8, opacity: 0.22, strokeOpacity: 0.44, color: colors.high },
                      { rxScale: 0.4, ryScale: 0.26, dy: -12, opacity: 0.34, strokeOpacity: 0.65, color: colors.peak },
                      { rxScale: 0.18, ryScale: 0.13, dy: -16, opacity: 0.65, strokeOpacity: 0.9, color: colors.tip }
                    ];

                    return (
                      <g key={`topo-peak-${n.id}`} className="transition-all duration-300">
                        {/* Render individual circular and wireframe topographical projection lines */}
                        {elements.map((el, index) => {
                          const rx = baseRadius * el.rxScale;
                          const ry = baseRadius * el.rxScale * 0.55; // Perspective pitch elliptical distortion
                          const cy = n.y + el.dy;

                          return (
                            <g key={`topo-contour-${index}`}>
                              {/* Elevation Concentric Isoline Rings with Glowing 3D Base Fills */}
                              <ellipse
                                cx={n.x}
                                cy={cy}
                                rx={rx}
                                ry={ry}
                                fill={el.color}
                                fillOpacity={el.opacity}
                                stroke={el.color}
                                strokeOpacity={el.strokeOpacity}
                                strokeWidth="0.8"
                                className="transition-all duration-300"
                              />

                              {/* Orthographic 3D projection elevation guides connecting successive levels */}
                              {index > 0 && (
                                <>
                                  {/* Left ridge line connector */}
                                  <line
                                    x1={n.x - rx}
                                    y1={cy}
                                    x2={n.x - (baseRadius * elements[index - 1].rxScale)}
                                    y2={n.y + elements[index - 1].dy}
                                    stroke={el.color}
                                    strokeWidth="0.45"
                                    strokeOpacity="0.18"
                                  />
                                  {/* Right ridge line connector */}
                                  <line
                                    x1={n.x + rx}
                                    y1={cy}
                                    x2={n.x + (baseRadius * elements[index - 1].rxScale)}
                                    y2={n.y + elements[index - 1].dy}
                                    stroke={el.color}
                                    strokeWidth="0.45"
                                    strokeOpacity="0.18"
                                  />
                                </>
                              )}
                            </g>
                          );
                        })}

                        {/* Topographical Altitude text badge hovering over the high-stress peaks */}
                        <g transform={`translate(${n.x}, ${n.y - 25})`}>
                          <rect
                            x="-22"
                            y="-9"
                            width="44"
                            height="11"
                            rx="1.5"
                            fill="#06060a"
                            fillOpacity="0.95"
                            stroke={colors.base}
                            strokeWidth="0.5"
                          />
                          <text
                            textAnchor="middle"
                            y="-1.5"
                            fill={colors.base}
                            fontSize="6.5"
                            fontWeight="bold"
                            fontFamily="monospace"
                            className="font-mono tracking-widest fill-current"
                          >
                            {`S:${n.score}M`}
                          </text>
                        </g>
                      </g>
                    );
                  })}
                </g>
              )}

              {/* Connected Linework vectors with animated threat flow pulse offsets */}
              <g id="grid-links-group">
                {links.map((link, idx) => {
                  const srcNode = nodes.find((n) => n.id === link.source);
                  const tgtNode = nodes.find((n) => n.id === link.target);

                  if (!srcNode || !tgtNode) return null;

                  // Highlighting path colors and stroke widths according to status severity
                  const isThreat = link.threatDetected || srcNode.severity === "Malicious" || tgtNode.severity === "Malicious";
                  const isSuspicious = srcNode.severity === "Suspicious" || tgtNode.severity === "Suspicious";
                  const strokeColor = !link.isActive
                    ? "#111827"
                    : isThreat
                    ? "#ef4444"
                    : isSuspicious
                    ? "#eab308"
                    : "#1e293b";

                  const strokeWidth = !link.isActive ? 1 : isThreat ? 2.5 : isSuspicious ? 1.8 : 1.2;

                  return (
                    <g key={`lnk-${idx}`}>
                      {/* Standard Connector Line */}
                      <line
                        x1={srcNode.x}
                        y1={srcNode.y}
                        x2={tgtNode.x}
                        y2={tgtNode.y}
                        stroke={strokeColor}
                        strokeWidth={strokeWidth}
                        opacity={!link.isActive ? 0.25 : 0.8}
                        strokeDasharray={isThreat ? "5, 4" : undefined}
                      />

                      {/* Animated sliding packet payload indicator dots */}
                      {link.isActive && (
                        <circle r="3.5" fill={isThreat ? "#ef4444" : isSuspicious ? "#f59e0b" : "#06b6d4"}>
                          <animateMotion
                            dur={isThreat ? "1.5s" : isSuspicious ? "2.5s" : "4s"}
                            repeatCount="indefinite"
                            path={`M ${srcNode.x} ${srcNode.y} L ${tgtNode.x} ${tgtNode.y}`}
                          />
                        </circle>
                      )}
                    </g>
                  );
                })}
              </g>

              {/* PREDICTIVE LATERAL PATHS OVERLAY */}
              {showPredictiveOverlay && (
                <g id="predictive-paths-layer" style={{ pointerEvents: "none" }}>
                  {lateralLinks.map((p, idx) => {
                    const srcNode = nodes.find((n) => n.id === p.source);
                    const tgtNode = nodes.find((n) => n.id === p.target);
                    if (!srcNode || !tgtNode) return null;

                    return (
                      <g key={`pred-lnk-${idx}`}>
                        {/* Glowing Wide Translucent Orange Underlay */}
                        <line
                          x1={srcNode.x}
                          y1={srcNode.y}
                          x2={tgtNode.x}
                          y2={tgtNode.y}
                          stroke="#f97316"
                          strokeWidth="5.5"
                          opacity="0.25"
                          strokeLinecap="round"
                          className="animate-pulse"
                        />
                        {/* Thin High-Intensity Orange Dashed Path Line */}
                        <line
                          x1={srcNode.x}
                          y1={srcNode.y}
                          x2={tgtNode.x}
                          y2={tgtNode.y}
                          stroke="#f97316"
                          strokeWidth="1.8"
                          strokeDasharray="5, 3"
                          opacity="0.95"
                          strokeLinecap="round"
                        />
                        {/* Rapidly flowing lateral movement signaling dot */}
                        <circle r="3.5" fill="#f97316" filter="drop-shadow(0 0 5px #f97316)">
                          <animateMotion
                            dur="1.3s"
                            repeatCount="indefinite"
                            path={`M ${srcNode.x} ${srcNode.y} L ${tgtNode.x} ${tgtNode.y}`}
                          />
                        </circle>
                      </g>
                    );
                  })}
                </g>
              )}

              {/* Node nodes representation mapping */}
              <g id="grid-nodes-group">
                {nodes.map((node) => {
                  const isSelected = selectedNodeId === node.id;
                  
                  // Color selectors according to Green=Normal, Yellow=Suspicious, Red=Malicious
                  let colorValue = "#10b981"; // Normal (Green)
                  let shadowColor = "rgba(16, 185, 129, 0.4)";
                  if (node.severity === "Suspicious") {
                    colorValue = "#eab308"; // Suspicious (Yellow)
                    shadowColor = "rgba(234, 179, 8, 0.5)";
                  } else if (node.severity === "Malicious") {
                    colorValue = "#ef4444"; // Malicious (Red)
                    shadowColor = "rgba(239, 68, 68, 0.6)";
                  }

                  const radius = node.type === "Firewall" ? 14 : node.type === "Database" || node.type === "Server" ? 11 : 8.5;
                  const isShielded = shieldedNodeIds.includes(node.id);

                  return (
                    <g
                      key={node.id}
                      transform={`translate(${node.x}, ${node.y})`}
                      className="cursor-pointer transition-shadow"
                    >
                      {/* Background selection circle indicator */}
                      {isSelected && (
                        <circle
                          r={radius + 8}
                          fill="none"
                          stroke="#00e5ff"
                          strokeWidth="1"
                          strokeDasharray="3, 2"
                          className="animate-spin"
                          style={{ transformOrigin: "center", animationDuration: "12s" }}
                        />
                      )}

                      {/* Ripple pulsing echo ring */}
                      {node.severity === "Malicious" && (
                        <circle r={radius + 15} fill="none" stroke="#ef4444" strokeWidth="1.2" opacity="0.6">
                          <animate attributeName="r" values={`${radius};${radius + 18}`} dur="1.8s" repeatCount="indefinite" />
                          <animate attributeName="opacity" values="0.8;0" dur="1.8s" repeatCount="indefinite" />
                        </circle>
                      )}

                      {/* Defensive Shield Forcefield Overlay Ring */}
                      {isShielded && (
                        <circle
                          r={radius + 6}
                          fill="none"
                          stroke="#22d3ee"
                          strokeWidth="2.2"
                          strokeDasharray="3, 2"
                          opacity="0.85"
                          className="animate-pulse"
                          style={{ animationDuration: "2s" }}
                        />
                      )}

                      {/* Interactive Target Circle */}
                      <circle
                        r={radius}
                        fill={isShielded ? "#083344" : colorValue}
                        stroke={isShielded ? "#22d3ee" : isSelected ? "#ffffff" : "#090d16"}
                        strokeWidth={isSelected ? 2 : 1.5}
                        filter={`drop-shadow(0 0 8px ${isShielded ? "#22d3ee" : colorValue})`}
                        onMouseDown={(e) => handleNodeMouseDown(node.id, e)}
                        className="transition-all hover:scale-110"
                      />

                      {/* Tiny overlay letter badge for node type designation */}
                      <text
                        textAnchor="middle"
                        dy="3"
                        fill={isShielded ? "#22d3ee" : "#050506"}
                        fontSize="8"
                        fontWeight="bold"
                        className="select-none pointer-events-none"
                      >
                        {isShielded ? "🛡️" : node.type.slice(0, 1)}
                      </text>

                      {/* Micro Shield floating overlay icon */}
                      {isShielded && (
                        <g transform={`translate(${radius + 4}, ${-radius - 4})`} className="animate-bounce">
                          <circle r="6" fill="#083344" stroke="#22d3ee" strokeWidth="1" />
                          <path d="M-2.5,-1.5 L2.5,-1.5 L2.5,1 C2.5,2 0,3.5 0,3.5 C0,3.5 -2.5,2 -2.5,1 Z" fill="#22d3ee" />
                        </g>
                      )}

                      {/* Mini floating description text when selected or threat detected */}
                      <text
                        y={radius + 12}
                        textAnchor="middle"
                        fill={isShielded ? "#22d3ee" : colorValue}
                        fontSize="9"
                        fontWeight="bold"
                        fontFamily="monospace"
                        className="select-none pointer-events-none drop-shadow-md font-mono"
                      >
                        {node.label}
                      </text>

                      {/* Hostname & IP Address label directly below the node */}
                      <text
                        y={radius + 22}
                        textAnchor="middle"
                        fill="#94a3b8"
                        fontSize="8"
                        fontWeight="normal"
                        fontFamily="monospace"
                        className="select-none pointer-events-none drop-shadow-md font-mono opacity-90"
                      >
                        {`${node.id} (${node.ip})`}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>

            {/* Heatmap Custom Interactive Control Panel */}
            <div className="absolute top-4 left-4 bg-[#07070a]/90 backdrop-blur-md border border-[#1e1e2d] w-64 rounded p-3 text-[10px] font-mono shadow-2xl transition-all z-20 pointer-events-auto">
              <div className="flex items-center justify-between border-b border-[#1b1b26] pb-2 mb-2">
                <div className="flex items-center gap-1.5 font-bold text-white uppercase font-sans text-xs tracking-tight">
                  <Flame className="w-3.5 h-3.5 text-red-500 animate-pulse" />
                  <span>Threat Density Overlay</span>
                </div>
                <button
                  onClick={() => setHeatmapSettingsExpanded(!heatmapSettingsExpanded)}
                  className="text-slate-500 hover:text-white font-bold px-1 select-none cursor-pointer"
                >
                  {heatmapSettingsExpanded ? "[-]" : "[+]"}
                </button>
              </div>

              {heatmapSettingsExpanded ? (
                <div className="space-y-3">
                  {/* Heatmap Master Toggle */}
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">OVERLAY STATE:</span>
                    <button
                      onClick={() => setShowHeatmap(!showHeatmap)}
                      className={`px-2 py-0.5 rounded text-[8.5px] font-bold uppercase transition-all tracking-wider cursor-pointer ${
                        showHeatmap 
                          ? "bg-red-950/40 text-red-400 border border-red-800" 
                          : "bg-slate-900 text-slate-500 border border-gray-800"
                      }`}
                    >
                      {showHeatmap ? "ACTIVE ENGINE" : "BYPASSED"}
                    </button>
                  </div>

                  {/* Mode Selector */}
                  <div className="space-y-1">
                    <span className="text-slate-500 block uppercase text-[8px]">Visualization Mode:</span>
                    <div className="grid grid-cols-4 gap-1">
                      {(["fuzzy", "topo", "matrix", "hybrid"] as const).map((m) => (
                        <button
                          key={m}
                          onClick={() => setHeatmapMode(m)}
                          disabled={!showHeatmap}
                          className={`py-1 text-[7.5px] font-bold uppercase rounded border transition-all cursor-pointer ${
                            !showHeatmap
                              ? "opacity-30 cursor-not-allowed border-transparent bg-[#111] text-stone-600"
                              : heatmapMode === m
                              ? "bg-cyan-950/50 border-cyan-500 text-cyan-400 font-bold"
                              : "bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {m === "fuzzy" ? "Thermal" : m === "topo" ? "3D Topo" : m === "matrix" ? "Grid" : "Hybrid"}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Intensity Slider */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-slate-500 uppercase text-[8px]">
                      <span className="flex items-center gap-1"><Sliders className="w-2.5 h-2.5" /> Thermal Radius:</span>
                      <span className="text-cyan-400 font-bold">{heatmapIntensity.toFixed(1)}x</span>
                    </div>
                    <input
                      type="range"
                      min="0.5"
                      max="2.5"
                      step="0.1"
                      value={heatmapIntensity}
                      disabled={!showHeatmap || heatmapMode === "matrix"}
                      onChange={(e) => setHeatmapIntensity(parseFloat(e.target.value))}
                      className="w-full h-1 bg-gray-900 rounded-lg appearance-none cursor-pointer accent-cyan-500 disabled:opacity-30 disabled:cursor-not-allowed"
                    />
                  </div>

                  {/* Top 3 hotspots feeds */}
                  {showHeatmap && (
                    <div className="space-y-1.5 border-t border-[#14141d] pt-2">
                      <span className="text-slate-500 block uppercase text-[8px]">Dynamic Network Hotspots:</span>
                      <div className="space-y-1">
                        {getTopSectors().length === 0 ? (
                          <div className="text-slate-600 text-[8.5px] italic text-center py-1">All segments optimal.</div>
                        ) : (
                          getTopSectors().map((sec, i) => (
                            <div key={i} className="flex justify-between items-center bg-[#0d0d14] p-1.5 rounded border border-[#14141d]">
                              <div className="flex items-center gap-1 min-w-0">
                                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                                  sec.status === "CRITICAL" ? "bg-red-500 animate-pulse" : sec.status === "ELEVATED" ? "bg-yellow-500" : "bg-emerald-500"
                                }`} />
                                <span className="text-slate-300 text-[8.5px] truncate font-sans" title={sec.name}>{sec.name.split(" (")[0]}</span>
                              </div>
                              <span className={`font-bold font-mono text-[9px] shrink-0 text-right ${
                                sec.status === "CRITICAL" ? "text-red-400" : sec.status === "ELEVATED" ? "text-yellow-400" : "text-emerald-400"
                              }`}>
                                {sec.combined}%
                              </span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-[9px] text-slate-500">
                  Engine: <span className={showHeatmap ? "text-emerald-400 font-bold" : "text-slate-500 font-bold"}>{showHeatmap ? "RUNNING" : "STANDBY"}</span> ({heatmapMode.toUpperCase()})
                </div>
              )}
            </div>

            {/* Float Coordinates Overlay matching Sophisticated Dark design specs */}
            <div className="absolute bottom-4 left-4 p-3 bg-[#0d0d14]/85 backdrop-blur-md border border-[#1e1e28] rounded pointer-events-none font-mono">
              <div className="text-[10px] text-cyan-400 mb-0.5 tracking-wider font-bold">LIVE TELEMETRY COORDS</div>
              <div className="text-sm font-bold text-white flex gap-3">
                <span>LAT: 40.7128</span>
                <span className="text-[#1a1a20]">|</span>
                <span>LON: -74.0060</span>
              </div>
              <div className="text-[9px] text-slate-500 mt-1 uppercase">
                TARGET INTEGRITY LEVEL: HIGH-SCALE ENTERPRISE NYC-01 CLUSTER
              </div>
            </div>

            {/* Predictive Lateral Movement Tracker Interactive Control Panel */}
            <div className="absolute top-4 right-4 bg-[#07070a]/90 backdrop-blur-md border border-[#1e1e2d] w-64 rounded p-3 text-[10px] font-mono shadow-2xl transition-all z-20 pointer-events-auto">
              <div className="flex items-center justify-between border-b border-[#1b1b26] pb-2 mb-2">
                <div className="flex items-center gap-1.5 font-bold text-white uppercase font-sans text-xs tracking-tight">
                  <TrendingUp className="w-3.5 h-3.5 text-orange-500 animate-pulse" />
                  <span>LATERAL TRAJECTORY PROJECTION</span>
                </div>
                <button
                  onClick={() => setPredictivePanelExpanded(!predictivePanelExpanded)}
                  className="text-slate-500 hover:text-white font-bold px-1 select-none cursor-pointer"
                >
                  {predictivePanelExpanded ? "[-]" : "[+]"}
                </button>
              </div>

              {predictivePanelExpanded ? (
                <div className="space-y-3">
                  {/* Master Toggle */}
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">PROJECTION OVERLAY:</span>
                    <button
                      onClick={() => setShowPredictiveOverlay(!showPredictiveOverlay)}
                      className={`px-2 py-0.5 rounded text-[8.5px] font-bold uppercase transition-all tracking-wider cursor-pointer ${
                        showPredictiveOverlay
                          ? "bg-orange-950/45 text-orange-400 border border-orange-850"
                          : "bg-slate-900 text-slate-500 border border-gray-800"
                      }`}
                    >
                      {showPredictiveOverlay ? "ENABLED [ORANGE]" : "PAUSED"}
                    </button>
                  </div>

                  {/* Root selection setting */}
                  <div className="space-y-1">
                    <span className="text-slate-500 block uppercase text-[8px]">Infiltration Origins:</span>
                    <div className="grid grid-cols-2 gap-1">
                      <button
                        onClick={() => setPredictiveRootType("all_threats")}
                        disabled={!showPredictiveOverlay}
                        className={`py-1 text-[8px] font-bold uppercase rounded border transition-all cursor-pointer ${
                          !showPredictiveOverlay
                            ? "opacity-30 cursor-not-allowed border-transparent bg-[#111] text-stone-600"
                            : predictiveRootType === "all_threats"
                            ? "bg-orange-950/30 border-orange-500 text-orange-400 font-bold"
                            : "bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200"
                        }`}
                        title="Project lateral movement starting from ALL malicious and suspicious network hosts"
                      >
                        All Compromises
                      </button>
                      <button
                        onClick={() => setPredictiveRootType("selected_only")}
                        disabled={!showPredictiveOverlay}
                        className={`py-1 text-[8px] font-bold uppercase rounded border transition-all cursor-pointer ${
                          !showPredictiveOverlay
                            ? "opacity-30 cursor-not-allowed border-transparent bg-[#111] text-stone-600"
                            : predictiveRootType === "selected_only"
                            ? "bg-orange-950/30 border-orange-500 text-orange-400 font-bold"
                            : "bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200"
                        }`}
                        title="Project lateral movement starting ONLY from the selected node (if it has a threat)"
                      >
                        Selected Only
                      </button>
                    </div>
                  </div>

                  {/* Multi-Hop Depth configuration */}
                  <div className="space-y-1">
                    <span className="text-slate-500 block uppercase text-[8px]">Projection Hop Depth:</span>
                    <div className="grid grid-cols-2 gap-1">
                      {[1, 2].map((depth) => (
                        <button
                          key={depth}
                          onClick={() => setPredictiveHopDepth(depth as 1 | 2)}
                          disabled={!showPredictiveOverlay}
                          className={`py-1 text-[8px] font-bold uppercase rounded border transition-all cursor-pointer ${
                            !showPredictiveOverlay
                              ? "opacity-30 cursor-not-allowed border-transparent bg-[#111] text-stone-600"
                              : predictiveHopDepth === depth
                              ? "bg-orange-950/30 border-orange-500 text-orange-400 font-bold"
                              : "bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {depth} Hop{depth > 1 ? "s" : ""}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* High Risk Target Feed */}
                  {showPredictiveOverlay && (
                    <div className="space-y-2 border-t border-[#14141d] pt-2">
                      <div className="flex justify-between items-center text-[8px] text-slate-500 uppercase">
                        <span>Projected Infiltration Targets:</span>
                        <span className="text-orange-400 font-bold">{vulnerableTargets.length} TARGETS</span>
                      </div>
                      <div className="space-y-1.5 max-h-40 overflow-y-auto pr-0.5">
                        {vulnerableTargets.length === 0 ? (
                          <div className="text-slate-600 text-[8.5px] italic text-center py-2 bg-[#09090e] rounded border border-dashed border-[#1a1a25]">
                            No impending lateral moves calculated. Network isolated.
                          </div>
                        ) : (
                          vulnerableTargets.map((target) => (
                            <div key={target.nodeId} className="bg-[#0b0c10] p-1.5 rounded border border-[#1b1b2a] flex flex-col gap-1">
                              <div className="flex justify-between items-center">
                                <span className="text-slate-200 text-[8.5px] font-bold truncate block w-28" title={`${target.label} (Hop ${target.hop})`}>
                                  {target.label}
                                </span>
                                <span className={`text-[8.5px] font-mono font-bold px-1 rounded ${
                                  target.maxRisk > 70 ? "text-red-400 bg-red-950/20" : "text-orange-400 bg-orange-950/20"
                                }`}>
                                  {target.maxRisk}% risk
                                </span>
                              </div>
                              <div className="text-[7.5px] text-slate-500 truncate font-mono">
                                IP: {target.ip} • Hop {target.hop} from {target.sourceNodeId}
                              </div>
                              {/* Tactical defense quick triggers */}
                              <div className="flex gap-1 mt-1 pt-1 border-t border-[#13131e]">
                                <button
                                  onClick={() => toggleShieldNode(target.nodeId)}
                                  className={`flex-1 py-0.5 text-[7px] font-bold uppercase rounded border transition-all cursor-pointer ${
                                    shieldedNodeIds.includes(target.nodeId)
                                      ? "bg-cyan-950/35 text-cyan-400 border-cyan-700 hover:bg-cyan-900/40"
                                      : "bg-slate-900 text-slate-400 border-slate-800 hover:border-cyan-500 hover:text-white"
                                  }`}
                                  title="Deploy active firewall security shield on this forecasted target"
                                >
                                  {shieldedNodeIds.includes(target.nodeId) ? "🛡️ Shielded" : "Deploy Shield"}
                                </button>
                                <button
                                  onClick={() => severActiveConnection(target.nodeId, target.sourceNodeId)}
                                  className="py-0.5 px-1.5 bg-slate-900 text-red-400 border border-slate-800 hover:border-red-500 hover:bg-red-950/15 text-[7px] font-bold uppercase rounded transition-all cursor-pointer"
                                  title="Sever parent connection to proactively block credential transmission"
                                >
                                  Sever Link
                                </button>
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  )}

                  {/* Active Shields Tracking list */}
                  {shieldedNodeIds.length > 0 && (
                    <div className="border-t border-[#14141d] pt-2 space-y-1">
                      <span className="text-slate-500 block uppercase text-[8px]">Active Defensive Shields:</span>
                      <div className="flex flex-wrap gap-1 text-[7.5px]">
                        {shieldedNodeIds.map(id => (
                          <div key={id} className="flex items-center gap-1 bg-cyan-950/30 text-cyan-400 border border-cyan-800/60 px-1 py-0.5 rounded font-mono">
                            <span>{id}</span>
                            <button 
                              onClick={() => toggleShieldNode(id)}
                              className="text-red-400 hover:text-red-200 font-bold ml-0.5 cursor-pointer"
                              title="Decommission security shield"
                            >
                              x
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-[9px] text-slate-500">
                  Model: <span className={showPredictiveOverlay ? "text-orange-400 font-bold" : "text-slate-500 font-bold"}>{showPredictiveOverlay ? "ACTIVE" : "BYPASSED"}</span> ({predictiveHopDepth} Hops Engine)
                </div>
              )}
            </div>
          </div>

          {/* Quick Node inspector drawer panel immediately below the canvas graph */}
          {selectedNodeObj ? (
            <div className="border-t border-[#1a1a20] bg-[#070b13] p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="space-y-1 w-full sm:w-auto">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] uppercase font-mono px-2 py-0.5 border rounded-sm font-bold ${
                    selectedNodeObj.severity === "Malicious"
                      ? "bg-red-950/50 border-red-500/50 text-red-400 animate-pulse"
                      : selectedNodeObj.severity === "Suspicious"
                      ? "bg-yellow-950/50 border-yellow-500/50 text-yellow-500"
                      : "bg-[#0c2420] border-[#10b981]/50 text-[#10b981]"
                  }`}>
                    {selectedNodeObj.severity.toUpperCase()} Anomalous
                  </span>
                  <span className="text-xs font-semibold text-slate-400 font-mono">
                    ID: {selectedNodeObj.id}
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-1.5 font-sans">
                  {selectedNodeObj.label} <span className="text-xs font-mono text-cyan-400">({selectedNodeObj.ip})</span>
                </h3>
                <p className="text-xs text-slate-400 max-w-xl font-mono">
                  {selectedNodeObj.details || "Steady stream of network packets. No current behavioral alerts flagged."}
                </p>
                <div className="text-[10px] text-slate-500 font-mono flex gap-4">
                  <span>OS: <strong className="text-slate-300">{selectedNodeObj.os}</strong></span>
                  <span>ANOMALY RATING: <strong className={selectedNodeObj.score > 50 ? "text-red-400" : "text-cyan-400"}>{selectedNodeObj.score}/100</strong></span>
                </div>
              </div>

              {/* Security Admin Tactical Controls for Selected Nodes */}
              <div className="flex gap-2 w-full sm:w-auto">
                <button
                  id={`btn-[#isolate]-${selectedNodeObj.id}`}
                  onClick={() => executeIsolation(selectedNodeObj.id)}
                  className="flex-1 sm:flex-none px-3 py-2 bg-red-950/40 border border-red-800/60 hover:border-red-500 text-[10px] text-red-400 uppercase font-mono font-semibold hover:bg-red-900/30 rounded transition-all cursor-pointer"
                  title="Sever host network IP and assign to quarantine isolated VLAN cluster."
                >
                  Isolate Node
                </button>
                <button
                  id={`btn-[#kill-traffic]-${selectedNodeObj.id}`}
                  onClick={() => executeKillTraffic(selectedNodeObj.id)}
                  className="flex-1 sm:flex-none px-3 py-2 bg-slate-900 border border-gray-800 hover:border-cyan-500/50 text-[10px] text-cyan-400 uppercase font-mono font-semibold hover:bg-[#0c1324] rounded transition-all cursor-pointer"
                  title="Drop all active TCP/UDP linkages associated with this host router-wide."
                >
                  Kill Traffic
                </button>
                <button
                  onClick={async () => {
                    setSelectedNodeId(selectedNodeObj.id);
                    await generateMitigationWorkflowCode();
                  }}
                  disabled={generatingPlaybook}
                  className="px-3 py-2 bg-slate-900 border border-[#1a1a20] text-slate-300 hover:text-white uppercase font-mono font-semibold hover:bg-[#151522] rounded transition-all flex items-center gap-1.5 text-[10px] cursor-pointer"
                >
                  <Workflow className="w-3 h-3 text-cyan-400" />
                  {generatingPlaybook ? "Orchestrating..." : "SOAR Script"}
                </button>
              </div>
            </div>
          ) : (
            <div className="border-t border-[#1a1a20] bg-[#07090f] p-4 text-center text-xs text-slate-500 font-mono">
              Pro-tip: Click on any active network node inside the central diagram visualizer to trigger target isolation scripts or review host telemetry.
            </div>
          )}
        </section>

        {/* RIGHT COLUMN: LIVE AI INCIDENT FORENSICS & WORKFLOW RUNNERS */}
        <aside className={`${
          activeTab === "forensics"
            ? "col-span-12 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-6 overflow-y-auto"
            : "hidden"
        } border-l border-[#1a1a20] bg-[#08080c] flex flex-col`}>
          
          {/* Active alerts trigger panel */}
          <div className="p-4 border-b border-[#1a1a20]">
            <h2 className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center justify-between">
              <span>Active Security Alerts</span>
              <span className="text-[9px] font-bold text-red-500 animate-pulse uppercase">● ACTIVE CRITICAL</span>
            </h2>

            <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
              {alerts.length === 0 ? (
                <div className="text-center py-4 text-xs text-slate-500 font-mono">No active intrusion alerts. Normal.</div>
              ) : (
                alerts.map((a) => {
                  const isSelected = selectedAlertId === a.id;
                  const scoreColor = a.score > 80 ? "text-red-400" : a.score > 50 ? "text-yellow-400" : "text-green-400";
                  
                  return (
                    <button
                      key={a.id}
                      id={`alert-row-${a.id}`}
                      onClick={() => {
                        setSelectedAlertId(a.id);
                        // find matching logs
                        if (a.category === "Brute Force") setActiveScenario("bruteforce");
                        else if (a.category === "DNS Tunneling") setActiveScenario("dns_exfilt");
                        else if (a.category === "Ransomware Lateral Spread") setActiveScenario("ransomware");
                        else if (a.category === "SQL Injection") setActiveScenario("sqli");
                        else setActiveScenario("general");
                      }}
                      className={`w-full text-left p-2 rounded border transition-all relative flex flex-col gap-1 cursor-pointer ${
                        isSelected
                          ? "bg-[#160d0b] border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.1)] text-white"
                          : "bg-[#090b11] border-gray-900 hover:border-slate-800 text-slate-400"
                      }`}
                    >
                      <div className="flex justify-between items-center text-[10px] font-mono">
                        <span className="text-slate-500">{a.timestamp ? a.timestamp.slice(11, 19) : "00:00:00"} UTC</span>
                        <span className={`font-bold ${scoreColor}`}>Score: {a.score}</span>
                      </div>

                      <div className="text-xs font-bold text-slate-100 uppercase tracking-tight line-clamp-1">
                        {a.threatTitle}
                      </div>

                      <div className="flex justify-between text-[10px] font-mono text-slate-400">
                        <span>SRC: {a.sourceNode}</span>
                        <span>PROT: {a.protocol}</span>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          {/* Realtime Cyber Forensics Log Analyzer widget (Power of Server-side Gemini) */}
          <div className="p-4 border-b border-[#1a1a20] space-y-3">
            <h2 className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1">
              <Brain className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span>AI Automated Log Forensic Expert</span>
            </h2>

            <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
              Feed raw, unsanitized network logs below. Aegis AI compiles threat telemetry, maps laterally compromised endpoints, audits SOC2/GDPR compliance risk, and designs response vectors using <strong className="text-cyan-400">Gemini 3.5</strong>.
            </p>

            <div className="space-y-2">
              <label className="text-[9px] font-mono text-slate-500 uppercase tracking-wider block">Raw Network Log Trail</label>
              <textarea
                value={customLogs}
                onChange={(e) => setCustomLogs(e.target.value)}
                className="w-full h-24 bg-[#060609] border border-gray-850 p-2 font-mono text-[10px] text-cyan-500/90 rounded focus:border-cyan-500/50 focus:outline-none resize-none"
                placeholder="Paste telemetry traceroute, authentication events, or firewall records here..."
              />
            </div>

            {/* AI Forensics triggering action */}
            <button
              onClick={performAILogsForensics}
              disabled={generatingReport}
              id="btn-trigger-ai-forensics"
              className="w-full py-2 bg-cyan-950/45 hover:bg-cyan-900/40 border border-cyan-500/50 hover:border-cyan-400/80 text-cyan-400 text-xs uppercase font-mono tracking-wider font-semibold rounded flex items-center justify-center gap-2 transition-all cursor-pointer"
            >
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              {generatingReport ? "Performing Deep AI Analysis..." : "Compile Forensic Report"}
            </button>

            {reportError && (
              <div className="p-2.5 bg-red-950/20 border border-red-500/30 rounded text-[11px] font-mono text-red-400">
                ⚠️ Forensic Gateway Error: {reportError}
              </div>
            )}
          </div>

          {/* AI Forensic interactive analytical report details container */}
          <div className="p-4 flex-1">
            {forensicReport ? (
              <div className="space-y-4 font-mono text-xs">
                
                {/* Forensic Results Header */}
                <div className="p-3 bg-[#0c181f] border border-cyan-500/30 rounded">
                  <div className="flex justify-between items-center text-[10px] uppercase font-bold text-cyan-400 mb-1.5">
                    <span>AI INCIDENT VERDICT</span>
                    <span className="bg-red-950 px-2 py-0.5 rounded text-red-400 text-[10px]">
                      {forensicReport.severity}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold text-white uppercase tracking-tight">
                    {forensicReport.threatTitle}
                  </h4>
                  <div className="text-slate-500 text-[10px] mt-1 flex justify-between">
                    <span>PROBABILITY CRITICALITY:</span>
                    <span className="text-cyan-400 font-bold">{forensicReport.probabilityScore}%</span>
                  </div>
                </div>

                {/* Narrative Summary */}
                <div className="space-y-1">
                  <div className="text-[10px] font-mono text-slate-500 uppercase">Chronology of compromised vector</div>
                  <p className="text-[11px] text-slate-300 bg-[#07090f]/90 p-2 rounded leading-relaxed border border-gray-900 select-all font-sans">
                    {forensicReport.forensicsSummary}
                  </p>
                </div>

                {/* Lateral movement flow list */}
                {forensicReport.lateralMovement && forensicReport.lateralMovement.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase flex items-center gap-1">
                      <CornerDownRight className="w-3" /> Implicated Lateral Spreads
                    </div>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {forensicReport.lateralMovement.map((lat, idx) => (
                        <div key={`lat-${idx}`} className="p-1.5 bg-gray-950 border border-slate-900 rounded text-[11px]">
                          <div className="flex justify-between font-bold text-cyan-400">
                            <span>{lat.from} → {lat.to}</span>
                            <span className="text-red-400">{lat.maliceIndicator}</span>
                          </div>
                          <div className="text-[10px] text-slate-400">Protocol: {lat.protocol}</div>
                          <div className="text-[9px] text-slate-500 italic font-sans mt-0.5">{lat.reason}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Compliance Impact list */}
                {forensicReport.complianceViolations && forensicReport.complianceViolations.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase">Regulatory Compliance Impact</div>
                    <div className="grid grid-cols-2 gap-2">
                      {forensicReport.complianceViolations.map((comp, idx) => (
                        <div key={`comp-${idx}`} className="p-1.5 bg-[#140f09] border border-yellow-800/40 rounded">
                          <div className="font-bold text-yellow-500 text-[10px]">{comp.framework}</div>
                          <div className="text-[9px] text-slate-300 leading-tight truncate" title={comp.clause}>{comp.clause}</div>
                          <div className="text-[8px] bg-yellow-950 text-yellow-400 px-1 py-0.5 uppercase tracking-wider text-center mt-1 font-bold">
                            {comp.status}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommended Mitigation checklist */}
                {forensicReport.recommendedMitigations && forensicReport.recommendedMitigations.length > 0 && (
                  <div className="space-y-1.5">
                    <div className="text-[10px] text-slate-500 uppercase">Tactical Mitigation Plan Checklist</div>
                    <ul className="space-y-1 select-text">
                      {forensicReport.recommendedMitigations.map((mit, idx) => (
                        <li key={`mit-${idx}`} className="p-1.5 bg-[#0a1412] text-emerald-400 border border-[#10b981]/15 text-[10px] rounded flex gap-1.5">
                          <span>✓</span>
                          <span>{mit}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Predictive Risk 30 day Outlook */}
                {forensicReport.predictiveRiskState && (
                  <div className="p-2.5 bg-yellow-950/15 border border-yellow-500/20 text-yellow-400 rounded text-[10px] leading-relaxed">
                    <strong>30-DAY PREDICTIVE RISK OUTLOOK:</strong> {forensicReport.predictiveRiskState}
                  </div>
                )}

              </div>
            ) : (
              <div className="h-full border border-dashed border-gray-900 rounded p-6 flex flex-col justify-center items-center text-center text-slate-600 font-mono">
                <Compass className="w-8 h-8 text-slate-700 mb-2" />
                <span>Forensic results window empty.</span>
                <span className="text-[10px] text-slate-500 mt-1 max-w-sm">
                  Click 'Compile Forensic Report' above to engage Gemini AI analytical audits relative to selected logs.
                </span>
              </div>
            )}
          </div>
        </aside>

      </div>

      {/* DETAILED TACTICAL RESPONSE WORKSPACE & AUTOMATION SCRIPTS (DOCK DRAWER) */}
      <section className={`${
        activeTab === "compliance" ? "flex-1 overflow-y-auto" : "hidden"
      } bg-[#07070a] border-t border-[#1a1a20] p-6 grid grid-cols-1 md:grid-cols-12 gap-6`}>
        
        {/* Compliance and Auditing Controls Panel */}
        <div className="col-span-1 md:col-span-4 space-y-3.5">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
              <span>Compliance & SIEM Audits</span>
            </h2>
            <button
              onClick={handleExportCSVReport}
              id="export-csv-auditor-btn"
              className="px-2.5 py-1 text-[10px] font-mono tracking-wide font-bold uppercase rounded border border-cyan-500/40 text-cyan-400 hover:bg-cyan-950/30 transition-all flex items-center gap-1 cursor-pointer"
            >
              <Download className="w-3 h-3" /> Export CSV Logs
            </button>
          </div>

          <p className="text-xs text-slate-400 font-sans leading-relaxed">
            Download raw event streams matching structural GDPR, HIPAA, or SOC2 controls. Security compliance is checked dynamically against simulated event variables.
          </p>

          <div className="space-y-2">
            {COMPLIANCE_FRAMEWORKS_DATA.map((frm) => (
              <div key={frm.framework} className="bg-[#0b0c11] border border-[#1a1a24] p-2.5 rounded text-xs flex justify-between items-center">
                <div className="space-y-0.5">
                  <div className="font-bold text-slate-200">{frm.framework} Compliance Pool</div>
                  <div className="text-[10px] text-slate-500 truncate max-w-xs">{frm.description}</div>
                  <div className="text-[9px] text-slate-400 font-mono">Recommendation: <span className="text-cyan-400">{frm.recommendation}</span></div>
                </div>
                <div className="text-right whitespace-nowrap">
                  <span className={`text-[10px] px-2 py-0.5 font-bold uppercase ${
                    frm.unmanagedThreats > 0
                      ? "bg-red-950/30 text-red-400 border border-red-900/40"
                      : "bg-[#0b2210] text-emerald-400 border border-[#10b981]/20"
                  }`}>
                    Score: {frm.complianceScore}%
                  </span>
                  <div className="text-[10px] font-mono text-slate-400 mt-1 uppercase text-right">
                    {frm.status}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Dynamic AI orchestrated SOAR response playbook blocks */}
        <div className="col-span-1 md:col-span-5 space-y-4 border-t md:border-t-0 md:border-l md:border-r border-[#1a1a20] pt-6 md:pt-0 md:px-6">
          <div className="flex justify-between items-center">
            <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Workflow className="w-4 h-4 text-cyan-400" />
              <span>Orchestrated AI Mitigation Playbook</span>
            </h3>

            {role !== "auditor" && (
              <button
                id="mitigation-[#gen-orchestra]-btn"
                onClick={generateMitigationWorkflowCode}
                disabled={generatingPlaybook}
                className="px-3 py-1 bg-cyan-950 text-cyan-400 border border-cyan-800/80 hover:border-cyan-400 rounded font-mono text-[10px] uppercase font-bold transition-all flex items-center gap-1 animate-pulse"
              >
                <Cpu className="w-3 h-3" />
                {generatingPlaybook ? "Orchestrating script..." : "Generate Custom Playbook"}
              </button>
            )}
          </div>

          <p className="text-xs text-slate-400 font-sans leading-relaxed">
            Generate customized Ansible, Nginx, or Kubernetes scripts relative to the currently flagged threat IP. Automatically injects iptables drops and SIEM trigger payloads.
          </p>

          {playbookWorkflow ? (
            <div className="space-y-2">
              <div className="flex justify-between items-center p-2 bg-slate-900/50 rounded-t border-t border-r border-l border-gray-800 text-[10px] font-mono">
                <span className="text-emerald-400 font-bold uppercase">
                  TYPE: {playbookWorkflow.playbookType}
                </span>
                <button
                  onClick={copyPlaybookToClipboard}
                  className="text-slate-400 hover:text-cyan-400 transition-colors flex items-center gap-1 border border-gray-800 px-1.5 py-0.5 rounded"
                >
                  {copiedPlaybook ? <Check className="w-3 h-3 text-emerald-400" /> : <Clipboard className="w-3 h-3" />}
                  {copiedPlaybook ? "Copied" : "Copy"}
                </button>
              </div>

              {/* Code Script Block */}
              <pre className="p-3 bg-black border border-gray-850 rounded text-[9.5px] text-cyan-500 font-mono overflow-x-auto max-h-48 scrollbar">
                <code>{playbookWorkflow.script}</code>
              </pre>

              {/* Automation script mitigation explanation */}
              <div className="p-2.5 bg-slate-950 text-slate-400 rounded text-[10.5px] border border-gray-900 leading-relaxed font-sans">
                <strong>Orchestration explanation:</strong> {playbookWorkflow.explanation}
              </div>
            </div>
          ) : (
            <div className="border border-dashed border-gray-850 rounded p-6 text-center text-xs text-slate-600 font-mono">
              {playbookError ? (
                <div className="text-red-400">⚠️ Error: {playbookError}</div>
              ) : (
                <div className="space-y-1">
                  <div>No security script compiled.</div>
                  <div className="text-[10px] text-slate-500 text-center max-w-sm mx-auto">
                    Select a node of concern in the interactive graph above and trigger 'Generate Custom Playbook' to request an executable SOAR quarantine block script.
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* SIEM integration target settings blueprints */}
        <div className="col-span-1 md:col-span-3 space-y-4 mt-6 md:mt-0 pt-6 md:pt-0">
          <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
            <Globe className="w-4 h-4 text-cyan-400" />
            <span>SIEM Connector Blueprints</span>
          </h3>

          <p className="text-xs text-slate-400 font-sans leading-relaxed">
            Map out Aegis raw telemetry JSON models directly for enterprise syslog receivers.
          </p>

          <div className="space-y-2">
            {SIEM_INTEGRATIONS.map((siem) => (
              <div key={siem.name} className="p-2 border border-gray-900 bg-gray-950 rounded space-y-1.5 hover:border-slate-800">
                <div className="flex justify-between items-center">
                  <span className="text-slate-200 font-bold text-xs">{siem.name}</span>
                  <span className="text-[9px] bg-cyan-950 text-cyan-400 px-1.5 py-0.5 rounded border border-cyan-900/30 uppercase font-mono">
                    {siem.type}
                  </span>
                </div>
                <div className="text-[9px] font-mono text-slate-400">
                  Channel Hook: <code className="text-slate-300">{siem.channel}</code>
                </div>
                
                {/* Micro json print */}
                <details className="cursor-pointer group">
                  <summary className="text-[9px] font-mono text-cyan-400 group-open:text-slate-500 hover:underline">
                    Display JSON Blueprint
                  </summary>
                  <pre className="p-2 bg-black border border-slate-900 text-[8.5px] text-cyan-600 font-mono mt-1 overflow-x-auto rounded select-all">
                    <code>{siem.payloadExample}</code>
                  </pre>
                </details>
              </div>
            ))}
          </div>
        </div>

      </section>

      {/* FOOTER BAR matching the Sophisticated Dark design specifications exactly */}
      <footer className="h-12 border-t border-[#1a1a20] bg-[#0a0a0f] px-6 flex items-center justify-between font-mono text-[10px] text-slate-500">
        <div className="flex gap-6 items-center">
          <span className="flex items-center gap-1.5 text-cyan-400">
            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-ping" />
            AEGIS ENGINE SYSTEM SECURE
          </span>
          <span className="hidden sm:inline text-slate-700">|</span>
          <span className="hidden sm:inline uppercase">V3.82.0-STABLE SECURE HANDSHAKE</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="uppercase text-slate-400">Compliance Standard: NIST SP 800-53</span>
          <div className="w-px h-3 bg-gray-800"></div>
          <span>AUTO-SAVE: LIVE</span>
        </div>
      </footer>

    </div>
  );
}
