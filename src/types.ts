export type UserRole = "admin" | "analyst" | "auditor";

export interface NetworkNode {
  id: string;
  label: string;
  type: "Workstation" | "Database" | "Server" | "Subnet" | "External" | "Firewall";
  severity: "Normal" | "Suspicious" | "Malicious";
  ip: string;
  os: string;
  details?: string;
  score: number; // 0 - 100 anomaly level
  isCompromised?: boolean;
  // Canvas coordinate helpers
  x: number;
  y: number;
  targetX?: number;
  targetY?: number;
  vx: number;
  vy: number;
  fx?: number | null;
  fy?: number | null;
}

export interface NetworkLink {
  source: string;
  target: string;
  bytesTransferred: number;
  protocol: string;
  isActive: boolean;
  threatDetected: boolean;
  pulseOffset?: number;
}

export interface ThreatAlert {
  id: string;
  timestamp: string;
  threatTitle: string;
  sourceNode: string;
  targetNode: string;
  protocol: string;
  severity: "Green" | "Yellow" | "Red"; // Green=Normal, Yellow=Suspicious, Red=Malicious
  category: "Brute Force" | "DNS Tunneling" | "Ransomware Lateral Spread" | "SQL Injection" | "Anomalous Portscan";
  status: "Active" | "Investigating" | "Quarantined" | "Resolved";
  score: number;
  description: string;
}

export interface LateralMovement {
  from: string;
  to: string;
  protocol: string;
  reason: string;
  maliceIndicator: string;
}

export interface AbnormalLogin {
  user: string;
  sourceIp: string;
  location: string;
  unusualFactors: string;
}

export interface ComplianceViolation {
  framework: "GDPR" | "HIPAA" | "SOC2" | "PCI-DSS" | "NIST";
  clause: string;
  threatLevel: "High" | "Medium" | "Low" | string;
  status: "NON-COMPLIANT" | "RISK-ALERT" | string;
}

export interface AIForensicReport {
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  threatTitle: string;
  probabilityScore: number;
  forensicsSummary: string;
  maliciousNodes: string[];
  lateralMovement: LateralMovement[];
  abnormalLogins: AbnormalLogin[];
  complianceViolations: ComplianceViolation[];
  predictiveRiskState: string;
  recommendedMitigations: string[];
}

export interface PlaybookWorkflow {
  playbookType: string;
  script: string;
  explanation: string;
}
