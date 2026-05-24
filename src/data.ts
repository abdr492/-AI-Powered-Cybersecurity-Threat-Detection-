import { NetworkNode, NetworkLink, ThreatAlert } from "./types";

// Helper to project nodes around a standard architectural structure
export const INITIAL_NODES: NetworkNode[] = [
  { id: "fw-01", label: "Edge Firewall", type: "Firewall", severity: "Normal", ip: "192.168.1.1", os: "FortiOS v7.2", score: 5, x: 400, y: 100, vx: 0, vy: 0, details: "Primary external link protection. Inspects ingress/egress port 80/443/53/22." },
  { id: "dc-01", label: "Primary Domain Controller", type: "Server", severity: "Normal", ip: "10.150.1.10", os: "Windows Server 2022", score: 12, x: 250, y: 350, vx: 0, vy: 0, details: "Active Directory Domain Services, Kerberos KDC, DNS Authority." },
  { id: "db-prod", label: "Customer Master DB", type: "Database", severity: "Normal", ip: "10.150.3.5", os: "PostgreSQL v15 (Linux)", score: 15, x: 150, y: 480, vx: 0, vy: 0, details: "Hosts PII, GDPR scope. Read-write workload from application servers." },
  { id: "db-backup", label: "Cold DR Database Replica", type: "Database", severity: "Normal", ip: "10.150.3.20", os: "PostgreSQL v15 (Linux)", score: 8, x: 100, y: 550, vx: 0, vy: 0, details: "Daily automated database backups sync pool. Strictly offline access." },
  { id: "srv-app-01", label: "E-Commerce App Server", type: "Server", severity: "Normal", ip: "10.150.2.14", os: "Ubuntu Server 22.04 LTS", score: 18, x: 400, y: 280, vx: 0, vy: 0, details: "Hosts public web backend. Interacts with database cluster." },
  { id: "srv-file-02", label: "Internal File Server Repo", type: "Server", severity: "Normal", ip: "10.150.2.45", os: "Windows Server 2019", score: 25, x: 550, y: 380, vx: 0, vy: 0, details: "SMB / DFS namespace repository. Holds core financial audit blueprints." },
  { id: "subnet-hr", label: "HR VLAN Subnet-A", type: "Subnet", severity: "Normal", ip: "10.0.1.0/24", os: "Cisco Catalyst Switch L3", score: 4, x: 650, y: 220, vx: 0, vy: 0, details: "Employee onboarding network, active laptops, printers, phones." },
  { id: "user-alice", label: "alice.workstation", type: "Workstation", severity: "Normal", ip: "10.0.1.15", os: "Windows 11 Enterprise", score: 10, x: 700, y: 150, vx: 0, vy: 0, details: "Alice Vance (Talent Acquisition). High SMB file activity logs track." },
  { id: "user-bob", label: "bob.dev-station", type: "Workstation", severity: "Normal", ip: "10.0.4.52", os: "Fedora Workstation v39", score: 14, x: 550, y: 500, vx: 0, vy: 0, details: "Bob Miller (Fullstack Developer). SSH access enabled to staging cluster, Git repository control." },
  { id: "user-admin", label: "ansible.admin-pod", type: "Workstation", severity: "Normal", ip: "10.150.2.22", os: "Alpine Security Linux", score: 2, x: 280, y: 200, vx: 0, vy: 0, details: "Automated configuration controller pod. Secure script engine node." },
  { id: "ext-attacker", label: "Anomalous Geolocation VPN", type: "External", severity: "Normal", ip: "84.32.190.4", os: "Proxy / Unknown Tor Exit", score: 45, x: 150, y: 150, vx: 0, vy: 0, details: "External ASN requesting high-payload HTTPS connections." }
];

export const INITIAL_LINKS: NetworkLink[] = [
  { source: "fw-01", target: "srv-app-01", bytesTransferred: 145020, protocol: "HTTPS/443", isActive: true, threatDetected: false },
  { source: "fw-01", target: "ext-attacker", bytesTransferred: 34220, protocol: "HTTPS/443", isActive: true, threatDetected: false },
  { source: "srv-app-01", target: "dc-01", bytesTransferred: 289000, protocol: "Kerberos/88", isActive: true, threatDetected: false },
  { source: "srv-app-01", target: "db-prod", bytesTransferred: 1492300, protocol: "Postgres/5432", isActive: true, threatDetected: false },
  { source: "srv-file-02", target: "dc-01", bytesTransferred: 52190, protocol: "SMB/445", isActive: true, threatDetected: false },
  { source: "user-alice", target: "srv-file-02", bytesTransferred: 812100, protocol: "SMB/445", isActive: true, threatDetected: false },
  { source: "user-bob", target: "srv-app-01", bytesTransferred: 242040, protocol: "SSH/22", isActive: true, threatDetected: false },
  { source: "user-admin", target: "srv-file-02", bytesTransferred: 40150, protocol: "SSH/22", isActive: true, threatDetected: false },
  { source: "user-admin", target: "dc-01", bytesTransferred: 12900, protocol: "WinRM/5985", isActive: true, threatDetected: false },
  { source: "db-prod", target: "db-backup", bytesTransferred: 4892410, protocol: "Postgres/5432", isActive: true, threatDetected: false },
  { source: "subnet-hr", target: "fw-01", bytesTransferred: 450120, protocol: "HTTPS/443", isActive: true, threatDetected: false }
];

export const INITIAL_ALERTS: ThreatAlert[] = [
  {
    id: "alert-101",
    timestamp: "2026-05-24T05:45:10Z",
    threatTitle: "Anomalous AD Query Volume",
    sourceNode: "srv-app-01",
    targetNode: "dc-01",
    protocol: "LDAP/389",
    severity: "Yellow",
    category: "Anomalous Portscan",
    status: "Investigating",
    score: 62,
    description: "Web application server requested 50+ LDAP records in under 3 seconds. Possible enumeration attempt."
  },
  {
    id: "alert-102",
    timestamp: "2026-05-24T05:50:32Z",
    threatTitle: "Host Geographic VPN Anomaly",
    sourceNode: "ext-attacker",
    targetNode: "srv-app-01",
    protocol: "HTTPS/443",
    severity: "Yellow",
    category: "SQL Injection",
    status: "Active",
    score: 74,
    description: "Incoming HTTPS payload contained multiple UNION-based database manipulation statements from untrusted ASN."
  }
];

// Forensics Log Snippets corresponding to different attacks
export const ATTACK_LOG_NARRATIVES = {
  bruteforce: `[2026-05-24T06:01:00Z] SSHD Connection opened from 10.0.1.15 on port 51221
[2026-05-24T06:01:01Z] SSHD pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.1.15 user=root
[2026-05-24T06:01:02Z] SSHD pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.1.15 user=admin
[2026-05-24T06:01:03Z] SSHD pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.1.15 user=operator
[2026-05-24T06:01:05Z] SSHD pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.1.15 user=sysadmin
[2026-05-24T06:01:07Z] SSHD Auth threshold exceeded for host 10.0.1.15. Attempting brute-force root dictionary.
[2026-05-24T06:01:10Z] SSHD Connection closed from 10.0.1.15 (attempts: 84)
[2026-05-24T06:01:12Z] SSHD Connection opened from 10.0.1.15 on port 51290
[2026-05-24T06:01:13Z] SSHD Accepted password for r_administrator from 10.0.1.15 port 51290 ssh2
[2026-05-24T06:01:14Z] SYSTEM: User r_administrator instantiated interactive TTY. Privilege Level: Admin.`,

  dns_exfilt: `[2026-05-24T05:58:20Z] DNS_REK: Host 10.0.4.52 requested TXT record for bGVha2VkX2NyZWRlbnRpYWxzX2RiX3VzZXI=.secure.external-rogue-ns.xyz
[2026-05-24T05:58:21Z] DNS_REK: Host 10.0.4.52 requested TXT record for dGhlX3F1aWNrX2Jyb3duX2ZveF9qdW1wc19vdmVy==.secure.external-rogue-ns.xyz
[2026-05-24T05:58:22Z] DNS_REK: Host 10.0.4.52 requested TXT record for Y29tcHJvbWlzZWRfYmFja3VwX3Bhc3N3b3JkX2hhc2g=.secure.external-rogue-ns.xyz
[2026-05-24T05:58:25Z] DNS_REK: Host 10.0.4.52 requested TXT record for SVNPTUFUSUNfU0VDVVJFX0FVRElUXzIwMjZfUERG.secure.external-rogue-ns.xyz
[2026-05-24T05:58:26Z] SYSTEM: Detected highly anomalous DNS TXT query volume (280 req/sec) from 10.0.4.52. High entropy subdomains suspect.
[2026-05-24T05:58:28Z] FIREWALL: DNS Tunnel protective alert flagged. Outbound DNS channel saturated. Payload size index: 94%`,

  ransomware: `[2026-05-24T05:52:12Z] SMBD: User alice.vance initiated SMB connect to Share://InternalBackup/Finances
[2026-05-24T05:52:15Z] SMBD: File modified: Shares/Finances/ledger_2025.xlsx renamed to Shares/Finances/ledger_2025.xlsx.locked
[2026-05-24T05:52:16Z] SMBD: File modified: Shares/Finances/tax_returns.pdf renamed to Shares/Finances/tax_returns.pdf.locked
[2026-05-24T05:52:17Z] SMBD: File modified: Shares/Finances/payroll_reports.csv renamed to Shares/Finances/payroll_reports.csv.locked
[2026-05-24T05:52:18Z] SMBD: File modified: Shares/Finances/executive_equity.doc renamed to Shares/Finances/executive_equity.doc.locked
[2026-05-24T05:52:19Z] SYSTEM ALERT: Continuous file write threshold exceeded on Host 10.150.2.45. Signature suggests ransomware encryption behavior.
[2026-05-24T05:52:21Z] SYSTEM NOTE: Shadow copy deletion cmd requested: 'vssadmin.exe delete shadows /all /quiet' from script hook.`,

  sqli: `[2026-05-24T05:48:40Z] NGINX_ACCESS: 84.32.190.4 - - "POST /api/v1/auth/login HTTP/1.1" 401 Payload: "username=admin' UNION SELECT null,username,password FROM users--&password=foo"
[2026-05-24T05:48:42Z] NGINX_ACCESS: 84.32.190.4 - - "POST /api/v1/auth/login HTTP/1.1" 401 Payload: "username=admin' AND 1=1 UNION SELECT name, schema() FROM information_schema.tables--&password=x"
[2026-05-24T05:48:45Z] NGINX_ACCESS: 84.32.190.4 - - "POST /api/v1/auth/login HTTP/1.1" 200 Payload: "username=admin' OR '1'='1'--&password=foo"
[2026-05-24T05:48:46Z] DB-PROD Postgres: Command logs read: Query 'SELECT * FROM accounts WHERE email = 'admin' OR '1'='1'' executed on postgres_db.
[2026-05-24T05:48:48Z] WAF: Blind SQL Injection alert triggered on 84.32.190.4. SQL parsing indicates schema structural exfiltration.`,

  general: `[2026-05-24T06:02:10Z] DHCPD: Allocated dynamic IP 10.0.1.182 to host laptop-fiona
[2026-05-24T06:02:15Z] ACTIVE_DIR: User john.doe authorized via Kerberos ticket. Granted access to DC-01.
[2026-05-24T06:02:18Z] SMBD: alice.vance opened file Shares/Marketing/pitch_deck_v2.pptx (Success, read access).
[2026-05-24T06:02:22Z] POSTGRES_DB: Normal application connection accepted from AppServer Host 10.150.2.14 on pool-02.
[2026-05-24T06:02:30Z] ROUTER-EXT: Keepalive check to Gateway 192.168.1.1: Ping successful. 0.4ms latency bounds.`
};

// Compliance audit report summaries
export const COMPLIANCE_FRAMEWORKS_DATA = [
  {
    framework: "GDPR",
    description: "General Data Protection Regulation (EU). Focuses on protection of personally identifiable information (PII).",
    complianceScore: 84,
    unmanagedThreats: 1,
    status: "CRITICAL RISK",
    recommendation: "Ensure absolute database encryption for Postgres master pools. Restrict cross-border active VPN profiles."
  },
  {
    framework: "HIPAA",
    description: "Health Insurance Portability and Accountability Act. Governs ePHI (electronic protected health information) protection.",
    complianceScore: 91,
    unmanagedThreats: 0,
    status: "COMPLIANT-GUARDED",
    recommendation: "Review multi-factor log verification cycles for HR VLAN nodes periodic audits."
  },
  {
    framework: "SOC 2 Type II",
    description: "Trust Services Criteria framework focusing on security, availability, processing integrity, and confidentiality of customer data.",
    complianceScore: 78,
    unmanagedThreats: 2,
    status: "NON-COMPLIANT",
    recommendation: "Remediate lateral SMB communication vectors instantly. Deploy automated Ansible security groups blockbook triggers."
  },
  {
    framework: "PCI-DSS v4.0",
    description: "Payment Card Industry Data Security Standard. Targets credit card transaction flows security.",
    complianceScore: 88,
    unmanagedThreats: 1,
    status: "RISK-ALERT",
    recommendation: "Isolate Database DR replica cluster immediately. Restrict default SSH server remote root privileges."
  }
];

// SIEM Out-of-the-Box configuration blueprints
export const SIEM_INTEGRATIONS = [
  {
    name: "Splunk Enterprise SIEM",
    type: "HEC Endpoint",
    channel: "Splunk-HTTP-Event-Collector",
    activeRule: "eval threat_criticality = if(ai_probability_score > 90, 'CRITICAL', 'ALERT')",
    docUrl: "https://docs.splunk.com/Documentation",
    payloadExample: `{
  "sourcetype": "ai:threat:telemetry",
  "event": {
    "detector": "AI_CYBER_AGENT",
    "threat": "\${alert.threatTitle}",
    "source_ip": "\${alert.sourceIp}",
    "confidence_rating": "\${alert.probabilityScore}"
  }
}`
  },
  {
    name: "Microsoft Sentinel",
    type: "Log Analytics Workspace API",
    channel: "SentinelDataConnector",
    activeRule: "SecurityAlert | where ProviderName == 'AICyberThreatDetector' | extend TargetIP = tostring(ExtendedProperties['TargetNode'])",
    docUrl: "https://learn.microsoft.com/en-us/azure/sentinel",
    payloadExample: `{
  "mms_provider": "AI_THREAT_GRAPH",
  "alertName": "\${alert.threatTitle}",
  "severity": "High",
  "compromisedEntity": "\${alert.sourceIp}"
}`
  },
  {
    name: "Elastic Search SIEM (Kibana Security)",
    type: "Elastic Agent Integration",
    channel: "security-threat-logs-*",
    activeRule: "any where threat.severity == 'critical' and ai_analysts.quarantine == false",
    docUrl: "https://www.elastic.co/guide/en/security",
    payloadExample: `{
  "@timestamp": "\${alert.timestamp}",
  "threat": {
    "action": "\${alert.category}",
    "probability": "\${alert.probabilityScore}"
  }
}`
  }
];
