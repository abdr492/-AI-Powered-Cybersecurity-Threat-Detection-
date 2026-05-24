import React, { useState } from "react";
import { Shield, Brain, Server, Users, Radio, CheckCircle, RefreshCw, Send } from "lucide-react";
import { UserRole } from "../types";

interface RoleHeaderProps {
  currentRole: UserRole;
  setRole: (role: UserRole) => void;
  onRefreshMetrics: () => void;
  systemStatus: "OPTIMAL" | "ATTACK_SUSPECTED" | "MITIGATION_ENGAGED";
  siemConnected: boolean;
  onToggleSiem: () => void;
}

export const RoleHeader: React.FC<RoleHeaderProps> = ({
  currentRole,
  setRole,
  onRefreshMetrics,
  systemStatus,
  siemConnected,
  onToggleSiem
}) => {
  const [testingWebhook, setTestingWebhook] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  const rolesList: { value: UserRole; label: string; desc: string; color: string }[] = [
    { value: "admin", label: "IT Administrator", desc: "Full tactical management & automated playbook authorization", color: "text-emerald-400 border-emerald-500/30" },
    { value: "analyst", label: "Security Analyst", desc: "Deep forensics investigation & predictive analytics query access", color: "text-orange-400 border-orange-500/30" },
    { value: "auditor", label: "Compliance Auditor", desc: "Read-only compliance charts & printable report export permissions", color: "text-blue-400 border-blue-500/30" }
  ];

  const handleTestSIEM = () => {
    setTestingWebhook(true);
    setTestResult(null);
    setTimeout(() => {
      setTestingWebhook(false);
      setTestResult("Webhook success: Code 202 accepted at Splunk/Azure endpoint.");
      setTimeout(() => setTestResult(null), 4000);
    }, 1200);
  };

  return (
    <header className="border-b border-gray-800 bg-[#060b16] px-6 py-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
      {/* Brand / Logo */}
      <div className="flex items-center gap-3">
        <div className="relative p-2.5 bg-red-950/30 border border-red-500/30 rounded-lg pulse-glow-red">
          <Shield className="w-6 h-6 text-red-500 animate-pulse" />
          <Radio className="w-3 h-3 text-red-400 absolute top-1 right-1 animate-ping" />
        </div>
        <div>
          <h1 className="text-lg font-bold font-sans text-gray-100 tracking-tight flex items-center gap-2">
            Aegis AI <span className="text-xs px-2 py-0.5 bg-red-950/50 border border-red-500/50 text-red-400 uppercase tracking-widest font-mono rounded-sm">Threat Engine v4.8</span>
          </h1>
          <p className="text-xs text-slate-500 font-mono tracking-normal">
            Force-Directed Real-Time Behavioral Anomaly Telemetry
          </p>
        </div>
      </div>

      {/* Role-Based Access Controls (RBAC) */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 bg-[#0a1224] border border-gray-800 rounded-lg p-2.5 w-full md:w-auto">
        <span className="text-xs uppercase tracking-wider font-mono text-slate-400 flex items-center gap-1.5 px-2">
          <Users className="w-3.5 h-3.5 text-slate-500" /> Privilege Role:
        </span>
        <div className="flex gap-1.5 w-full sm:w-auto">
          {rolesList.map((r) => {
            const isSelected = currentRole === r.value;
            return (
              <button
                key={r.value}
                id={`rbac-btn-${r.value}`}
                onClick={() => setRole(r.value)}
                title={r.desc}
                className={`px-3 py-1 text-xs font-mono font-medium rounded-md transition-all uppercase tracking-wide cursor-pointer ${
                  isSelected
                    ? "bg-[#111e3b] text-cyan-400 border border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.15)]"
                    : "text-slate-400 border border-transparent hover:bg-gray-800/50"
                }`}
              >
                {r.value}
              </button>
            );
          })}
        </div>
      </div>

      {/* Integrity Metrics & SIEM Sync Status */}
      <div className="flex flex-wrap items-center gap-4 text-xs font-mono w-full md:w-auto md:justify-end">
        {/* Threat State Indicators */}
        <div className="flex items-center gap-2 bg-[#090f1d] border border-gray-850 px-3 py-1.5 rounded-md">
          <span className="text-slate-500">SYSTEM STATE:</span>
          {systemStatus === "OPTIMAL" && (
            <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
              <CheckCircle className="w-3.5 h-3.5" /> BASES OPTIMAL
            </span>
          )}
          {systemStatus === "ATTACK_SUSPECTED" && (
            <span className="flex items-center gap-1.5 text-red-500 font-bold animate-pulse">
              ⚠️ ATTACK SUSPECTED
            </span>
          )}
          {systemStatus === "MITIGATION_ENGAGED" && (
            <span className="flex items-center gap-1.5 text-cyan-400 font-bold">
              🛠️ MITIGATION ACTIVE
            </span>
          )}
        </div>

        {/* Webhook & SIEM connector status */}
        <div className="flex items-center gap-3 bg-[#090f1d] border border-gray-850 px-3 py-1.5 rounded-md">
          <div className="flex items-center gap-2">
            <span className="text-slate-500">SIEM PLATFORM:</span>
            <button
              onClick={onToggleSiem}
              id="siem-toggle-action"
              className={`px-2 py-0.5 uppercase tracking-widest text-[10px] rounded-sm font-bold border transition-colors ${
                siemConnected
                  ? "bg-cyan-950/50 border-cyan-500/50 text-cyan-400"
                  : "bg-slate-900 border-slate-700 text-slate-500"
              }`}
            >
              {siemConnected ? "LIVE SYNC" : "OFFLINE"}
            </button>
          </div>
          {siemConnected && (
            <button
              id="btn-test-siem-webhook"
              onClick={handleTestSIEM}
              disabled={testingWebhook}
              className="text-slate-400 hover:text-cyan-400 transition-colors flex items-center gap-1 px-1 py-0.5 border border-gray-800 rounded hover:border-cyan-500/30"
              title="Post Test Event Webhook to SIEM Platform"
            >
              {testingWebhook ? (
                <RefreshCw className="w-3 h-3 animate-spin text-cyan-400" />
              ) : (
                <Send className="w-3 h-3" />
              )}
              Test Webhook
            </button>
          )}
        </div>

        {/* Global manual refresh trigger */}
        <button
          onClick={onRefreshMetrics}
          id="manual-refresh-trigger"
          className="p-2 border border-gray-800 hover:border-cyan-500/50 hover:bg-slate-900 rounded bg-slate-950 text-slate-400 hover:text-cyan-400 transition-all cursor-pointer"
          title="Regenerate dynamic scenario metrics"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {testResult && (
        <div className="absolute top-16 right-6 z-50 bg-[#091a2e] border border-cyan-500/50 text-cyan-300 px-4 py-2 rounded-md shadow-lg font-mono text-xs flex items-center gap-2 animate-bounce">
          <div className="w-2 h-2 bg-cyan-400 rounded-full animate-ping" />
          {testResult}
        </div>
      )}
    </header>
  );
};
