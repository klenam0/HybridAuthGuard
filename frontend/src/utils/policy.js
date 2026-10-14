import { Ban, FileText, ListChecks, ShieldAlert } from "lucide-react";

// What the running backend actually does, from /api/config (and /api/status
// until the config arrives). The UI states only what this mode does:
//   v3      incident tiers (block / step-up / queue / log); block is off when
//           its rate is 0; step-up is a simulated MFA challenge, recorded and
//           never enforced
//   legacy  HIGH-severity alerts trigger a simulated block
// ML alerts exist only in ML_MODE "legacy" (v4 raises none; with the forest
// retired there is no ML step at all).
export function enginePolicy(backendConfig, status) {
  const rulesMode = backendConfig?.rules_mode || status?.rules_mode || null;
  const mlMode = backendConfig?.ml_mode || status?.ml_mode || null;
  const v3 = rulesMode === "v3";
  const rates = backendConfig?.response?.v3_policy?.tier_rates || {};
  return {
    known: rulesMode !== null,
    v3,
    rulesMode,
    mlMode,
    mlAlerts: mlMode === null ? null : mlMode === "legacy",
    mlStep:
      mlMode === null
        ? null
        : mlMode === "legacy" || backendConfig?.ml_v4_iforest === "on",
    blockOn: v3 ? Number(rates.block || 0) > 0 : true,
    stepUpRate: v3 ? Number(rates.step_up || 0) : 0,
    queueRate: v3 ? Number(rates.queue || 0) : 0,
  };
}

export const TIERS = {
  block: {
    label: "Blocked (simulated)",
    short: "Block",
    Icon: Ban,
    badge: "bg-red-500/15 text-red-600 border-red-500/30",
  },
  step_up: {
    label: "Challenged (simulated MFA, not enforced)",
    short: "Step-up",
    Icon: ShieldAlert,
    badge: "bg-orange-500/15 text-orange-600 border-orange-500/30",
  },
  queue: {
    label: "Analyst queue",
    short: "Queue",
    Icon: ListChecks,
    badge: "bg-cyan-500/15 text-cyan-600 border-cyan-500/30",
  },
  log: {
    label: "Logged only",
    short: "Log",
    Icon: FileText,
    badge: "bg-slate-500/15 text-[color:var(--text-secondary)] border-slate-500/30",
  },
};

// The incident tier recorded on a v3 alert, or null (legacy alerts).
export function alertTier(alert) {
  const t = alert?.incident?.tier || alert?.response?.tier;
  return t && TIERS[t] ? t : null;
}
