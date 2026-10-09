import {
  AlertTriangle,
  CircleAlert,
  Info,
  OctagonAlert,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";

// Single source of truth for alert severity. Colours come from the
// --badge-* and --chart-* theme variables so both themes stay in step, and
// every severity has its own icon so it is never conveyed by colour alone.
export const SEVERITY = {
  CRITICAL: {
    label: "Critical",
    rank: 4,
    Icon: OctagonAlert,
    badge:
      "bg-[color:var(--badge-critical-bg)] text-[color:var(--badge-critical-text)]",
    text: "text-[color:var(--badge-critical-text)]",
    chart: "var(--chart-critical)",
  },
  HIGH: {
    label: "High",
    rank: 3,
    Icon: AlertTriangle,
    badge: "bg-[color:var(--badge-high-bg)] text-[color:var(--badge-high-text)]",
    text: "text-[color:var(--badge-high-text)]",
    chart: "var(--chart-high)",
  },
  MEDIUM: {
    label: "Medium",
    rank: 2,
    Icon: CircleAlert,
    badge:
      "bg-[color:var(--badge-medium-bg)] text-[color:var(--badge-medium-text)]",
    text: "text-[color:var(--badge-medium-text)]",
    chart: "var(--chart-medium)",
  },
  LOW: {
    label: "Low",
    rank: 1,
    Icon: Info,
    badge: "bg-[color:var(--badge-low-bg)] text-[color:var(--badge-low-text)]",
    text: "text-[color:var(--badge-low-text)]",
    chart: "var(--chart-low)",
  },
};

// Severities the backend actually emits, highest first.
export const SEVERITY_LEVELS = ["HIGH", "MEDIUM", "LOW"];

export function severityKey(value) {
  const key = String(value || "").toUpperCase();
  return SEVERITY[key] ? key : "LOW";
}

export function getSeverity(value) {
  return SEVERITY[severityKey(value)];
}

// Active-state classes for severity filter tabs (Live Alerts, Alert Log).
export const FILTER_ACTIVE = {
  ALL: "bg-slate-700 text-white",
  ...Object.fromEntries(
    Object.entries(SEVERITY).map(([key, s]) => [key, s.badge]),
  ),
};

// Overall threat level from /api/threat-level. It is only meaningful while
// the backend is reachable; otherwise the level is unknown.
export function getThreatLevel(level, connectionStatus) {
  if (connectionStatus === "offline" || connectionStatus === "connecting") {
    return {
      key: "UNKNOWN",
      label: "Unknown",
      Icon: ShieldQuestion,
      className:
        "bg-[color:var(--bg-elevated)] text-[color:var(--text-secondary)]",
    };
  }
  const key = String(level || "NORMAL").toUpperCase();
  if (SEVERITY[key]) {
    const s = SEVERITY[key];
    return { key, label: s.label, Icon: s.Icon, className: s.badge };
  }
  return {
    key: "NORMAL",
    label: "Normal",
    Icon: ShieldCheck,
    className: "bg-green-500/15 text-green-400",
  };
}
