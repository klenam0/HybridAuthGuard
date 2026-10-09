import { SEVERITY, SEVERITY_LEVELS } from "./severity";

// Shared Recharts styling. Values are CSS variables, so charts follow the
// light/dark theme without re-rendering.
export const chartTooltip = {
  contentStyle: {
    background: "var(--bg-elevated)",
    border: "1px solid var(--border)",
    borderRadius: 8,
    color: "var(--text-primary)",
    fontSize: 12,
    boxShadow: "0 8px 24px rgba(15, 23, 42, 0.18)",
  },
  labelStyle: { color: "var(--text-primary)", fontWeight: 600, marginBottom: 4 },
  itemStyle: { color: "var(--text-secondary)", padding: 0 },
};

export const barCursor = { fill: "var(--accent-dim)" };
export const lineCursor = { stroke: "var(--border-light)", strokeWidth: 1 };

export const axisTick = { fill: "var(--text-secondary)", fontSize: 11 };
export const axisLine = { stroke: "var(--border)" };
export const gridStroke = "var(--border)";

export const SEVERITY_SERIES = SEVERITY_LEVELS.map((key) => ({
  key,
  label: SEVERITY[key].label,
  color: SEVERITY[key].chart,
}));

export function formatHour(hour) {
  return `${String(hour).padStart(2, "0")}:00`;
}
