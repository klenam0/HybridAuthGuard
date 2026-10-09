import { getSeverity, severityKey } from "../config/severity";

const SIZES = {
  sm: "text-[11px] px-1.5 py-0.5 gap-1",
  md: "text-xs px-2 py-0.5 gap-1.5",
};

export default function SeverityBadge({ severity, size = "sm", className = "" }) {
  const key = severityKey(severity);
  const { Icon, label, badge } = getSeverity(key);

  return (
    <span
      className={`sev-badge inline-flex items-center rounded-md font-semibold uppercase tracking-wide whitespace-nowrap flex-shrink-0 ${SIZES[size] || SIZES.sm} ${badge} ${className}`}
      title={`${label} severity`}
    >
      <Icon className="w-3 h-3" aria-hidden="true" />
      {key}
    </span>
  );
}
