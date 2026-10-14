import { TIERS } from "../utils/policy";

// The v3 incident response tier. `long` shows the full label, e.g.
// "Challenged (simulated MFA, not enforced)".
export default function TierBadge({ tier, long = false, className = "" }) {
  const t = TIERS[tier];
  if (!t) return null;
  const { Icon } = t;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-semibold whitespace-nowrap flex-shrink-0 ${t.badge} ${className}`}
      title={`Incident tier: ${t.label}`}
    >
      <Icon className="w-3 h-3" aria-hidden="true" />
      {long ? t.label : t.short}
    </span>
  );
}
