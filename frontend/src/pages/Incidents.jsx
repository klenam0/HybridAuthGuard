// frontend/src/pages/Incidents.jsx

import { useCallback, useEffect, useState } from "react";
import PageHeader from "../components/PageHeader";
import TierBadge from "../components/TierBadge";
import { API } from "../config/api";
import { enginePolicy, TIERS } from "../utils/policy";

const FILTERS = ["all", "block", "step_up", "queue", "log"];
const REFRESH_MS = 5000;

// Event time (epoch seconds, UTC) as "YYYY-MM-DD HH:MM:SS".
function eventTime(ts) {
  if (ts === null || ts === undefined) return "-";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function fmtScore(score) {
  if (!Array.isArray(score)) return "-";
  return score.map((v) => (typeof v === "number" ? v.toFixed(3) : String(v))).join(", ");
}

// Incidents (source IP, calendar day) from /api/incidents, newest first.
// Fetched here rather than in the global poll: the endpoint exists only in
// v3 mode.
export default function Incidents({ data }) {
  const { stats, status, backendConfig } = data;
  const policy = enginePolicy(backendConfig, status);
  const [tier, setTier] = useState("all");
  const [rows, setRows] = useState([]);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    const q = tier === "all" ? "" : `&tier=${tier}`;
    try {
      const res = await fetch(`${API}/incidents?limit=500${q}`);
      if (res.status === 404) {
        setRows([]);
        setError("Incidents exist only when the backend runs RULES_MODE v3.");
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setRows(await res.json());
      setError(null);
    } catch (e) {
      setError(`Could not load incidents (${e.message || "request failed"}).`);
    }
  }, [tier]);

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const counts = stats?.incident_tiers || {};
  const rates = backendConfig?.response?.v3_policy?.tier_rates || {};
  const rateText = (t) =>
    t === "log" ? "everything else" : rates[t] ? `at most ${rates[t]}/day` : "off";

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader routeId="incidents">
        <div className="flex items-center gap-1 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg p-1.5 overflow-x-auto">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setTier(f)}
              className={`px-2.5 sm:px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-colors ${
                tier === f
                  ? "bg-cyan-500/15 text-cyan-600"
                  : "text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)]"
              }`}
            >
              {f === "all" ? "All" : TIERS[f].short}
            </button>
          ))}
        </div>
      </PageHeader>

      {/* Tier summary: incidents in the store per tier, and each tier's rate */}
      <div id="incident-tiers" className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {Object.keys(TIERS).map((t) => (
          <div
            key={t}
            className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4"
          >
            <TierBadge tier={t} long className="whitespace-normal" />
            <p className="text-2xl font-semibold mt-2 text-[color:var(--text-primary)]">
              {counts[t] ?? 0}
            </p>
            <p className="ui-caption mt-1">
              incidents · {policy.v3 ? rateText(t) : "v3 only"}
            </p>
          </div>
        ))}
      </div>

      {policy.v3 && (backendConfig?.response?.v3_policy?.floor_detectors || []).length > 0 && (
        <p className="ui-caption text-[color:var(--text-secondary)]">
          Step-up and queue admit only incidents with an alert of{" "}
          {backendConfig.response.v3_policy.floor_detectors.join(", ")}; the rest stay at log.
        </p>
      )}

      {error && (
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 ui-body text-[color:var(--text-secondary)]">
          {error}
        </div>
      )}

      <div
        id="incident-list"
        className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl overflow-hidden"
      >
        <div className="hidden md:grid md:grid-cols-12 gap-3 px-5 py-3 border-b border-[color:var(--border)] bg-[color:var(--bg-elevated)]">
          <div className="col-span-3 ui-table-head">Incident (IP · day)</div>
          <div className="col-span-2 ui-table-head">Tier</div>
          <div className="col-span-3 ui-table-head">Detectors</div>
          <div className="col-span-1 ui-table-head">Alerts</div>
          <div className="col-span-1 ui-table-head">Email</div>
          <div className="col-span-2 ui-table-head">Last alert (event time)</div>
        </div>
        <div className="divide-y divide-[color:var(--border)] max-h-[32rem] overflow-y-auto">
          {rows.length === 0 && !error ? (
            <p className="py-14 text-center ui-body text-[color:var(--text-secondary)]">
              No incidents yet
            </p>
          ) : (
            rows.map((r) => (
              <div
                key={r.incident_id}
                className="flex flex-col gap-1.5 md:grid md:grid-cols-12 md:gap-3 md:items-center px-4 md:px-5 py-3"
              >
                <div className="md:col-span-3 min-w-0">
                  <p className="text-sm font-mono font-semibold text-[color:var(--text-primary)] truncate">
                    {r.ip}
                  </p>
                  <p className="ui-caption font-mono">
                    {r.day} · score {fmtScore(r.score)}
                  </p>
                </div>
                <div className="md:col-span-2">
                  <TierBadge tier={r.tier} />
                </div>
                <div className="md:col-span-3 ui-caption text-[color:var(--text-secondary)]">
                  {(r.detectors || []).join(", ") || "-"}
                </div>
                <div className="md:col-span-1 text-sm text-[color:var(--text-primary)]">
                  {r.alerts}
                </div>
                <div className="md:col-span-1 ui-caption">
                  {r.email && r.email !== "not_required" ? r.email : "-"}
                </div>
                <div className="md:col-span-2 ui-caption font-mono">
                  {eventTime(r.last_ts)}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <p className="ui-caption leading-6">
        An incident is one source IP on one calendar day. Its tier is the
        highest it reached: step-up is a simulated MFA challenge (recorded, not
        enforced); the queue is for an analyst; the rest are logged. One email
        per incident entering the block or step-up tier, with an hourly limit
        and digest. Showing the latest {rows.length} incidents.
      </p>
    </div>
  );
}
