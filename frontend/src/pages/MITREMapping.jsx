import { ExternalLink, Shield } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";

const TACTIC_COLORS = {
  "Credential Access": "bg-red-500/20 text-red-400 border-red-500/30",
  "Defense Evasion / Persistence":
    "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Persistence: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  "Initial Access": "bg-purple-500/20 text-purple-400 border-purple-500/30",
  "Lateral Movement": "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
};

function TacticBadge({ tactic }) {
  const cls =
    TACTIC_COLORS[tactic] ||
    "bg-slate-500/20 text-slate-400 border-slate-500/30";
  return (
    <span
      className={`text-[9px] font-semibold px-2 py-0.5 rounded border ${cls}`}
    >
      {tactic}
    </span>
  );
}



export default function MITREMapping({ data }) {
  const { alerts } = data;

  // Build technique map from alerts
  const techniqueMap = {};
  alerts.forEach((alert) => {
    if (!alert.mitre) return;
    const id = alert.mitre.technique_id;
    if (!techniqueMap[id]) {
      techniqueMap[id] = {
        technique_id: alert.mitre.technique_id,
        technique_name: alert.mitre.technique_name,
        tactics: new Set(),
        url: alert.mitre.url,
        count: 0,
        severities: {},
        alert_types: new Set(),
      };
    }
    // Collect every distinct tactic in the group (e.g. T1078 is
    // "Defense Evasion / Persistence" for Multiple IP Login but
    // "Persistence" for ML Anomaly / Suspicious Login Time).
    (alert.mitre.tactic || "")
      .split(" / ")
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((s) => techniqueMap[id].tactics.add(s));
    techniqueMap[id].count += 1;
    techniqueMap[id].alert_types.add(alert.type);
    const sev = alert.severity || "LOW";
    techniqueMap[id].severities[sev] =
      (techniqueMap[id].severities[sev] || 0) + 1;
  });

  const techniques = Object.values(techniqueMap)
    .map((t) => ({ ...t, tactic: [...t.tactics].sort().join(" / ") }))
    .sort((a, b) => b.count - a.count);

  const maxCount = techniques[0]?.count || 1;
  const totalAlerts = alerts.length;
  const uniqueTechniques = techniques.length;

  // Dominant severity per technique
  function dominantSeverity(severities) {
    const order = ["HIGH", "MEDIUM", "LOW"];
    for (const s of order) {
      if (severities[s]) return s;
    }
    return "LOW";
  }

  return (
    <div id="mitre-matrix" className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader routeId="mitre-mapping">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-cyan-700 leading-none">
              {uniqueTechniques}
            </p>
            <p className="ui-caption mt-1">Techniques</p>
          </div>
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-orange-700 leading-none">
              {totalAlerts}
            </p>
            <p className="ui-caption mt-1">Total Alerts</p>
          </div>
        </div>
      </PageHeader>

      {/* Empty state */}
      {techniques.length === 0 && (
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl py-16 text-center">
          <Shield className="w-8 h-8 text-[color:var(--text-muted)] mx-auto mb-3" />
          <p className="ui-body font-medium text-[color:var(--text-secondary)]">
            No techniques mapped yet
          </p>
          <p className="ui-caption mt-1">Click ▶ Run to start detection</p>
        </div>
      )}

      {/* Technique table */}
      {techniques.length > 0 && (
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl overflow-hidden">
          {/* Table header - hidden on mobile, rows are stacked instead */}
          <div className="hidden sm:grid sm:grid-cols-12 gap-3 px-5 py-3 border-b border-[color:var(--border)] bg-[color:var(--bg-elevated)]">
            <div className="col-span-2 ui-table-head">Technique ID</div>
            <div className="col-span-3 ui-table-head">Technique Name</div>
            <div className="col-span-2 ui-table-head">Tactic</div>
            <div className="col-span-2 ui-table-head">Alert Types</div>
            <div className="col-span-2 ui-table-head">Frequency</div>
            <div className="col-span-1 ui-table-head">Severity</div>
          </div>

          {/* Table rows */}
          <div className="divide-y divide-[color:var(--border)]">
            {techniques.map((t, i) => (
              <div
                key={t.technique_id}
                className="flex flex-col items-start gap-2 sm:grid sm:grid-cols-12 sm:gap-3 sm:items-center px-4 sm:px-5 py-4 hover:bg-white/[0.02] transition-colors"
              >
                {/* Technique ID */}
                <div className="sm:col-span-2 flex items-center gap-2">
                  <span className="text-sm text-[color:var(--text-secondary)] w-4 flex-shrink-0">
                    {String(i + 1).padStart(2, "0")}
                  </span>

                  <a
                    href={t.url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-1 text-cyan-600 hover:text-cyan-500 transition-colors group"
                  >
                    <span className="text-sm font-semibold font-mono">
                      {t.technique_id}
                    </span>
                    <ExternalLink className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </a>
                </div>

                {/* Technique name */}
                <div className="sm:col-span-3 pl-6 sm:pl-0">
                  <p className="ui-body font-medium text-[color:var(--text-primary)]">
                    {t.technique_name}
                  </p>
                </div>

                {/* Tactic */}
                <div className="sm:col-span-2 pl-6 sm:pl-0">
                  <TacticBadge tactic={t.tactic} />
                </div>

                {/* Alert types */}
                <div className="sm:col-span-2 pl-6 sm:pl-0">
                  <div className="space-y-0.5">
                    {[...t.alert_types].map((type) => (
                      <p
                        key={type}
                        className="text-sm text-[color:var(--text-secondary)] truncate"
                      >
                        {type}
                      </p>
                    ))}
                  </div>
                </div>

                {/* Frequency bar */}
                <div className="sm:col-span-2 w-full pl-6 sm:pl-0">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-[color:var(--border)] rounded-full h-1.5">
                      <div
                        className="h-1.5 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all"
                        style={{
                          width: `${Math.max(8, (t.count / maxCount) * 100)}%`,
                        }}
                      />
                    </div>
                    <span className="text-sm font-semibold text-[color:var(--text-primary)] w-4 text-right flex-shrink-0">
                      {t.count}
                    </span>
                  </div>
                </div>

                {/* Severity */}
                <div className="sm:col-span-1 pl-6 sm:pl-0">
                  <SeverityBadge severity={dominantSeverity(t.severities)} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Framework note */}
      <div className="flex items-start gap-3 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4">
        <div className="w-6 h-6 rounded bg-cyan-500/20 grid place-items-center flex-shrink-0 mt-0.5">
          <span className="text-cyan-600 text-sm">ⓘ</span>
        </div>
        <div>
          <p className="ui-label text-[color:var(--text-primary)] mb-1">
            MITRE ATT&CK Framework
          </p>
          <p className="ui-caption leading-7">
            All detections are mapped to the MITRE ATT&CK® framework, a globally
            recognised knowledge base of adversary tactics and techniques. Each
            technique ID links directly to the official MITRE documentation for
            incident response guidance.
          </p>
        </div>
      </div>
    </div>
  );
}
