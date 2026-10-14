// frontend/src/pages/ResponseActions.jsx

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from "recharts";
import { Activity } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import {
  axisTick,
  barCursor,
  chartTooltip,
  formatHour,
  lineCursor,
} from "../config/chartTheme";
import { SEVERITY } from "../config/severity";
import { enginePolicy } from "../utils/policy";

const SEVERITY_COLORS = {
  HIGH: SEVERITY.HIGH.chart,
  MEDIUM: SEVERITY.MEDIUM.chart,
  LOW: SEVERITY.LOW.chart,
};
const TYPE_COLORS = [
  "#f97316",
  "#8b5cf6",
  "#06b6d4",
  "#22c55e",
  "#ec4899",
  "#f59e0b",
];

function CardWrap({ children, className = "" }) {
  return (
    <div
      className={`bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-5 ${className}`}
    >
      {children}
    </div>
  );
}

function CardTitle({ children }) {
  return <p className="ui-kicker mb-3">{children}</p>;
}

function BarRow({ label, pct, color }) {
  const colors = {
    green: "bg-green-400",
    cyan: "bg-cyan-400",
    blue: "bg-blue-400",
    purple: "bg-purple-400",
  };
  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-[color:var(--text-secondary)] w-24 flex-shrink-0">
        {label}
      </span>
      <div className="flex-1 bg-[color:var(--border)] rounded-full h-1.5">
        <div
          className={`h-1.5 rounded-full ${colors[color]} transition-all`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-sm text-[color:var(--text-secondary)] w-8 text-right">
        {pct}%
      </span>
    </div>
  );
}

export default function ResponseActions({ data }) {
  const { alerts, stats, timeline, modelInfo, pipelineStats, backendConfig, status } =
    data;
  const policy = enginePolicy(backendConfig, status);
  // Confidence cut-offs from /api/config (backend/config.py).
  const highCut = backendConfig?.ml?.confidence_high_cutoff;
  const medCut = backendConfig?.ml?.confidence_medium_cutoff;
  const fmtCut = (v) => (typeof v === "number" ? v.toFixed(2) : "?");

  const total = stats?.total_alerts || 0;
  const high = stats?.severity_counts?.HIGH || 0;
  const medium = stats?.severity_counts?.MEDIUM || 0;

  // Real model info from API
  const precision = modelInfo?.precision
    ? (modelInfo.precision * 100).toFixed(1)
    : "-";
  const recall = modelInfo?.recall ? (modelInfo.recall * 100).toFixed(1) : "-";
  const f1 = modelInfo?.f1 ? (modelInfo.f1 * 100).toFixed(1) : "-";
  const trainingSize = modelInfo?.training_size || "-";
  const trainedAt = modelInfo?.trained_at
    ? modelInfo.trained_at.split("T")[0]
    : "-";

  // Real pipeline stats
  const avgMs = pipelineStats?.avg_event_time_ms || null;
  const avgSec = avgMs ? (avgMs / 1000).toFixed(2) : "-";
  // Email delivery rate from recorded outcomes (stats.email).
  const emailCounts = stats?.email || {};
  const emailAttempted = (emailCounts.sent || 0) + (emailCounts.failed || 0);
  const successRate =
    emailAttempted > 0
      ? `${Math.round(((emailCounts.sent || 0) / emailAttempted) * 100)}%`
      : "-";

  // Severity donut data
  const severityData = stats
    ? Object.entries(stats.severity_counts || {})
        .filter(([, v]) => v > 0)
        .map(([name, value]) => ({ name, value }))
    : [];

  // Alert type bar data with short labels
  const typeData = (stats?.type_counts || []).map((d) => ({
    ...d,
    short: d.name
      .replace("Suspicious Login Time", "Login Time")
      .replace("Multiple IP Login", "Multi-IP")
      .replace("Brute Force Attack", "Brute Force")
      .replace("Slow Brute Force", "Slow BF")
      .replace("Credential Stuffing", "Cred Stuff")
      .replace("ML Anomaly Detected", "ML Anomaly"),
  }));

  // MITRE frequency from real alerts
  const mitreCounts = {};
  alerts.forEach((a) => {
    if (a.mitre?.technique_id) {
      const id = a.mitre.technique_id;
      mitreCounts[id] = (mitreCounts[id] || 0) + 1;
    }
  });
  const mitreData = Object.entries(mitreCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([id, count]) => ({ id, count }));
  const mitreMax = mitreData[0]?.count || 1;

  // Real ML confidence from actual alert scores
  const mlAlerts = alerts.filter(
    (a) => a.type === "ML Anomaly Detected" && a.anomaly_score !== undefined,
  );
  // Prefer the confidence the backend assigned; fall back to the score
  // and the configured cut-offs for alerts that lack it.
  const bandOf = (a) => {
    if (a.confidence) return a.confidence;
    if (typeof highCut !== "number" || typeof medCut !== "number") return null;
    if (a.anomaly_score < highCut) return "High";
    if (a.anomaly_score < medCut) return "Medium";
    return "Low";
  };
  const hiC = mlAlerts.filter((a) => bandOf(a) === "High").length;
  const mdC = mlAlerts.filter((a) => bandOf(a) === "Medium").length;
  const loC = mlAlerts.length - hiC - mdC;
  const tot = mlAlerts.length || 1;
  const hiP = mlAlerts.length ? Math.round((hiC / tot) * 100) : null;
  const mdP = mlAlerts.length ? Math.round((mdC / tot) * 100) : null;
  const loP = mlAlerts.length ? Math.round((loC / tot) * 100) : null;

  // Response coverage from the outcomes recorded on each alert
  // (alert.response); alerts saved before outcomes were recorded are
  // left out rather than assumed successful.
  const share = (part, whole) =>
    whole > 0 ? Math.round((part / whole) * 100) : 0;
  const recorded = alerts.filter((a) => a.response);
  const recHigh = recorded.filter((a) => a.severity === "HIGH");
  const recMedium = recorded.filter((a) => a.severity === "MEDIUM");
  // v3: HIGH = the step-up tier (simulated MFA, not enforced); legacy: block.
  const ipBlockPct = share(
    recHigh.filter((a) => (policy.v3 ? a.response.step_up : a.response.simulated_block)).length,
    recHigh.length,
  );
  const emailPct = share(emailCounts.sent || 0, emailAttempted);
  const notifyPct = share(
    recMedium.filter((a) => a.response.admin_notify_simulated).length,
    recMedium.length,
  );
  // Every alert listed here was read back from the store, so it was written.
  const logPct = total > 0 ? 100 : 0;

  return (
    <div id="response-timeline" className="p-3 sm:p-6 space-y-5 sm:space-y-6">
      <PageHeader routeId="response-actions" />
      {alerts.filter((a) => a.severity === "HIGH").length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-3">
            AI-Generated Threat Analysis
          </p>
          <div className="space-y-3">
            {alerts.filter((a) => a.severity === "HIGH" && a.llm_explanation)
              .length === 0 ? (
              <div className="bg-[#0f1629] border border-[#1e2a3d] rounded-xl p-4 flex items-center gap-4">
                <div className="w-5 h-5 border-2 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
                <span className="text-sm text-slate-400">
                  AI is analysing HIGH threats…
                </span>
              </div>
            ) : (
              alerts
                .filter((a) => a.llm_explanation && a.severity === "HIGH")
                .slice(0, 2)
                .map((alert, i) => (
                  <div
                    key={i}
                    className="bg-[#0f1629] border border-[#1e2a3d] rounded-xl p-4"
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap mb-3">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={alert.severity} />
                        <span className="text-[12px] font-semibold text-[color:var(--text-primary)]">
                          {alert.type}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[9px] bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded px-2 py-0.5">
                          🤖 AI Analysis
                        </span>
                        <span className="text-[10px] text-slate-600 font-mono">
                          {alert.ip}
                        </span>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-300 leading-relaxed whitespace-pre-line">
                      {alert.llm_explanation}
                    </p>
                    {alert.mitre && (
                      <div className="mt-3 pt-3 border-t border-[#1e2a3d] flex items-center gap-3 flex-wrap">
                        <span className="text-[10px] text-cyan-400 font-mono font-bold">
                          {alert.mitre.technique_id}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {alert.mitre.technique_name}
                        </span>
                        <a
                          href={alert.mitre.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[9px] text-cyan-400 hover:text-cyan-300 ml-auto"
                        >
                          ↗ MITRE
                        </a>
                      </div>
                    )}
                  </div>
                ))
            )}
          </div>
        </div>
      )}
      {/* Top row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Response Agent */}
        <CardWrap>
          <div className="flex items-start justify-between gap-2 flex-wrap mb-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-green-500/20 grid place-items-center">
                <Activity className="w-4 h-4 text-green-400" />
              </div>
              <div>
                <p className="ui-label text-[color:var(--text-primary)]">
                  Response Stage
                </p>
                <p className="ui-caption">Automated Response</p>
              </div>
            </div>
            <div className="flex items-center gap-1.5 bg-green-500/10 border border-green-500/20 rounded-full px-2 py-0.5">
              <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
              <span className="text-xs text-green-400 font-semibold">
                Active
              </span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            {[
              {
                label: "Processed",
                value: total,
                color: "text-[color:var(--text-primary)]",
              },
              { label: "HIGH Alerts", value: high, color: "text-orange-400" },
              {
                label: "Medium",
                value: medium,
                color: "text-[color:var(--text-primary)]",
              },
              { label: "Email delivered", value: successRate, color: "text-green-400" },
            ].map(({ label, value, color }) => (
              <div key={label}>
                <p className="ui-caption">{label}</p>
                <p className={`text-2xl font-semibold leading-none ${color}`}>
                  {value}
                </p>
              </div>
            ))}
          </div>
        </CardWrap>

        {/* ML Intelligence - real data */}
        <CardWrap>
          <div className="flex items-center gap-2 mb-4">
            <div className="w-5 h-5 rounded bg-cyan-500/20 grid place-items-center">
              <span className="text-cyan-400 text-sm">ⓘ</span>
            </div>
            <p className="ui-kicker">ML Intelligence - Isolation Forest</p>
          </div>

          {policy.mlAlerts === false ? (
            <p className="ui-body text-[color:var(--text-secondary)] leading-6">
              Not used in this mode. ML mode v4 raises no ML alerts: no
              label-free model cleared the evaluation bar, and the legacy model
              was trained on label-filtered rows. Responses come from the rule
              alerts and the incident triage.
            </p>
          ) : (
          <>

          <div className="grid grid-cols-2 gap-3 mb-4">
            {[
              {
                label: "Model",
                value: "Isolation Forest",
                color: "text-[color:var(--text-primary)]",
              },
              {
                label: "Training Set",
                value: trainingSize,
                color: "text-[color:var(--text-primary)]",
              },
              {
                label: "Inference",
                value: "Runtime only",
                color: "text-cyan-400",
              },
              {
                label: "Trained",
                value: trainedAt,
                color: "text-[color:var(--text-primary)]",
              },
              {
                label: "Precision",
                value: `${precision}%`,
                color: "text-green-400",
              },
              { label: "Recall", value: `${recall}%`, color: "text-amber-400" },
              { label: "F1-Score", value: `${f1}%`, color: "text-cyan-400" },
              {
                label: "Avg Event",
                value: avgMs ? `${avgMs}ms` : "-",
                color: "text-[color:var(--text-primary)]",
              },
            ].map(({ label, value, color }) => (
              <div key={label}>
                <p className="ui-caption">{label}</p>
                <p className={`text-sm font-medium ${color}`}>{value}</p>
              </div>
            ))}
          </div>

          {/* Real confidence distribution */}
          <p className="ui-caption mb-2">Confidence Distribution (Live)</p>
          {mlAlerts.length === 0 ? (
            <p className="ui-body text-[color:var(--text-secondary)]">
              No ML alerts yet, run detection first
            </p>
          ) : (
            <div className="space-y-2">
              {[
                {
                  label: `High (score < ${fmtCut(highCut)})`,
                  pct: hiP,
                  color: "bg-red-400",
                },
                {
                  label: `Med  (score < ${fmtCut(medCut)})`,
                  pct: mdP,
                  color: "bg-orange-400",
                },
                {
                  label: `Low  (score ≥ ${fmtCut(medCut)})`,
                  pct: loP,
                  color: "bg-green-400",
                },
              ].map(({ label, pct, color }) => (
                <div key={label} className="flex items-center gap-2">
                  <span className="text-sm text-[color:var(--text-secondary)] w-24 sm:w-32 flex-shrink-0 truncate">
                    {label}
                  </span>
                  <div className="flex-1 bg-[color:var(--border)] rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full ${color}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-sm text-[color:var(--text-secondary)] w-7 text-right flex-shrink-0">
                    {pct}%
                  </span>
                </div>
              ))}
            </div>
          )}
          </>
          )}
        </CardWrap>
      </div>
      {/* Threat Analytics */}
      <div>
        <p className="ui-kicker mb-4">Threat Analytics</p>

        {/* Row 1 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
          <CardWrap>
            <CardTitle>Alerts by Hour of Day</CardTitle>
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart
                data={timeline}
                margin={{ top: 5, right: 5, bottom: 0, left: -25 }}
              >
                <defs>
                  <linearGradient id="gH" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={SEVERITY_COLORS.HIGH} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={SEVERITY_COLORS.HIGH} stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gM" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={SEVERITY_COLORS.MEDIUM} stopOpacity={0.2} />
                    <stop offset="95%" stopColor={SEVERITY_COLORS.MEDIUM} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="hour"
                  tick={axisTick}
                  tickFormatter={formatHour}
                  interval={5}
                />
                <YAxis tick={axisTick} allowDecimals={false} />
                <Tooltip
                  {...chartTooltip}
                  cursor={lineCursor}
                  labelFormatter={(h) =>
                    `${formatHour(h)}–${formatHour((h + 1) % 24)}`
                  }
                />
                <Area
                  type="monotone"
                  dataKey="HIGH"
                  stroke={SEVERITY_COLORS.HIGH}
                  strokeWidth={1.5}
                  fill="url(#gH)"
                />
                <Area
                  type="monotone"
                  dataKey="MEDIUM"
                  stroke={SEVERITY_COLORS.MEDIUM}
                  strokeWidth={1}
                  fill="url(#gM)"
                  strokeDasharray="3 3"
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardWrap>

          <CardWrap>
            <CardTitle>Severity Distribution</CardTitle>
            <div className="flex items-center gap-4 flex-wrap">
              <ResponsiveContainer width={120} height={120}>
                <PieChart>
                  <Pie
                    data={
                      severityData.length
                        ? severityData
                        : [{ name: "none", value: 1 }]
                    }
                    cx="50%"
                    cy="50%"
                    innerRadius={32}
                    outerRadius={52}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    {(severityData.length
                      ? severityData
                      : [{ name: "none" }]
                    ).map((e, i) => (
                      <Cell
                        key={i}
                        fill={SEVERITY_COLORS[e.name] || "var(--border)"}
                      />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2.5">
                {severityData.map((d) => (
                  <div key={d.name} className="flex items-center gap-2">
                    <div
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{ background: SEVERITY_COLORS[d.name] }}
                    />
                    <span className="text-sm text-[color:var(--text-secondary)]">
                      {d.name}
                    </span>
                    <span className="text-sm font-medium text-[color:var(--text-primary)] ml-2">
                      {d.value}
                    </span>
                  </div>
                ))}
                {severityData.length === 0 && (
                  <p className="ui-caption">No data yet</p>
                )}
              </div>
            </div>
          </CardWrap>
        </div>

        {/* Row 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <CardWrap>
            <CardTitle>Alert Type Breakdown</CardTitle>
            {typeData.length === 0 ? (
              <p className="ui-body py-4 text-[color:var(--text-secondary)]">
                No data yet
              </p>
            ) : (
              <ResponsiveContainer width="100%" height={150}>
                <BarChart
                  data={typeData}
                  margin={{ top: 5, right: 5, bottom: 25, left: -25 }}
                >
                  <XAxis
                    dataKey="short"
                    tick={axisTick}
                    angle={-30}
                    textAnchor="end"
                  />
                  <YAxis
                    tick={axisTick}
                    allowDecimals={false}
                  />
                  <Tooltip {...chartTooltip} cursor={barCursor} />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                    {typeData.map((_, i) => (
                      <Cell
                        key={i}
                        fill={TYPE_COLORS[i % TYPE_COLORS.length]}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardWrap>

          <CardWrap>
            <CardTitle>MITRE ATT&CK Frequency</CardTitle>
            {mitreData.length === 0 ? (
              <p className="ui-body text-[color:var(--text-secondary)]">
                Run detection to see MITRE data
              </p>
            ) : (
              <div className="space-y-2.5">
                {mitreData.map(({ id, count }) => (
                  <div key={id} className="flex items-center gap-2">
                    <span className="text-sm text-cyan-400 font-mono w-16 sm:w-20 flex-shrink-0">
                      {id}
                    </span>
                    <div className="flex-1 bg-[color:var(--border)] rounded-full h-1.5">
                      <div
                        className="h-1.5 rounded-full bg-gradient-to-r from-orange-500 to-red-500"
                        style={{
                          width: `${Math.max(8, (count / mitreMax) * 100)}%`,
                        }}
                      />
                    </div>
                    <span className="text-sm text-[color:var(--text-secondary)] w-4 text-right flex-shrink-0">
                      {count}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardWrap>

          <CardWrap>
            <CardTitle>Response Effectiveness</CardTitle>
            <div className="space-y-2 mb-4">
              <BarRow label={policy.v3 ? "Sim. step-up" : "Sim. block"} pct={ipBlockPct} color="green" />
              <BarRow label="Email Alerts" pct={emailPct} color="cyan" />
              <BarRow label={policy.v3 ? "Analyst queue" : "Admin Notify"} pct={notifyPct} color="blue" />
              <BarRow label="Log Written" pct={logPct} color="purple" />
            </div>
            <div className="flex items-center justify-around pt-4 border-t border-[color:var(--border)]">
              <div className="text-center">
                <p className="text-2xl font-semibold leading-none text-green-400">
                  {successRate}
                </p>
                <p className="ui-caption mt-1">Email delivery</p>
              </div>
              <div className="w-px h-8 bg-[color:var(--border)]" />
              <div className="text-center">
                <p className="text-2xl font-semibold leading-none text-cyan-400">
                  {avgSec}s
                </p>
                <p className="ui-caption mt-1">Avg Event Time</p>
              </div>
            </div>
          </CardWrap>
        </div>
      </div>
    </div>
  );
}
