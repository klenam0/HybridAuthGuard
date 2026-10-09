import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  Ban,
  ChevronRight,
  Cpu,
  ShieldCheck,
  Zap,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import {
  getSeverity,
  getThreatLevel,
  SEVERITY_LEVELS,
} from "../config/severity";
import {
  axisLine,
  axisTick,
  barCursor,
  chartTooltip,
  formatHour,
  gridStroke,
  SEVERITY_SERIES,
} from "../config/chartTheme";
import { formatUtcTime, timeAgo } from "../utils/time";

const percent = (part, whole) =>
  whole > 0 ? `${((part / whole) * 100).toFixed(1)}%` : "-";

function Skeleton({ className = "" }) {
  return (
    <span
      className={`block animate-pulse rounded bg-[color:var(--border)] ${className}`}
      aria-hidden="true"
    />
  );
}

function Panel({ title, meta, children, footer, className = "" }) {
  return (
    <section
      className={`bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl flex flex-col min-w-0 ${className}`}
    >
      <div className="flex items-baseline justify-between gap-3 px-4 pt-4 pb-3">
        <h2 className="ui-label text-[color:var(--text-primary)]">{title}</h2>
        {meta && <span className="ui-caption text-right">{meta}</span>}
      </div>
      <div className="px-4 pb-4 flex-1 min-h-0">{children}</div>
      {footer && (
        <div className="px-4 py-2.5 border-t border-[color:var(--border)]">
          {footer}
        </div>
      )}
    </section>
  );
}

function PanelMessage({ children }) {
  return (
    <p className="ui-body text-[color:var(--text-secondary)] py-6 text-center">
      {children}
    </p>
  );
}

function MetricTile({ Icon, label, value, detail, state }) {
  return (
    <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 min-w-0">
      <div className="flex items-center justify-between gap-2">
        <p className="ui-metric-label">{label}</p>
        <Icon
          className="w-4 h-4 text-[color:var(--text-muted)] flex-shrink-0"
          aria-hidden="true"
        />
      </div>
      {state === "loading" ? (
        <Skeleton className="h-7 w-20 mt-2" />
      ) : (
        <p className="mt-1.5 text-2xl font-semibold tabular-nums leading-none text-[color:var(--text-primary)]">
          {state === "unavailable" ? "-" : value}
        </p>
      )}
      <p className="ui-caption mt-1.5 truncate">
        {state === "unavailable" ? "Unavailable: backend offline" : detail}
      </p>
    </div>
  );
}

function StatusFact({ label, children }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1.5">
      <dt className="ui-caption">{label}</dt>
      <dd className="text-sm font-medium text-right text-[color:var(--text-primary)] min-w-0 truncate">
        {children}
      </dd>
    </div>
  );
}

function DetectorRow({ name, alerts: alertCount, last, isML }) {
  const label = name === "ML Anomaly Detected" ? "Isolation Forest ML" : name;
  return (
    <div className="flex items-center gap-3 py-2 border-b border-[color:var(--border)] last:border-0">
      <span
        className={`w-6 h-6 rounded-md grid place-items-center flex-shrink-0 ${
          isML ? "bg-purple-500/20 text-purple-400" : "bg-cyan-500/20 text-cyan-400"
        }`}
        aria-hidden="true"
      >
        {isML ? (
          <Cpu className="w-3.5 h-3.5" />
        ) : (
          <ShieldCheck className="w-3.5 h-3.5" />
        )}
      </span>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-[color:var(--text-primary)] truncate">
          {label}
        </p>
        <p className="ui-caption">Last: {last}</p>
      </div>
      <p className="text-sm font-semibold tabular-nums text-[color:var(--text-primary)]">
        {alertCount}
      </p>
    </div>
  );
}

function AlertRow({ alert, onOpen, showBadge }) {
  const { Icon, text } = getSeverity(alert.severity);
  return (
    <li>
      <button
        type="button"
        onClick={() => onOpen(alert.alert_id)}
        className="w-full flex items-center gap-3 py-2 px-2 -mx-2 rounded-lg text-left hover:bg-white/[0.03] transition-colors"
      >
        {showBadge ? (
          <SeverityBadge severity={alert.severity} />
        ) : (
          <Icon className={`w-4 h-4 flex-shrink-0 ${text}`} aria-label={alert.severity} />
        )}
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-medium text-[color:var(--text-primary)] truncate">
            {alert.type}
          </span>
          <span className="block ui-caption font-mono truncate">
            {alert.user || "-"} · {alert.ip || "-"}
          </span>
        </span>
        <span
          className="ui-caption whitespace-nowrap"
          title={alert.detected_at}
        >
          {timeAgo(alert.detected_at) || "-"}
        </span>
        <ChevronRight
          className="w-4 h-4 text-[color:var(--text-muted)] flex-shrink-0"
          aria-hidden="true"
        />
      </button>
    </li>
  );
}

export default function Dashboard({ data }) {
  const {
    alerts,
    stats,
    status,
    timeline,
    modelInfo,
    agentsData,
    detectors,
    pipelineStats,
    threatLevel,
    enrichment,
    connection,
    running,
    navigateToAlert,
  } = data;

  const hasData = connection.lastSuccess !== null;
  const tileState = hasData
    ? "ready"
    : connection.status === "offline"
      ? "unavailable"
      : "loading";

  const total = stats?.total_alerts ?? alerts.length;
  const severityCounts = stats?.severity_counts || {};
  const flaggedIps = stats?.blocked_ips?.length ?? 0;
  const mlCount = alerts.filter((a) => a.type === "ML Anomaly Detected").length;
  const eventsProcessed = pipelineStats?.events_processed;
  const avgMs = pipelineStats?.avg_event_time_ms;

  const sortedAlerts = useMemo(
    () =>
      [...alerts].sort((a, b) =>
        (b.detected_at || "").localeCompare(a.detected_at || ""),
      ),
    [alerts],
  );
  const highAlerts = sortedAlerts.filter(
    (a) => a.severity === "HIGH" || a.severity === "CRITICAL",
  );
  const latestDetection = sortedAlerts[0]?.detected_at;

  const threat = getThreatLevel(threatLevel?.level, connection.status);
  const ThreatIcon = threat.Icon;
  const lastKnownThreat =
    threat.key === "UNKNOWN" && hasData
      ? getThreatLevel(threatLevel?.level, "online")
      : null;

  const timelineTotal = (timeline || []).reduce(
    (sum, h) => sum + (h.total || 0),
    0,
  );
  const peakHour = (timeline || []).reduce(
    (peak, h) => ((h.total || 0) > (peak?.total || 0) ? h : peak),
    null,
  );
  const seriesTotals = Object.fromEntries(
    SEVERITY_SERIES.map((s) => [
      s.key,
      (timeline || []).reduce((sum, h) => sum + (h[s.key] || 0), 0),
    ]),
  );

  const openAlert = (alertId) => navigateToAlert(alertId);

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader routeId="dashboard">
        <span className="ui-caption">
          {hasData
            ? `Data as of ${formatUtcTime(connection.lastSuccess)}`
            : connection.status === "offline"
              ? "No data received"
              : "Loading…"}
        </span>
      </PageHeader>

      {/* ── Security posture ─────────────────────────────────────────── */}
      <section
        id="dashboard-metrics"
        aria-label="Security posture"
        className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-[color:var(--border)]"
      >
        {/* Threat level */}
        <div className="lg:col-span-4 p-4 sm:p-5 flex items-start gap-4">
          <span
            className={`sev-badge w-12 h-12 rounded-xl grid place-items-center flex-shrink-0 ${threat.className}`}
            aria-hidden="true"
          >
            <ThreatIcon className="w-6 h-6" />
          </span>
          <div className="min-w-0">
            <p className="ui-kicker">Threat level</p>
            <p className="text-2xl font-bold tracking-wide leading-tight text-[color:var(--text-primary)]">
              {threat.key}
            </p>
            <p className="ui-caption mt-1">
              {threat.key === "UNKNOWN"
                ? connection.status === "connecting"
                  ? "Waiting for the backend…"
                  : "Backend unreachable, so the level can't be determined."
                : threat.key === "NORMAL"
                  ? "No alerts in the current alert set."
                  : `Highest severity present among ${total} alert${total === 1 ? "" : "s"} in the current set.`}
            </p>
            {lastKnownThreat && (
              <p className="ui-caption mt-1">
                Last known: {lastKnownThreat.key} at{" "}
                {formatUtcTime(connection.lastSuccess)}
              </p>
            )}
          </div>
        </div>

        {/* Severity breakdown */}
        <div className="lg:col-span-5 p-4 sm:p-5">
          <div className="flex items-baseline justify-between gap-2 mb-3">
            <p className="ui-kicker">Alerts by severity</p>
            <p className="ui-caption tabular-nums">
              {hasData ? `${total} total` : ""}
            </p>
          </div>
          {!hasData ? (
            tileState === "loading" ? (
              <Skeleton className="h-2 w-full" />
            ) : (
              <p className="ui-caption">Unavailable: backend offline.</p>
            )
          ) : (
            <>
              <div
                className="flex h-2 w-full gap-0.5 rounded-full overflow-hidden bg-[color:var(--border)]"
                role="img"
                aria-label={SEVERITY_LEVELS.map(
                  (k) => `${k} ${severityCounts[k] || 0}`,
                ).join(", ")}
              >
                {total > 0 &&
                  SEVERITY_LEVELS.map((k) =>
                    severityCounts[k] ? (
                      <span
                        key={k}
                        style={{
                          width: `${(severityCounts[k] / total) * 100}%`,
                          background: getSeverity(k).chart,
                        }}
                      />
                    ) : null,
                  )}
              </div>
              <ul className="mt-3 grid grid-cols-3 gap-2">
                {SEVERITY_LEVELS.map((k) => (
                  <li key={k} className="min-w-0">
                    <SeverityBadge severity={k} />
                    <p className="mt-1.5 text-xl font-semibold tabular-nums leading-none text-[color:var(--text-primary)]">
                      {severityCounts[k] || 0}
                    </p>
                    <p className="ui-caption">
                      {percent(severityCounts[k] || 0, total)}
                    </p>
                  </li>
                ))}
              </ul>
              {total === 0 && (
                <p className="ui-caption mt-2">
                  No alerts yet. Run detection to analyse the log stream.
                </p>
              )}
            </>
          )}
        </div>

        {/* Pipeline / model status */}
        <div className="lg:col-span-3 p-4 sm:p-5">
          <p className="ui-kicker mb-1">System</p>
          <dl>
          <StatusFact label="Pipeline">
            {!status ? (
              "Unknown"
            ) : running ? (
              <span className="text-cyan-400">Running</span>
            ) : (
              "Idle"
            )}
          </StatusFact>
          <StatusFact label="Last run">
            <span title={pipelineStats?.last_run}>
              {pipelineStats?.last_run
                ? timeAgo(pipelineStats.last_run)
                : "Never"}
            </span>
          </StatusFact>
          <StatusFact label="Last detection">
            <span title={latestDetection}>
              {latestDetection ? timeAgo(latestDetection) : "None"}
            </span>
          </StatusFact>
          <StatusFact label="ML model">
            {!status ? (
              "Unknown"
            ) : status.model_loaded ? (
              "Loaded"
            ) : (
              <span className="text-red-400">Not loaded</span>
            )}
          </StatusFact>
          <StatusFact label="LLM summaries">
            {!enrichment
              ? "Unknown"
              : enrichment.llm_available
                ? enrichment.pending > 0
                  ? `${enrichment.pending} pending`
                  : "Available"
                : "Unavailable"}
          </StatusFact>
          </dl>
        </div>
      </section>

      {/* ── Primary metrics ──────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <MetricTile
          Icon={Zap}
          label="Events processed"
          state={tileState}
          value={
            typeof eventsProcessed === "number"
              ? eventsProcessed.toLocaleString()
              : "-"
          }
          detail={
            typeof eventsProcessed !== "number"
              ? "No pipeline run recorded"
              : avgMs
                ? `Last run · ${avgMs} ms/event`
                : "Last pipeline run"
          }
        />
        <MetricTile
          Icon={Activity}
          label="Alerts"
          state={tileState}
          value={total.toLocaleString()}
          detail="In the current alert set"
        />
        <MetricTile
          Icon={Ban}
          label="Flagged source IPs"
          state={tileState}
          value={flaggedIps.toLocaleString()}
          detail="From HIGH alerts · block simulated"
        />
        <MetricTile
          Icon={Cpu}
          label="ML anomalies"
          state={tileState}
          value={mlCount.toLocaleString()}
          detail={
            modelInfo?.precision && modelInfo?.recall
              ? `Model P ${(modelInfo.precision * 100).toFixed(1)}% · R ${(modelInfo.recall * 100).toFixed(1)}% (offline eval)`
              : "Isolation Forest"
          }
        />
      </div>

      {/* ── Timeline + needs attention ───────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Panel
          className="lg:col-span-2"
          title="Alerts by hour of day"
          meta="Detection hour (server time), all alerts in the current set"
        >
          {!hasData ? (
            tileState === "loading" ? (
              <Skeleton className="h-52 w-full" />
            ) : (
              <PanelMessage>Unavailable: backend offline.</PanelMessage>
            )
          ) : timelineTotal === 0 ? (
            <PanelMessage>
              No alerts yet. The hourly distribution appears after the first
              detection run.
            </PanelMessage>
          ) : (
            <>
              <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 mb-3">
                {SEVERITY_SERIES.map((s) => (
                  <li
                    key={s.key}
                    className="flex items-center gap-1.5 ui-caption"
                  >
                    <span
                      className="w-2.5 h-2.5 rounded-sm"
                      style={{ background: s.color }}
                      aria-hidden="true"
                    />
                    {s.label}
                    <span className="tabular-nums text-[color:var(--text-primary)] font-medium">
                      {seriesTotals[s.key]}
                    </span>
                  </li>
                ))}
                {peakHour && (
                  <li className="ui-caption sm:ml-auto">
                    Peak {formatHour(peakHour.hour)} · {peakHour.total} alerts
                  </li>
                )}
              </ul>
              <div
                role="img"
                aria-label={`Alerts by hour of day. Peak at ${formatHour(peakHour?.hour ?? 0)} with ${peakHour?.total ?? 0} alerts.`}
              >
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart
                    data={timeline}
                    margin={{ top: 4, right: 4, bottom: 0, left: -20 }}
                    barCategoryGap={2}
                  >
                    <CartesianGrid
                      vertical={false}
                      stroke={gridStroke}
                      strokeDasharray="3 3"
                    />
                    <XAxis
                      dataKey="hour"
                      tick={axisTick}
                      axisLine={axisLine}
                      tickLine={false}
                      tickFormatter={formatHour}
                      interval={2}
                    />
                    <YAxis
                      tick={axisTick}
                      axisLine={false}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <Tooltip
                      {...chartTooltip}
                      cursor={barCursor}
                      labelFormatter={(h) =>
                        `${formatHour(h)}–${formatHour((h + 1) % 24)}`
                      }
                    />
                    {SEVERITY_SERIES.map((s, i) => (
                      <Bar
                        key={s.key}
                        dataKey={s.key}
                        name={s.label}
                        stackId="severity"
                        fill={s.color}
                        stroke="var(--bg-card)"
                        strokeWidth={1}
                        radius={
                          i === SEVERITY_SERIES.length - 1 ? [3, 3, 0, 0] : 0
                        }
                        isAnimationActive={false}
                      />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </>
          )}
        </Panel>

        <Panel
          title="Needs attention"
          meta={
            hasData
              ? `${highAlerts.length} high-severity alert${highAlerts.length === 1 ? "" : "s"}`
              : null
          }
          footer={
            hasData && (
              <button
                type="button"
                onClick={() => navigateToAlert(null)}
                className="ui-caption text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                Open Alert Log →
              </button>
            )
          }
        >
          {!hasData ? (
            tileState === "loading" ? (
              <div className="space-y-3">
                <Skeleton className="h-9 w-full" />
                <Skeleton className="h-9 w-full" />
                <Skeleton className="h-9 w-full" />
              </div>
            ) : (
              <PanelMessage>Unavailable: backend offline.</PanelMessage>
            )
          ) : highAlerts.length === 0 ? (
            <div className="py-6 text-center">
              <ShieldCheck
                className="w-6 h-6 text-green-400 mx-auto mb-2"
                aria-hidden="true"
              />
              <p className="ui-body text-[color:var(--text-secondary)]">
                No high-severity alerts in the current set.
              </p>
            </div>
          ) : (
            <ul>
              {highAlerts.slice(0, 5).map((alert) => (
                <AlertRow
                  key={alert.alert_id}
                  alert={alert}
                  onOpen={openAlert}
                  showBadge
                />
              ))}
            </ul>
          )}
        </Panel>
      </div>

      {/* ── Pipeline, detectors, recent detections ───────────────────── */}
      <div
        id="dashboard-pipeline"
        className="grid grid-cols-1 lg:grid-cols-3 gap-4"
      >
        <Panel
          title="Detection pipeline"
          meta={
            pipelineStats?.last_run
              ? `Last run ${pipelineStats.last_run}`
              : null
          }
          footer={
            <p className="ui-caption">
              Counts are from the last pipeline run. Per-stage health is not
              reported by the backend.
            </p>
          }
        >
          {agentsData.length === 0 ? (
            <PanelMessage>
              {hasData
                ? "No pipeline run recorded yet."
                : "Unavailable until the backend responds."}
            </PanelMessage>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="ui-table-head text-left">
                  <th className="font-semibold pb-2">Stage</th>
                  <th className="font-semibold pb-2 text-right">Processed</th>
                  <th className="font-semibold pb-2 text-right">Alerts</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[color:var(--border)]">
                {agentsData.map((a) => (
                  <tr key={a.name}>
                    <td className="py-2 pr-2">
                      <p className="font-medium text-[color:var(--text-primary)]">
                        {String(a.name).replace(/ Agent$/, " Stage")}
                      </p>
                      <p className="ui-caption">{a.role}</p>
                    </td>
                    <td className="py-2 text-right tabular-nums text-[color:var(--text-primary)]">
                      {(a.processed ?? 0).toLocaleString()}
                    </td>
                    <td className="py-2 text-right tabular-nums text-[color:var(--text-primary)]">
                      {(a.alerts ?? 0).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel title="Detection engine" meta="Alerts per detector">
          {detectors.length === 0 ? (
            <PanelMessage>
              {hasData
                ? "No detector activity yet."
                : "Unavailable until the backend responds."}
            </PanelMessage>
          ) : (
            detectors.map((d) => (
              <DetectorRow key={d.name} {...d} isML={d.is_ml} />
            ))
          )}
        </Panel>

        <Panel title="Recent detections" meta="Newest first">
          {sortedAlerts.length === 0 ? (
            <PanelMessage>
              {hasData
                ? "No detections yet. Run detection to start."
                : "Unavailable until the backend responds."}
            </PanelMessage>
          ) : (
            <ul>
              {sortedAlerts.slice(0, 6).map((alert) => (
                <AlertRow
                  key={alert.alert_id}
                  alert={alert}
                  onOpen={openAlert}
                />
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
