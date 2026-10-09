import { useState, useEffect } from "react";
import {
  Activity,
  Cpu,
  Database,
  Shield,
  CheckCircle,
  AlertTriangle,
  Clock,
  Zap,
  CircleDashed,
  WifiOff,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import { POLLED_ENDPOINTS } from "../config/api";
import { formatUtcTime } from "../utils/time";

const TONES = {
  ok: {
    cls: "bg-green-500/10 border-green-500/20 text-green-400",
    Icon: CheckCircle,
  },
  warn: {
    cls: "bg-amber-500/15 border-amber-500/30 text-amber-400",
    Icon: AlertTriangle,
  },
  error: {
    cls: "bg-red-500/15 border-red-500/30 text-red-400",
    Icon: WifiOff,
  },
  neutral: {
    cls: "bg-[color:var(--bg-elevated)] border-[color:var(--border)] text-[color:var(--text-secondary)]",
    Icon: CircleDashed,
  },
};

function StatusBadge({ tone = "neutral", label, title }) {
  const { cls, Icon } = TONES[tone] || TONES.neutral;
  return (
    <div
      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border flex-shrink-0 ${cls}`}
      title={title}
    >
      <Icon className="w-3.5 h-3.5" aria-hidden="true" />
      <span className="text-sm font-medium">{label}</span>
    </div>
  );
}

function HealthCard({ icon: Icon, label, value, sub, iconClass }) {
  return (
    <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
      <div
        className={`w-8 h-8 rounded-lg grid place-items-center mb-3 ${iconClass}`}
      >
        <Icon className="w-4 h-4" aria-hidden="true" />
      </div>
      <p className="text-2xl font-semibold leading-none mb-1 tabular-nums text-[color:var(--text-primary)]">
        {value}
      </p>
      <p className="ui-label text-[color:var(--text-primary)]">{label}</p>
      {sub && <p className="ui-caption mt-1">{sub}</p>}
    </div>
  );
}

function MetricRow({ label, value, color = "text-[color:var(--text-primary)]" }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-[color:var(--border)] last:border-0 gap-4">
      <span className="ui-body text-[color:var(--text-secondary)]">
        {label}
      </span>
      <span className={`text-sm font-medium text-right ${color}`}>{value}</span>
    </div>
  );
}

const pct = (v) => (typeof v === "number" ? `${(v * 100).toFixed(1)}%` : "-");

export default function SystemHealth({ data }) {
  const {
    modelInfo,
    pipelineStats,
    status,
    alerts,
    agentsData,
    detectors,
    enrichment,
    connection,
    running,
  } = data;
  const [uptimeSeconds, setUptimeSeconds] = useState(null);
  const online = connection.status === "online" || connection.status === "degraded";

  const formatUptime = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
  };

  // Uptime reported by the backend, ticked locally between polls.
  useEffect(() => {
    if (typeof status?.uptime_seconds === "number") {
      setUptimeSeconds(Math.max(0, Math.floor(status.uptime_seconds)));
    }
  }, [status?.uptime_seconds]);

  useEffect(() => {
    const id = setInterval(() => {
      setUptimeSeconds((current) =>
        typeof current === "number" ? current + 1 : current,
      );
    }, 1000);
    return () => clearInterval(id);
  }, []);

  // ── Component states, all derived from what the backend reported ────
  const apiState = {
    online: { tone: "ok", label: "API online" },
    degraded: { tone: "warn", label: "API degraded" },
    offline: { tone: "error", label: "API offline" },
    connecting: { tone: "neutral", label: "Checking API" },
  }[connection.status];

  const modelState = !status
    ? { tone: "neutral", label: "Model unknown" }
    : status.model_loaded
      ? { tone: "ok", label: "Model loaded" }
      : { tone: "error", label: "Model not loaded" };

  const pipelineState = !status
    ? { tone: "neutral", label: "Pipeline unknown" }
    : running
      ? { tone: "ok", label: "Pipeline running" }
      : { tone: "neutral", label: "Pipeline idle" };

  const llmState = !enrichment
    ? { tone: "neutral", label: "LLM unknown" }
    : enrichment.llm_available
      ? { tone: "ok", label: "LLM available" }
      : { tone: "warn", label: "LLM unavailable" };

  const totalAlerts = alerts.length;
  const highAlerts = alerts.filter((a) => a.severity === "HIGH").length;
  const mlAlerts = alerts.filter(
    (a) => a.type === "ML Anomaly Detected",
  ).length;
  const lastRun = pipelineStats?.last_run || "Never";
  const eventsProcessed = pipelineStats?.events_processed;
  const duration = pipelineStats?.duration_seconds || null;
  const avgMs = pipelineStats?.avg_event_time_ms || null;

  const trainedAt = modelInfo?.trained_at
    ? modelInfo.trained_at.split("T")[0]
    : "-";

  const failingEndpoints = POLLED_ENDPOINTS.filter(
    (p) => connection.endpoints[p] && !connection.endpoints[p].ok,
  );

  const summary =
    connection.status === "offline"
      ? {
          tone: "error",
          title: "Backend unreachable",
          body: connection.lastSuccess
            ? `No endpoint has answered since ${formatUtcTime(connection.lastSuccess)}. Figures on this page are the last values received.`
            : "No endpoint has answered yet. Start the backend API; the dashboard retries automatically.",
        }
      : connection.status === "connecting"
        ? {
            tone: "neutral",
            title: "Checking backend",
            body: "Waiting for the first response from the backend API.",
          }
        : connection.status === "degraded"
          ? {
              tone: "warn",
              title: "Partial connectivity",
              body: `${failingEndpoints.length} of ${POLLED_ENDPOINTS.length} polled endpoints are failing. Affected panels show the last data received.`,
            }
          : status && !status.model_loaded
            ? {
                tone: "warn",
                title: "ML model not loaded",
                body: "The API is responding, but model.pkl was not found, so ML anomaly detection cannot run.",
              }
            : {
                tone: "ok",
                title: "All polled endpoints responding",
                body: `The Isolation Forest model is loaded and runs inference only. The pipeline is ${running ? "running" : "idle"}${pipelineStats?.last_run ? `; last run ${pipelineStats.last_run}` : ""}.`,
              };
  const SummaryIcon = TONES[summary.tone].Icon;

  return (
    <div className="p-3 sm:p-6 space-y-5 sm:space-y-6">
      <PageHeader routeId="system-health">
        <StatusBadge {...apiState} />
        <StatusBadge {...modelState} />
        <StatusBadge {...pipelineState} />
        <StatusBadge {...llmState} />
      </PageHeader>

      {/* Summary */}
      <div
        className={`flex items-start gap-3 rounded-xl border p-4 ${TONES[summary.tone].cls}`}
        role="status"
      >
        <SummaryIcon className="w-4 h-4 flex-shrink-0 mt-0.5" aria-hidden="true" />
        <div>
          <p className="ui-label">{summary.title}</p>
          <p className="ui-body text-[color:var(--text-secondary)]">
            {summary.body}
          </p>
        </div>
      </div>

      {/* Top stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <HealthCard
          icon={Clock}
          label="API Uptime"
          value={
            online && typeof uptimeSeconds === "number"
              ? formatUptime(uptimeSeconds)
              : "-"
          }
          sub={online ? "Since backend server start" : "Backend not reachable"}
          iconClass="bg-green-500/20 text-green-400"
        />
        <HealthCard
          icon={Zap}
          label="Events Processed"
          value={
            typeof eventsProcessed === "number"
              ? eventsProcessed.toLocaleString()
              : "-"
          }
          sub="Last pipeline run"
          iconClass="bg-cyan-500/20 text-cyan-400"
        />
        <HealthCard
          icon={Shield}
          label="Alerts Generated"
          value={totalAlerts}
          sub={`${highAlerts} HIGH severity`}
          iconClass="bg-orange-500/20 text-orange-400"
        />
        <HealthCard
          icon={Cpu}
          label="ML Detections"
          value={mlAlerts}
          sub="Isolation Forest flags"
          iconClass="bg-purple-500/20 text-purple-400"
        />
      </div>

      {/* Middle row: ML Model + Pipeline Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* ML Model */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center justify-between gap-2 flex-wrap mb-4">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <p className="ui-label text-[color:var(--text-primary)]">
                ML Model Status
              </p>
            </div>
            <StatusBadge {...modelState} />
          </div>

          <MetricRow label="Algorithm" value="Isolation Forest" />
          <MetricRow label="Trained On" value={modelInfo?.training_size || "-"} />
          <MetricRow
            label="Data Source"
            value={modelInfo?.trained_on || "-"}
            color="text-cyan-400"
          />
          <MetricRow label="Train Date" value={trainedAt} />
          <MetricRow label="Contamination" value="0.4 (40%)" />
          <MetricRow label="N Estimators" value="200 trees" />
          <MetricRow
            label="Features"
            value={
              modelInfo?.feature_count ? `${modelInfo.feature_count}` : "-"
            }
          />
          <MetricRow
            label="Inference Mode"
            value="Runtime only"
            color="text-cyan-400"
          />

          <div className="mt-5 pt-4 border-t border-[color:var(--border)]">
            <p className="ui-kicker mb-1">Evaluation Metrics</p>
            <p className="ui-caption mb-3">
              Offline evaluation recorded at training time
            </p>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Precision", value: pct(modelInfo?.precision) },
                { label: "Recall", value: pct(modelInfo?.recall) },
                { label: "F1-Score", value: pct(modelInfo?.f1) },
                {
                  label: "ROC-AUC",
                  value:
                    typeof modelInfo?.roc_auc === "number"
                      ? modelInfo.roc_auc.toFixed(3)
                      : "-",
                },
              ].map(({ label, value }) => (
                <div
                  key={label}
                  className="bg-[color:var(--bg-elevated)] border border-[color:var(--border)] rounded-lg p-3 text-center"
                >
                  <p className="text-2xl font-semibold leading-none tabular-nums text-[color:var(--text-primary)]">
                    {value}
                  </p>
                  <p className="ui-caption mt-1">{label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Pipeline Stats */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center justify-between gap-2 flex-wrap mb-4">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-green-400" />
              <p className="ui-label text-[color:var(--text-primary)]">
                Pipeline Stats
              </p>
            </div>
            <StatusBadge {...pipelineState} />
          </div>

          <MetricRow label="Last Run" value={lastRun} />
          <MetricRow
            label="Events Processed"
            value={
              typeof eventsProcessed === "number"
                ? eventsProcessed.toLocaleString()
                : "-"
            }
          />
          <MetricRow
            label="Alerts (last run)"
            value={pipelineStats?.alerts_generated ?? "-"}
          />
          <MetricRow
            label="Run Duration"
            value={duration ? `${duration}s` : "-"}
          />
          <MetricRow
            label="Avg Event Time"
            value={avgMs ? `${avgMs}ms` : "-"}
            color="text-cyan-400"
          />

          <div className="mt-5 pt-4 border-t border-[color:var(--border)]">
            <p className="ui-kicker mb-1">Configuration</p>
            <p className="ui-caption mb-1">Set in the backend source</p>
            <MetricRow label="Detection Threshold" value="5 failed attempts" />
            <MetricRow label="ML Confidence Guard" value="High + Medium only" />
            <MetricRow
              label="Internal IP Guard"
              value="Disabled"
              color="text-[color:var(--text-secondary)]"
            />
          </div>

          <div className="mt-5 pt-4 border-t border-[color:var(--border)]">
            <p className="ui-kicker mb-1">Pipeline Stages</p>
            <p className="ui-caption mb-2">
              Stages run inside one pipeline process; the backend does not
              report per-stage health.
            </p>
            {agentsData.length === 0 ? (
              <p className="ui-caption py-2">No stage data received.</p>
            ) : (
              agentsData.map((a) => (
                <MetricRow
                  key={a.name}
                  label={`${String(a.name).replace(/ Agent$/, " Stage")} · ${a.role}`}
                  value={`${(a.processed ?? 0).toLocaleString()} processed`}
                />
              ))
            )}
          </div>
        </div>
      </div>

      {/* Bottom row: Detectors + API endpoints */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Detectors */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-cyan-400" />
            <p className="ui-label text-[color:var(--text-primary)]">
              Detectors
            </p>
          </div>
          {detectors.length === 0 ? (
            <p className="ui-caption py-2">No detector data received.</p>
          ) : (
            <div className="space-y-2">
              {detectors.map((d) => (
                <div
                  key={d.name}
                  className="flex items-center justify-between gap-2 flex-wrap py-2 border-b border-[color:var(--border)] last:border-0"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <div
                      className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                        d.is_ml ? "bg-purple-400" : "bg-cyan-400"
                      }`}
                    />
                    <span className="ui-body text-[color:var(--text-primary)] truncate">
                      {d.name}
                    </span>
                    {d.is_ml && (
                      <span className="text-xs bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded px-1.5 py-0.5">
                        ML
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="ui-caption tabular-nums">
                      {d.alerts} alerts · last {d.last}
                    </span>
                    {d.is_ml && status && !status.model_loaded && (
                      <StatusBadge tone="error" label="No model" />
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* API Health */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center justify-between gap-2 flex-wrap mb-4">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-cyan-400" />
              <p
                id="system-api-health"
                className="ui-label text-[color:var(--text-primary)]"
              >
                API Endpoints
              </p>
            </div>
            <span className="ui-caption">
              {connection.lastAttempt
                ? `Checked ${formatUtcTime(connection.lastAttempt)}`
                : "Not checked yet"}
            </span>
          </div>
          <div className="space-y-2">
            {POLLED_ENDPOINTS.map((path) => {
              const e = connection.endpoints[path];
              return (
                <div
                  key={path}
                  className="flex items-center justify-between gap-2 flex-wrap py-2 border-b border-[color:var(--border)] last:border-0"
                >
                  <span className="text-sm text-[color:var(--text-secondary)] font-mono truncate">
                    /api/{path}
                  </span>
                  <div className="flex items-center gap-3">
                    {e?.ok && (
                      <span className="ui-caption tabular-nums">{e.ms} ms</span>
                    )}
                    <StatusBadge
                      tone={!e ? "neutral" : e.ok ? "ok" : "error"}
                      label={!e ? "Pending" : e.ok ? "OK" : e.error}
                    />
                  </div>
                </div>
              );
            })}
            <div className="flex items-center justify-between gap-2 flex-wrap py-2">
              <span className="text-sm text-[color:var(--text-secondary)] font-mono truncate">
                /api/run
              </span>
              <span className="ui-caption">POST, used by the Run button</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
