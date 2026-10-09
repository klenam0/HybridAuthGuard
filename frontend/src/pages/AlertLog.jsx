// frontend/src/pages/AlertLog.jsx

import { useState, useEffect, useRef } from "react";
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  ShieldX,
  Bell,
  FileText,
  Mail,
  Clock,
  Hash,
  User,
  Globe,
  Cpu,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import { FILTER_ACTIVE } from "../config/severity";

const SEVERITY_BORDER = {
  HIGH: "border-l-orange-500",
  MEDIUM: "border-l-amber-500",
  LOW: "border-l-blue-500",
};

const SEVERITY_GLOW = {
  HIGH: "hover:border-orange-500/30",
  MEDIUM: "hover:border-amber-500/30",
  LOW: "hover:border-blue-500/30",
};

const ACTION_ICON = {
  HIGH: { Icon: ShieldX, color: "text-red-400", label: "IP Blocked" },
  MEDIUM: { Icon: Bell, color: "text-cyan-400", label: "Admin Notified" },
  LOW: { Icon: FileText, color: "text-slate-400", label: "Log Written" },
};

const SORT_OPTIONS = [
  { value: "newest", label: "Newest First" },
  { value: "oldest", label: "Oldest First" },
  { value: "severity", label: "Severity" },
  { value: "type", label: "Alert Type" },
];

function AlertCard({
  alert,
  index,
  isTarget,
  onTargetClear,
  forceExpand,
  onRead,
}) {
  const [expanded, setExpanded] = useState(forceExpand || false);

  // Sync expanded state when "Expand All" / "Collapse All" toggle changes
  useEffect(() => {
    if (forceExpand !== undefined) {
      setExpanded(forceExpand);
    }
  }, [forceExpand]);

  // Auto-expand when this card is the navigation target
  useEffect(() => {
    if (isTarget) {
      setExpanded(true);
      if (onRead) onRead(alert.alert_id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isTarget]);

  // Clear target highlight after 3 seconds
  useEffect(() => {
    if (!isTarget) return;
    const timer = setTimeout(() => {
      if (onTargetClear) onTargetClear();
    }, 3000);
    return () => clearTimeout(timer);
  }, [isTarget, onTargetClear]);

  const severity = alert.severity || "LOW";
  const action = ACTION_ICON[severity] || ACTION_ICON.LOW;
  const ActionIcon = action.Icon;
  const isML = alert.type === "ML Anomaly Detected";

  const time = alert.detected_at || alert.timestamp || "-";
  const hour = time.split(" ")[1] || "-";

  const toggleExpanded = () => {
    setExpanded((prev) => {
      const next = !prev;
      if (next && onRead) {
        onRead(alert.alert_id);
      }
      return next;
    });
  };

  return (
    <div
      className={`bg-[#0f1629] border border-l-4 ${SEVERITY_BORDER[severity] || "border-l-slate-600"} border-[#1e2a3d] ${SEVERITY_GLOW[severity]} rounded-xl transition-all overflow-hidden ${
        isTarget
          ? "ring-2 ring-cyan-500/50 ring-offset-1 ring-offset-[#080d1a]"
          : ""
      }`}
    >
      {/* Collapsed header - always visible */}
      <button
        onClick={toggleExpanded}
        className="w-full px-3 sm:px-5 py-4 flex items-center gap-2 sm:gap-3 text-left hover:bg-white/[0.02] transition-colors"
      >
        {/* Index */}
        <span className="text-[10px] text-slate-700 font-mono w-5 sm:w-6 flex-shrink-0">
          {String(index + 1).padStart(2, "0")}
        </span>

        {/* Severity badge */}
        <SeverityBadge severity={severity} />

        {/* Alert type */}
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <p className="text-[12px] font-semibold text-slate-200 truncate">
            {alert.type}
          </p>
          {isML && (
            <span className="text-[8px] bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded px-1 flex-shrink-0">
              ML
            </span>
          )}
        </div>

        {/* Alert ID */}
        <span className="text-[10px] text-slate-700 font-mono hidden md:block flex-shrink-0">
          #{alert.alert_id || "-"}
        </span>

        {/* IP */}
        <span className="text-[10px] text-slate-500 font-mono hidden lg:block flex-shrink-0">
          {alert.ip}
        </span>

        {/* Time */}
        <span className="text-[10px] text-slate-600 font-mono flex-shrink-0">
          {hour}
        </span>

        {/* Expand icon */}
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-slate-600 flex-shrink-0" />
        ) : (
          <ChevronDown className="w-4 h-4 text-slate-600 flex-shrink-0" />
        )}
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-3 sm:px-5 pb-5 space-y-4 border-t border-[#1e2a3d]">
          {/* Meta row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-4">
            <div className="flex items-center gap-2">
              <Hash className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[9px] text-slate-600">Alert ID</p>
                <p className="text-[11px] font-mono text-slate-300 truncate">
                  {alert.alert_id || "-"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Clock className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[9px] text-slate-600">Detected At</p>
                <p className="text-[11px] font-mono text-slate-300 truncate">
                  {time}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <User className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[9px] text-slate-600">Target User</p>
                <p className="text-[11px] text-slate-300 truncate">
                  {alert.user || "-"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Globe className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-[9px] text-slate-600">Source IP</p>
                <p className="text-[11px] font-mono text-slate-300 truncate">
                  {alert.ip || "-"}
                </p>
              </div>
            </div>
          </div>

          {/* Explanation */}
          <div className="bg-[#0b1120] border border-[#1e2a3d] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">
                Analysis
              </p>
              {alert.llm_explanation ? (
                <span className="text-[9px] bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded px-2 py-0.5">
                  🤖 AI Generated
                </span>
              ) : alert.enriched === false ? (
                <span className="text-[9px] bg-slate-500/20 text-slate-500 border border-slate-500/30 rounded px-2 py-0.5 animate-pulse">
                  ⏳ AI Enriching...
                </span>
              ) : null}
            </div>
            <p className="text-[12px] text-slate-300 leading-relaxed whitespace-pre-line">
              {alert.llm_explanation ||
                alert.explanation ||
                alert.description ||
                "No explanation available."}
            </p>
          </div>

          {/* Feature explanation for ML alerts */}
          {alert.feature_explanation && (
            <div className="bg-[#0b1120] border border-purple-500/20 rounded-lg p-4">
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-2">
                Why the ML Model Flagged This
              </p>
              <p className="text-[11px] text-purple-300 mb-3">
                {alert.feature_explanation.summary}
              </p>
              <div className="space-y-2">
                {(alert.feature_explanation.contributions || [])
                  .slice(0, 4)
                  .map((c, i) => (
                    <div key={i} className="flex items-center gap-2 sm:gap-3">
                      <span className="text-[10px] text-slate-500 w-16 sm:w-28 flex-shrink-0 truncate">
                        {c.feature_label}
                      </span>
                      <div className="flex-1 bg-[#1e2a3d] rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full transition-all ${
                            c.deviation > 2
                              ? "bg-red-400"
                              : c.deviation > 1.5
                                ? "bg-orange-400"
                                : "bg-slate-500"
                          }`}
                          style={{
                            width: `${Math.min(100, c.deviation * 25)}%`,
                          }}
                        />
                      </div>
                      <span className="text-[10px] text-slate-400 w-10 sm:w-12 text-right flex-shrink-0">
                        {c.deviation.toFixed(1)}σ
                      </span>
                      <span
                        className={`text-[9px] flex-shrink-0 hidden sm:inline ${
                          c.is_anomalous ? "text-orange-400" : "text-slate-600"
                        }`}
                      >
                        {c.is_anomalous ? "⚠ unusual" : "normal"}
                      </span>
                    </div>
                  ))}
              </div>
              <p className="text-[9px] text-slate-600 mt-2">
                σ = standard deviations from normal baseline (561,464 normal
                RBA Dataset training logins)
              </p>
            </div>
          )}

          {/* MITRE section */}
          {alert.mitre && (
            <div className="bg-[#0b1120] border border-cyan-500/20 rounded-lg p-4">
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-3">
                MITRE ATT&CK
              </p>
              <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 sm:gap-4">
                <div className="space-y-2 flex-1 min-w-0">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="text-[13px] font-bold text-cyan-400 font-mono">
                      {alert.mitre.technique_id}
                    </span>
                    <span className="text-[11px] font-semibold text-slate-200">
                      {alert.mitre.technique_name}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[9px] text-slate-600">Tactic:</span>
                    <span className="text-[10px] bg-slate-700/50 text-slate-300 rounded px-2 py-0.5">
                      {alert.mitre.tactic}
                    </span>
                  </div>
                </div>

                <a
                  href={alert.mitre.url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center justify-center gap-1.5 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:text-cyan-300 rounded-lg px-3 py-1.5 text-[10px] font-semibold transition-colors flex-shrink-0 w-full sm:w-auto"
                >
                  <ExternalLink className="w-3 h-3" />
                  View on MITRE
                </a>
              </div>
            </div>
          )}

          {/* ML Score - only for ML alerts */}
          {isML && alert.anomaly_score !== undefined && (
            <div className="bg-[#0b1120] border border-purple-500/20 rounded-lg p-4">
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-3">
                ML Anomaly Details
              </p>
              <div className="grid grid-cols-3 gap-2 sm:gap-4">
                <div>
                  <p className="text-[9px] text-slate-600">Anomaly Score</p>
                  <p className="text-[14px] font-bold text-purple-400 font-mono">
                    {alert.anomaly_score}
                  </p>
                  <p className="text-[9px] text-slate-600 mt-0.5 hidden sm:block">
                    Lower = more anomalous
                  </p>
                </div>
                <div>
                  <p className="text-[9px] text-slate-600">Confidence</p>
                  <p
                    className={`text-[14px] font-bold font-mono ${
                      alert.confidence === "High"
                        ? "text-red-400"
                        : alert.confidence === "Medium"
                          ? "text-amber-400"
                          : "text-slate-400"
                    }`}
                  >
                    {alert.confidence || "-"}
                  </p>
                </div>
                <div>
                  <p className="text-[9px] text-slate-600">Algorithm</p>
                  <p className="text-[14px] font-bold text-purple-400">
                    Isolation Forest
                  </p>
                </div>
              </div>
              {/* Score bar */}
              <div className="mt-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[9px] text-slate-600">Normal</span>
                  <span className="text-[9px] text-slate-600">Anomalous</span>
                </div>
                <div className="w-full bg-[#1e2a3d] rounded-full h-2">
                  <div
                    className="h-2 rounded-full bg-gradient-to-r from-green-500 to-red-500"
                    style={{
                      width: `${Math.min(100, Math.max(10, Math.abs(alert.anomaly_score || 0) * 500))}%`,
                      marginLeft: "auto",
                    }}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Trigger Details */}
          {alert.trigger_details && (
            <div className="bg-[#0b1120] border border-[#1e2a3d] rounded-lg p-4">
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-3">
                Why This Triggered
              </p>
              <div className="space-y-2">
                <div className="flex items-start gap-3">
                  <span className="text-[9px] text-slate-600 w-16 sm:w-20 flex-shrink-0 pt-0.5">
                    Rule
                  </span>
                  <span className="text-[11px] text-slate-300">
                    {alert.trigger_details.rule}
                  </span>
                </div>
                <div className="flex items-start gap-3">
                  <span className="text-[9px] text-slate-600 w-16 sm:w-20 flex-shrink-0 pt-0.5">
                    Threshold
                  </span>
                  <span className="text-[11px] text-slate-300">
                    {alert.trigger_details.threshold}
                  </span>
                </div>
                <div className="flex items-start gap-3">
                  <span className="text-[9px] text-slate-600 w-16 sm:w-20 flex-shrink-0 pt-0.5">
                    Detected
                  </span>
                  <span className="text-[11px] text-orange-400 font-medium">
                    {alert.trigger_details.actual}
                  </span>
                </div>
                {alert.trigger_details.values && (
                  <div className="mt-2 bg-[#080d1a] rounded-lg p-2">
                    <p className="text-[9px] text-slate-600 mb-1">Raw values</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
                      {Object.entries(alert.trigger_details.values).map(
                        ([k, v]) => (
                          <div
                            key={k}
                            className="flex justify-between text-[10px] font-mono"
                          >
                            <span className="text-slate-600">{k}</span>
                            <span className="text-cyan-400">{String(v)}</span>
                          </div>
                        ),
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Response action */}
          <div className="flex items-center justify-between gap-2 flex-wrap bg-[#0b1120] border border-[#1e2a3d] rounded-lg px-4 py-3">
            <div className="flex items-center gap-2">
              <ActionIcon className={`w-4 h-4 ${action.color}`} />
              <div>
                <p className="text-[10px] text-slate-600">Automated Response</p>
                <p className={`text-[11px] font-semibold ${action.color}`}>
                  {action.label}
                </p>
              </div>
            </div>
            {severity === "HIGH" && (
              <div className="flex items-center gap-1.5">
                <Mail className="w-3 h-3 text-green-400" />
                <span className="text-[10px] text-green-400">Email sent</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AlertLog({ data }) {
  const { alerts, targetAlertId, clearTargetAlertId, markAlertPageRead } = data;
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("ALL");
  const [sort, setSort] = useState("newest");
  const [expanded, setExpanded] = useState(false);
  const cardRefs = useRef({});

  // Scroll to and highlight target alert when navigation occurs
  useEffect(() => {
    if (!targetAlertId) return;
    const timer = setTimeout(() => {
      const el = cardRefs.current[targetAlertId];
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }, 150);
    return () => clearTimeout(timer);
  }, [targetAlertId]);

  const FILTERS = ["ALL", "HIGH", "MEDIUM", "LOW"];

  // Filter
  let filtered = alerts
    .filter((a) => filter === "ALL" || a.severity === filter)
    .filter(
      (a) =>
        search === "" ||
        a.type?.toLowerCase().includes(search.toLowerCase()) ||
        a.ip?.includes(search) ||
        a.user?.toLowerCase().includes(search.toLowerCase()) ||
        a.alert_id?.toLowerCase().includes(search.toLowerCase()) ||
        a.mitre?.technique_id?.toLowerCase().includes(search.toLowerCase()),
    );

  // Sort
  filtered = [...filtered].sort((a, b) => {
    if (sort === "newest")
      return (b.detected_at || "").localeCompare(a.detected_at || "");
    if (sort === "oldest")
      return (a.detected_at || "").localeCompare(b.detected_at || "");
    if (sort === "severity") {
      const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
      return (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
    }
    if (sort === "type") return (a.type || "").localeCompare(b.type || "");
    return 0;
  });

  const total = alerts.length;
  const high = alerts.filter((a) => a.severity === "HIGH").length;
  const medium = alerts.filter((a) => a.severity === "MEDIUM").length;
  const low = alerts.filter((a) => a.severity === "LOW").length;

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader routeId="alert-log">
        {/* Summary counts */}
        <div className="flex items-center gap-3 flex-wrap">
          {[
            {
              label: "Total",
              value: total,
              color: "text-[color:var(--text-primary)]",
            },
            { label: "HIGH", value: high, color: "text-orange-400" },
            { label: "MEDIUM", value: medium, color: "text-amber-400" },
            { label: "LOW", value: low, color: "text-blue-400" },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center"
            >
              <p className={`text-2xl font-semibold leading-none ${color}`}>
                {value}
              </p>
              <p className="ui-caption mt-1">{label}</p>
            </div>
          ))}
        </div>
      </PageHeader>

      {/* Controls */}
      <div
        id="alert-log-search"
        className="flex flex-col sm:flex-row sm:items-center gap-3"
      >
        {/* Search */}
        <div className="flex items-center gap-2 bg-[#0f1629] border border-[#1e2a3d] rounded-lg px-3 py-2 w-full sm:flex-1">
          <svg
            className="w-3.5 h-3.5 text-slate-600 flex-shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            type="text"
            placeholder="Search by type, IP, user, alert ID, MITRE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent text-[11px] text-slate-300 placeholder-slate-700 outline-none flex-1 min-w-0"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="text-slate-600 hover:text-slate-400 text-xs flex-shrink-0"
            >
              ✕
            </button>
          )}
        </div>

        {/* Severity filter */}
        <div className="flex items-center gap-1 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg p-1.5 w-full sm:w-auto overflow-x-auto">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-colors ${
                filter === f
                  ? FILTER_ACTIVE[f]
                  : "text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)]"
              }`}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Sort */}
        <select
          value={sort}
          onChange={(e) => setSort(e.target.value)}
          className="bg-[#0f1629] border border-[#1e2a3d] text-[11px] text-slate-300 rounded-lg px-3 py-2 outline-none w-full sm:w-auto"
        >
          {SORT_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>

        {/* Expand all toggle */}
        <button
          onClick={() => setExpanded((e) => !e)}
          className="bg-[#0f1629] border border-[#1e2a3d] text-[11px] text-slate-400 hover:text-slate-200 rounded-lg px-3 py-2 transition-colors w-full sm:w-auto whitespace-nowrap"
        >
          {expanded ? "Collapse All" : "Expand All"}
        </button>
      </div>

      {/* Results count */}
      <p className="text-[10px] text-slate-600">
        Showing {filtered.length} of {total} alerts
        {search && ` matching "${search}"`}
      </p>

      {/* Alert cards */}
      {filtered.length === 0 ? (
        <div className="bg-[#0f1629] border border-[#1e2a3d] rounded-xl py-16 text-center">
          <Cpu className="w-8 h-8 text-slate-700 mx-auto mb-3" />
          <p className="text-slate-600 text-sm font-semibold">
            {total === 0 ? "No alerts yet" : "No alerts match your search"}
          </p>
          <p className="text-slate-700 text-xs mt-1">
            {total === 0
              ? "Click ▶ Run to start detection"
              : "Try clearing your search or changing the filter"}
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((alert, i) => (
            <div
              key={alert.alert_id || i}
              ref={(el) => {
                if (alert.alert_id) cardRefs.current[alert.alert_id] = el;
              }}
            >
              <AlertCard
                alert={alert}
                index={i}
                isTarget={alert.alert_id === targetAlertId}
                onTargetClear={clearTargetAlertId}
                forceExpand={expanded}
                onRead={(id) => markAlertPageRead?.("alert-log", id)}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
