import { Shield, Cpu, CheckCircle, ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";
import PageHeader from "../components/PageHeader";
import { shortAlertId } from "../utils/alertId";

const DETECTOR_INFO = {
  "Suspicious Login Time": {
    description:
      "Flags successful logins occurring between midnight and 06:00. Legitimate enterprise activity rarely occurs in this window. Attackers exploiting stolen credentials often operate from different time zones.",
    type: "rule",
  },
  "Multiple IP Login": {
    description:
      "Detects when the same user authenticates from two different IP addresses within 2 minutes. Physically impossible for a legitimate user - indicates stolen credentials or active session hijacking.",
    type: "rule",
  },
  "Brute Force Attack": {
    description:
      "Detects rapid repeated failed login attempts from a single IP. Automated tools typically attempt hundreds of passwords per minute. Fires when the failure threshold is reached.",
    type: "rule",
  },
  "Slow Brute Force": {
    description:
      "Detects attackers who deliberately slow their attempts to evade rate-limiting rules. One attempt every 10 minutes stays under the rapid-fire threshold but accumulates over time.",
    type: "rule",
  },
  "Credential Stuffing": {
    description:
      "Detects automated attacks using leaked username/password lists. Distinguished from brute force by the number of unique usernames tried - a stuffing attack tries many accounts, not one.",
    type: "rule",
  },
  "ML Anomaly Detected": {
    description:
      "Isolation Forest trained on 561,464 normal login events from the RBA Dataset (a privacy-preserving synthesis of real production logins) detects statistical deviations from normal behaviour. Catches novel attacks that rule-based detectors miss - including unknown attack patterns.",
    type: "ml",
    training: "561,464 normal RBA Dataset events",
    features: [
      "Login hour",
      "Failure status",
      "Source IP",
      "User account",
      "Failure rate",
      "Country",
      "Device type",
    ],
  },
};

// Thresholds, MITRE technique and tactic come from /api/config
// (backend/config.py) so this page always shows what the backend enforces.
const pad2 = (h) => String(h).padStart(2, "0");
const fmtScore = (v) => (typeof v === "number" ? v.toFixed(2) : "?");

function detectorPolicy(name, cfg) {
  const mitre = cfg?.mitre?.[name] || {};
  const base = { mitre: mitre.technique_id || "-", tactic: mitre.tactic || "-" };
  const r = cfg?.rules;
  const ml = cfg?.ml;
  if (!r || !ml) return { ...base, rule: "-", threshold: "-" };
  const slowWindowMin = r.slow_bf_window_seconds / 60;
  switch (name) {
    case "Suspicious Login Time":
      return {
        ...base,
        rule: `Login hour between ${pad2(r.suspicious_hour_start)}:00 and ${pad2(r.suspicious_hour_end)}:59`,
        threshold: "Any successful login in the restricted window",
      };
    case "Multiple IP Login":
      return {
        ...base,
        rule: `Same user, different IPs, within ${r.multi_ip_window_seconds} seconds`,
        threshold: `2 different IPs within ${r.multi_ip_window_seconds / 60} minutes`,
      };
    case "Brute Force Attack":
      return {
        ...base,
        rule: "Failed login count >= threshold from single IP",
        threshold: `${r.brute_force_threshold} failed attempts (configurable)`,
      };
    case "Slow Brute Force":
      return {
        ...base,
        rule: `${r.slow_bf_min_failures}+ failures within ${slowWindowMin} minutes, spread over ${r.slow_bf_min_spread_minutes}+ minutes`,
        threshold: `${r.slow_bf_min_failures} failures, minimum ${r.slow_bf_min_spread_minutes} minute spread, within ${slowWindowMin === 60 ? "1 hour" : `${slowWindowMin} minutes`}`,
      };
    case "Credential Stuffing":
      return {
        ...base,
        rule: `${r.cred_stuffing_min_users}+ unique usernames seen from a single IP`,
        threshold: `${r.cred_stuffing_min_users} unique usernames and ${r.cred_stuffing_min_failures}+ failed attempts from the IP`,
      };
    case "ML Anomaly Detected": {
      const failed = cfg?.mitre_ml_failed;
      return {
        ...base,
        ...(failed
          ? {
              mitre: `${base.mitre} / ${failed.technique_id}`,
              tactic: `${base.tactic} (successful logins) / ${failed.tactic} (failed logins)`,
            }
          : {}),
        rule: `Isolation Forest flags the event and its score is below ${fmtScore(ml.alert_margin)}`,
        threshold: `Score < ${fmtScore(ml.confidence_high_cutoff)} = High confidence, Score < ${fmtScore(ml.confidence_medium_cutoff)} = Medium confidence`,
      };
    }
    default:
      return { ...base, rule: "-", threshold: "-" };
  }
}

const TYPE_COLORS = {
  rule: {
    bg: "bg-cyan-500/20",
    text: "text-cyan-400",
    border: "border-cyan-500/30",
    label: "Rule-Based",
  },
  ml: {
    bg: "bg-purple-500/20",
    text: "text-purple-400",
    border: "border-purple-500/30",
    label: "ML",
  },
};

const SEVERITY_DOT = {
  HIGH: "bg-orange-400",
  MEDIUM: "bg-amber-400",
  LOW: "bg-blue-400",
};

function DetectorCard({ name, info, alerts, detectorData }) {
  const [expanded, setExpanded] = useState(false);
  const typeStyle = TYPE_COLORS[info.type] || TYPE_COLORS.rule;
  const alertCount = alerts.filter((a) => a.type === name).length;
  const lastAlert = alerts.find((a) => a.type === name);
  const lastTime = lastAlert?.detected_at?.split(" ")[1] || null;
  const isML = info.type === "ml";

  // Get recent trigger details from last alert
  const triggerDetails = lastAlert?.trigger_details;

  return (
    <div className="bg-[#0f1629] border border-[#1e2a3d] rounded-xl overflow-hidden">
      {/* Header */}
      <div className="p-4">
        <div className="flex items-start justify-between gap-2 flex-wrap mb-3">
          <div className="flex items-center gap-2">
            <div
              className={`w-7 h-7 rounded-lg grid place-items-center ${typeStyle.bg}`}
            >
              {isML ? (
                <Cpu className={`w-3.5 h-3.5 ${typeStyle.text}`} />
              ) : (
                <Shield className={`w-3.5 h-3.5 ${typeStyle.text}`} />
              )}
            </div>
            <div>
              <p className="text-[12px] font-bold text-[color:var(--text-primary)]">{name}</p>
              <span
                className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${typeStyle.bg} ${typeStyle.text} ${typeStyle.border}`}
              >
                {typeStyle.label}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-1.5 bg-green-500/10 border border-green-500/20 rounded-full px-2 py-0.5">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-[9px] text-green-400 font-bold">Active</span>
          </div>
        </div>

        {/* Description */}
        <p className="text-[11px] text-slate-500 leading-relaxed mb-3">
          {info.description}
        </p>

        {/* Stats row */}
        <div className="grid grid-cols-3 gap-2 mb-3">
          <div className="bg-[#0b1120] rounded-lg p-2 text-center">
            <p className="text-lg font-bold text-[color:var(--text-primary)]">{alertCount}</p>
            <p className="text-[9px] text-slate-600">Alerts</p>
          </div>
          <div className="bg-[#0b1120] rounded-lg p-2 text-center">
            <p className="text-[11px] font-bold text-cyan-400 truncate">
              {lastTime || "-"}
            </p>
            <p className="text-[9px] text-slate-600">Last fired</p>
          </div>
          <div className="bg-[#0b1120] rounded-lg p-2 text-center">
            <p className="text-[11px] font-bold text-slate-300">{info.mitre}</p>
            <p className="text-[9px] text-slate-600">MITRE</p>
            <p
              className="text-[9px] text-slate-500 truncate"
              title={info.tactic}
            >
              {info.tactic}
            </p>
          </div>
        </div>

        {/* Threshold info */}
        <div className="bg-[#0b1120] border border-[#1e2a3d] rounded-lg p-3 mb-3">
          <p className="text-[9px] font-semibold text-slate-600 uppercase tracking-widest mb-1">
            Detection Rule
          </p>
          <p className="text-[11px] text-slate-300">{info.rule}</p>
          <p className="text-[9px] text-slate-500 mt-1">
            Threshold: {info.threshold}
          </p>
        </div>

        {/* ML-specific info */}
        {isML && (
          <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-3 mb-3">
            <p className="text-[9px] font-semibold text-purple-400 uppercase tracking-widest mb-2">
              ML Model Details
            </p>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <p className="text-[9px] text-slate-600">Algorithm</p>
                <p className="text-[11px] text-[color:var(--text-primary)]">Isolation Forest</p>
              </div>
              <div>
                <p className="text-[9px] text-slate-600">Training data</p>
                <p className="text-[11px] text-[color:var(--text-primary)]">{info.training}</p>
              </div>
            </div>
            <p className="text-[9px] text-slate-600 mt-2 mb-1">
              Features used:
            </p>
            <div className="flex flex-wrap gap-1">
              {info.features?.map((f) => (
                <span
                  key={f}
                  className="text-[9px] bg-purple-500/20 text-purple-300 rounded px-1.5 py-0.5"
                >
                  {f}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Expand button for last trigger details */}
        {triggerDetails && (
          <button
            onClick={() => setExpanded((e) => !e)}
            className="w-full flex items-center justify-between bg-[#0b1120] border border-[#1e2a3d] hover:border-cyan-500/30 rounded-lg px-3 py-2 transition-colors"
          >
            <span className="text-[10px] text-slate-400 font-medium">
              Last trigger details
            </span>
            {expanded ? (
              <ChevronUp className="w-3.5 h-3.5 text-slate-500" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
            )}
          </button>
        )}
      </div>

      {/* Expanded trigger details */}
      {expanded && triggerDetails && (
        <div className="px-4 pb-4 border-t border-[#1e2a3d] pt-3 space-y-2">
          <div>
            <p className="text-[9px] text-slate-600">Triggered by</p>
            <p className="text-[11px] text-slate-300">
              {triggerDetails.actual}
            </p>
          </div>
          <div>
            <p className="text-[9px] text-slate-600">Rule applied</p>
            <p className="text-[11px] text-slate-300">{triggerDetails.rule}</p>
          </div>
          {triggerDetails.values && (
            <div>
              <p className="text-[9px] text-slate-600 mb-1">Raw values</p>
              <div className="bg-[#080d1a] rounded-lg p-2 font-mono text-[10px] text-cyan-400">
                {Object.entries(triggerDetails.values).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <span className="text-slate-500">{k}:</span>
                    <span className="truncate">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {lastAlert && (
            <div className="flex items-center gap-2 pt-1">
              <span
                className={`w-2 h-2 rounded-full flex-shrink-0 ${SEVERITY_DOT[lastAlert.severity] || "bg-slate-400"}`}
              />
              <span className="text-[10px] text-slate-500">
                Last alert: #{shortAlertId(lastAlert.alert_id)} - {lastAlert.severity}{" "}
                severity
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function DetectionEngine({ data }) {
  const { alerts, detectors, modelInfo, backendConfig } = data;
  const pct = (v) => (typeof v === "number" ? `${(v * 100).toFixed(1)}%` : "-");

  const ruleAlerts = alerts.filter((a) => a.type !== "ML Anomaly Detected");
  const mlAlerts = alerts.filter((a) => a.type === "ML Anomaly Detected");
  const totalAlerts = alerts.length;

  const detectorNames = Object.keys(DETECTOR_INFO);

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader routeId="detection-engine">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="bg-[#0f1629] border border-[#1e2a3d] rounded-lg px-3 py-1.5 text-center">
            <p className="text-lg font-bold text-[color:var(--text-primary)]">{totalAlerts}</p>
            <p className="text-[9px] text-slate-600">Total Alerts</p>
          </div>
          <div className="bg-[#0f1629] border border-cyan-500/20 rounded-lg px-3 py-1.5 text-center">
            <p className="text-lg font-bold text-cyan-400">
              {ruleAlerts.length}
            </p>
            <p className="text-[9px] text-slate-600">Rule Detections</p>
          </div>
          <div className="bg-[#0f1629] border border-purple-500/20 rounded-lg px-3 py-1.5 text-center">
            <p className="text-lg font-bold text-purple-400">
              {mlAlerts.length}
            </p>
            <p className="text-[9px] text-slate-600">ML Detections</p>
          </div>
        </div>
      </PageHeader>

      {/* How hybrid detection works */}
      <div className="bg-[#0f1629] border border-[#1e2a3d] rounded-xl p-4">
        <p className="text-[11px] font-semibold text-slate-300 mb-2">
          Hybrid Detection Architecture
        </p>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:gap-3">
          <div className="flex-1 bg-[#0b1120] border border-cyan-500/20 rounded-lg p-3 text-center">
            <Shield className="w-5 h-5 text-cyan-400 mx-auto mb-1" />
            <p className="text-[11px] font-bold text-cyan-400">
              Rule-Based (5)
            </p>
            <p className="text-[10px] text-slate-600 mt-1">
              Deterministic. Fires reliably on its coded patterns.
            </p>
          </div>
          <div className="text-slate-600 text-lg font-bold text-center">+</div>
          <div className="flex-1 bg-[#0b1120] border border-purple-500/20 rounded-lg p-3 text-center">
            <Cpu className="w-5 h-5 text-purple-400 mx-auto mb-1" />
            <p className="text-[11px] font-bold text-purple-400">
              ML-Based (1)
            </p>
            <p className="text-[10px] text-slate-600 mt-1">
              Probabilistic. {pct(modelInfo?.precision)} precision,{" "}
              {pct(modelInfo?.recall)} recall. Catches novel
              attacks rules never
              anticipated.
            </p>
          </div>
          <div className="text-slate-600 text-lg font-bold text-center">=</div>
          <div className="flex-1 bg-[#0b1120] border border-green-500/20 rounded-lg p-3 text-center">
            <CheckCircle className="w-5 h-5 text-green-400 mx-auto mb-1" />
            <p className="text-[11px] font-bold text-green-400">
              Hybrid Coverage
            </p>
            <p className="text-[10px] text-slate-600 mt-1">
              Known attacks caught by rules. Unknown patterns caught by ML.
              Complementary coverage.
            </p>
          </div>
        </div>
      </div>

      {/* Detector cards */}
      <div>
        <p className="text-[10px] font-semibold text-slate-600 uppercase tracking-widest mb-3">
          Active Detectors
        </p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {detectorNames.map((name) => (
            <DetectorCard
              key={name}
              name={name}
              info={{ ...DETECTOR_INFO[name], ...detectorPolicy(name, backendConfig) }}
              alerts={alerts}
              detectorData={detectors.find((d) => d.name === name)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
