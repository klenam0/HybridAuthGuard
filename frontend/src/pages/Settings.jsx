import { useState } from "react";
import {
  Lock,
  Download,
  Trash2,
  Shield,
  Cpu,
  Mail,
  Activity,
  AlertTriangle,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import { enginePolicy } from "../utils/policy";

const API = "http://localhost:5000/api";

function SettingRow({ label, description, children }) {
  return (
    <div className="flex items-start justify-between gap-3 py-3 border-b border-[#1e2a3d] last:border-0">
      <div className="flex-1 mr-2 sm:mr-6">
        <p className="text-[12px] font-semibold text-slate-200">{label}</p>
        <p className="text-[10px] text-slate-600 mt-0.5">{description}</p>
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

function SectionCard({ title, icon: Icon, iconColor, children }) {
  return (
    <div className="bg-[#0f1629] border border-[#1e2a3d] rounded-xl p-4">
      <div className="flex items-center gap-2 mb-4 pb-3 border-b border-[#1e2a3d]">
        <Icon className={`w-4 h-4 ${iconColor}`} />
        <p className="text-[12px] font-bold text-[color:var(--text-primary)]">{title}</p>
      </div>
      {children}
    </div>
  );
}

// Read-only on/off state. These settings live in the backend source and
// cannot be changed from the dashboard, so they are not interactive.
function StateBadge({ on, label }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-[11px] font-semibold px-3 py-1 rounded-lg border whitespace-nowrap ${
        on
          ? "bg-green-500/10 border-green-500/20 text-green-400"
          : "bg-[color:var(--bg-elevated)] border-[color:var(--border)] text-[color:var(--text-secondary)]"
      }`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${on ? "bg-green-400" : "bg-slate-500"}`}
        aria-hidden="true"
      />
      {label || (on ? "On" : "Off")}
    </span>
  );
}

function ValueBadge({ value, unit = "" }) {
  return (
    <span className="bg-[#0b1120] border border-[#1e2a3d] text-cyan-400 font-mono text-[11px] px-3 py-1 rounded-lg whitespace-nowrap">
      {value}
      {unit}
    </span>
  );
}

export default function Settings({ data }) {
  const { modelInfo, backendConfig, adminToken, setAdminToken, status } = data;
  const policy = enginePolicy(backendConfig, status);
  const rules = backendConfig?.rules;
  const ml = backendConfig?.ml;
  const show = (v) => (v === undefined || v === null ? "-" : String(v));
  const pad2 = (h) => String(h).padStart(2, "0");

  const [clearing, setClearing] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [tokenInput, setTokenInput] = useState("");
  const [clearMessage, setClearMessage] = useState("");

  // The admin token is typed in here at runtime and kept in memory only;
  // it is never part of the JavaScript bundle (audit F30).
  const clearToken = adminToken;

  const handleClearAlerts = async () => {
    if (!clearToken) return;
    if (
      !window.confirm(
        "Clear all alerts? A backup is written first and can be restored via /api/restore-alerts.",
      )
    )
      return;
    setClearing(true);
    setClearMessage("");
    try {
      const res = await fetch(`${API}/clear-alerts`, {
        method: "POST",
        headers: {
          "X-Admin-Token": clearToken,
        },
      });
      if (res.status === 401) {
        setAdminToken("");
        setClearMessage("The API rejected the admin token.");
        setClearing(false);
        return;
      }
    } catch {}
    setClearing(false);
    window.location.reload();
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const r = await fetch(`${API}/alerts`);
      const alerts = await r.json();
      const csv = [
        [
          "Alert ID",
          "Type",
          "Severity",
          "IP",
          "User",
          "Detected At",
          "MITRE ID",
        ].join(","),
        ...alerts.map((a) =>
          [
            a.alert_id || "",
            a.type || "",
            a.severity || "",
            a.ip || "",
            a.user || "",
            a.detected_at || "",
            a.mitre?.technique_id || "",
          ].join(","),
        ),
      ].join("\n");

      const blob = new Blob([csv], { type: "text/csv" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `soc-alerts-${new Date().toISOString().split("T")[0]}.csv`;
      link.click();
      URL.revokeObjectURL(url);
    } catch {}
    setExporting(false);
  };

  const precision = modelInfo?.precision
    ? `${(modelInfo.precision * 100).toFixed(1)}%`
    : "-";
  const recall = modelInfo?.recall
    ? `${(modelInfo.recall * 100).toFixed(1)}%`
    : "-";
  const f1 = modelInfo?.f1 ? `${(modelInfo.f1 * 100).toFixed(1)}%` : "-";
  const rocAuc = modelInfo?.roc_auc ? modelInfo.roc_auc.toFixed(3) : "-";

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader routeId="settings">
        <span
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border bg-[color:var(--bg-elevated)] border-[color:var(--border)] text-sm font-medium text-[color:var(--text-secondary)]"
          title="Change these values in the backend source and restart the pipeline"
        >
          <Lock className="w-3.5 h-3.5" aria-hidden="true" />
          Read-only
        </span>
      </PageHeader>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Detection Settings */}
        <SectionCard
          title="Detection Settings"
          icon={Shield}
          iconColor="text-cyan-400"
        >
          <SettingRow
            label="Rule Engine"
            description={
              policy.v3
                ? "v3 windowed rules; the legacy thresholds below are not used (see Detection Engine for the v3 windows)"
                : "Legacy rules (the thresholds below)"
            }
          >
            <ValueBadge value={show(policy.rulesMode)} />
          </SettingRow>
          {policy.v3 && (
            <SettingRow
              label="Response Policy"
              description="Incident tiers: step-up is a simulated MFA challenge, recorded and not enforced"
            >
              <ValueBadge
                value={`step-up ≤ ${policy.stepUpRate}/day · queue ≤ ${policy.queueRate}/day · block ${policy.blockOn ? "on" : "off"}`}
              />
            </SettingRow>
          )}
          <SettingRow
            label="Brute Force Threshold"
            description="Number of failed logins before alert triggers"
          >
            <ValueBadge value={show(rules?.brute_force_threshold)} unit=" attempts" />
          </SettingRow>
          <SettingRow
            label="Slow Brute Force Window"
            description="Time window for slow brute force detection"
          >
            <ValueBadge
              value={rules ? String(rules.slow_bf_window_seconds / 60) : "-"}
              unit=" minutes"
            />
          </SettingRow>
          <SettingRow
            label="Multiple IP Window"
            description="Time window for same-user multiple IP detection"
          >
            <ValueBadge value={show(rules?.multi_ip_window_seconds)} unit=" seconds" />
          </SettingRow>
          <SettingRow
            label="Credential Stuffing Threshold"
            description="Unique usernames from one IP to trigger alert"
          >
            <ValueBadge value={show(rules?.cred_stuffing_min_users)} unit=" usernames" />
          </SettingRow>
          <SettingRow
            label="Off-Hours Window"
            description="Hours considered suspicious for login activity"
          >
            <ValueBadge
              value={
                rules
                  ? `${pad2(rules.suspicious_hour_start)}:00 – ${pad2(rules.suspicious_hour_end)}:59`
                  : "-"
              }
            />
          </SettingRow>
          <SettingRow
            label="Internal IP Guard"
            description="Exclude internal IPs from ML scoring (INTERNAL_IP_GUARD_ENABLED)"
          >
            <StateBadge
              on={Boolean(rules?.internal_ip_guard_enabled)}
              label={rules?.internal_ip_guard_enabled ? undefined : "Disabled"}
            />
          </SettingRow>
          <SettingRow
            label="Internal IP Ranges"
            description="Subnets treated as internal"
          >
            <ValueBadge
              value={
                rules?.internal_networks?.join(", ") || "-"
              }
            />
          </SettingRow>
        </SectionCard>

        {/* ML Settings */}
        <SectionCard
          title="ML Model Settings"
          icon={Cpu}
          iconColor="text-purple-400"
        >
          <SettingRow
            label="ML Detection"
            description={
              policy.mlAlerts === false
                ? "ML mode v4: no ML alerts; the model below is the legacy one, used only in legacy mode"
                : "Isolation Forest anomaly detection"
            }
          >
            <StateBadge
              on={policy.mlAlerts !== false}
              label={policy.mlAlerts === false ? "Off (ML mode v4)" : undefined}
            />
          </SettingRow>
          <SettingRow
            label="Algorithm"
            description="Anomaly detection algorithm"
          >
            <ValueBadge value="Isolation Forest" />
          </SettingRow>
          <SettingRow
            label="Contamination"
            description="Expected anomaly rate in training data"
          >
            <ValueBadge value={show(ml?.contamination)} />
          </SettingRow>
          <SettingRow
            label="N Estimators"
            description="Number of trees in the forest"
          >
            <ValueBadge value={show(modelInfo?.n_estimators)} unit=" trees" />
          </SettingRow>
          <SettingRow
            label="Feature Count"
            description="Input features used per event"
          >
            <ValueBadge
              value={modelInfo?.feature_count || "-"}
              unit=" features"
            />
          </SettingRow>
          <SettingRow
            label="Training Set"
            description="Events used to train the model"
          >
            <ValueBadge value={modelInfo?.training_size || "-"} />
          </SettingRow>
          <SettingRow
            label="Inference Mode"
            description="Model never retrains on live data"
          >
            <ValueBadge value="Runtime only" />
          </SettingRow>

          {/* Eval metrics */}
          <div className="mt-3 pt-3 border-t border-[#1e2a3d]">
            <p className="text-[10px] text-slate-600 mb-2">
              Evaluation Metrics (RBA Dataset)
            </p>
            <div className="grid grid-cols-2 gap-2">
              {[
                {
                  label: "Precision",
                  value: precision,
                  color: "text-green-400",
                },
                { label: "Recall", value: recall, color: "text-amber-400" },
                { label: "F1-Score", value: f1, color: "text-cyan-400" },
                { label: "ROC-AUC", value: rocAuc, color: "text-purple-400" },
              ].map(({ label, value, color }) => (
                <div
                  key={label}
                  className="bg-[#0b1120] rounded-lg p-2 text-center"
                >
                  <p className={`text-sm font-bold ${color}`}>{value}</p>
                  <p className="text-[9px] text-slate-600">{label}</p>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>

        {/* Email Settings */}
        <SectionCard
          title="Email Alerting"
          icon={Mail}
          iconColor="text-green-400"
        >
          <SettingRow
            label="Email Notifications"
            description="Sent only when SMTP credentials are set in the backend .env file"
          >
            <ValueBadge value="Depends on .env" />
          </SettingRow>
          <SettingRow
            label="HIGH Severity Alerts"
            description="Email on HIGH severity detections"
          >
            <StateBadge on />
          </SettingRow>
          <SettingRow
            label="MEDIUM Severity Alerts"
            description="Email on MEDIUM severity detections"
          >
            <StateBadge on={false} />
          </SettingRow>
          <SettingRow
            label="SMTP Provider"
            description="Email delivery service"
          >
            <ValueBadge value="Gmail SMTP" />
          </SettingRow>
          <SettingRow label="Port" description="SMTP connection port">
            <ValueBadge value="465 (SSL)" />
          </SettingRow>
          <SettingRow
            label="Credentials"
            description="Stored in backend .env file"
          >
            <ValueBadge value="App password" />
          </SettingRow>
        </SectionCard>

        {/* Pipeline Settings + Data Management */}
        <div className="space-y-4">
          <SectionCard
            title="Pipeline Settings"
            icon={Activity}
            iconColor="text-blue-400"
          >
            <SettingRow
              label="Event Delay"
              description="Seconds between processing each log event"
            >
              <ValueBadge value="0.1 – 1.0" unit="s" />
            </SettingRow>
            <SettingRow
              label="Log Source"
              description="Current log input format"
            >
              <ValueBadge value="Authentication logs" />
            </SettingRow>
            <SettingRow
              label="Pipeline Mode"
              description="How the system processes events"
            >
              <ValueBadge value="Sequential stream" />
            </SettingRow>
          </SectionCard>

          <SectionCard
            title="Data Management"
            icon={AlertTriangle}
            iconColor="text-amber-400"
          >
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div>
                  <p className="text-[12px] font-semibold text-slate-200">
                    Export Alerts
                  </p>
                  <p className="text-[10px] text-slate-600 mt-0.5">
                    Download all alerts as CSV
                  </p>
                </div>
                <button
                  onClick={handleExport}
                  disabled={exporting}
                  className="flex items-center gap-1.5 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/30 text-[11px] font-semibold px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
                >
                  <Download className="w-3.5 h-3.5" />
                  {exporting ? "Exporting..." : "Export CSV"}
                </button>
              </div>

              <div className="pt-2 border-t border-[#1e2a3d]">
                <p className="text-[12px] font-semibold text-slate-200">
                  Admin Token
                </p>
                <p className="text-[10px] text-slate-600 mt-0.5 mb-2">
                  ADMIN_TOKEN from backend/.env. Held in this tab's memory only;
                  needed to run the pipeline or clear alerts.
                </p>
                {adminToken ? (
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-green-400">Token set for this session</span>
                    <button
                      onClick={() => setAdminToken("")}
                      className="text-[11px] text-slate-400 underline"
                    >
                      Forget
                    </button>
                  </div>
                ) : (
                  <form
                    className="flex items-center gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (tokenInput.trim()) setAdminToken(tokenInput.trim());
                      setTokenInput("");
                    }}
                  >
                    <input
                      type="password"
                      autoComplete="off"
                      value={tokenInput}
                      onChange={(e) => setTokenInput(e.target.value)}
                      placeholder="Admin token"
                      aria-label="Admin token"
                      className="flex-1 min-w-0 bg-[#0b1120] border border-[#1e2a3d] rounded-lg px-2 py-1 text-[11px] text-slate-200"
                    />
                    <button
                      type="submit"
                      className="bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/30 text-[11px] font-semibold px-3 py-1.5 rounded-lg"
                    >
                      Use
                    </button>
                  </form>
                )}
                {clearMessage && (
                  <p className="text-[10px] text-red-400 mt-1">{clearMessage}</p>
                )}
              </div>

              <div className="flex items-center justify-between gap-2 flex-wrap pt-2 border-t border-[#1e2a3d]">
                <div>
                  <p className="text-[12px] font-semibold text-red-400">
                    Clear All Alerts
                  </p>
                  <p className="text-[10px] text-slate-600 mt-0.5">
                    Permanently delete all saved alerts
                  </p>
                </div>
                {/* Tooltip on a wrapper: disabled buttons get no hover events in some browsers */}
                <span
                  title={
                    clearToken
                      ? undefined
                      : "Enter the admin token above to enable."
                  }
                >
                  <button
                    onClick={handleClearAlerts}
                    disabled={clearing || !clearToken}
                    className="flex items-center gap-1.5 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 text-[11px] font-semibold px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    {clearing ? "Clearing..." : "Clear Alerts"}
                  </button>
                </span>
              </div>
            </div>
          </SectionCard>
        </div>
      </div>

      {/* Note */}
      <div className="bg-[#0f1629] border border-amber-500/20 rounded-xl p-4">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-[11px] font-semibold text-slate-300 mb-1">
              Configuration Note
            </p>
            <p className="text-[10px] text-slate-600 leading-relaxed">
              Detection thresholds and ML parameters shown here reflect the
              current system configuration. In this prototype, changes to these
              values require updating the Python source files and restarting the
              pipeline. A production system would persist these to a
              configuration database with live hot-reload capability. Email
              credentials are stored securely in the backend environment file
              and are never exposed to the frontend.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
