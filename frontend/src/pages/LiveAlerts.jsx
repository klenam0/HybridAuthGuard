// frontend/src/pages/LiveAlerts.jsx

import { useState, useEffect, useRef } from "react";
import { ShieldX, Bell, FileText } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";
import { FILTER_ACTIVE } from "../config/severity";
import { shortAlertId } from "../utils/alertId";

const ACTIONS = {
  HIGH: { Icon: ShieldX, color: "text-red-400", label: "Simulated block + email" },
  CRITICAL: { Icon: ShieldX, color: "text-red-400", label: "Simulated block + email" },
  MEDIUM: { Icon: Bell, color: "text-cyan-400", label: "Admin notice (simulated)" },
  LOW: { Icon: FileText, color: "text-slate-400", label: "Logged" },
};

const FILTERS = ["ALL", "HIGH", "MEDIUM", "LOW"];

export default function LiveAlerts({ data }) {
  const { alerts, stats, markAlertPageRead } = data;
  const [filter, setFilter] = useState("ALL");

  const filtered =
    filter === "ALL" ? alerts : alerts.filter((a) => a.severity === filter);

  const blockedIPs = stats?.simulated_block_ips || stats?.blocked_ips || [];

  const recentActions = alerts.slice(0, 6).map((a, i) => {
    const action = ACTIONS[a.severity] || ACTIONS.LOW;
    return {
      time: (a.detected_at || "").split(" ")[1]?.slice(0, 5) || `00:0${i}`,
      Icon: action.Icon,
      color: action.color,
      label: action.label,
      detail:
        a.severity === "HIGH" || a.severity === "CRITICAL" ? a.ip : a.user,
    };
  });

  // ── IntersectionObserver for auto‑marking HIGH alerts as read ──────────
  const rowRefs = useRef({});
  const observerRef = useRef(null);

  useEffect(() => {
    if (observerRef.current) {
      observerRef.current.disconnect();
    }

    observerRef.current = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const alertId = entry.target.dataset.alertId;
            if (alertId) {
              markAlertPageRead?.("live-alerts", alertId);
            }
          }
        });
      },
      { threshold: 0.1 },
    );

    // Observe only HIGH‑severity rows (they are the ones contributing to badge)
    Object.values(rowRefs.current).forEach((el) => {
      if (el) observerRef.current.observe(el);
    });

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, [filtered, markAlertPageRead]);

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5 lg:h-full lg:flex lg:flex-col">
      {/* Header + filter tabs */}
      <PageHeader routeId="live-alerts">
        <div className="flex items-center gap-1 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg p-1.5 overflow-x-auto">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-2.5 sm:px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-colors ${
                filter === f
                  ? FILTER_ACTIVE[f]
                  : "text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)]"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </PageHeader>

      {/* Alert table */}
      <div
        id="live-alerts-feed"
        className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl overflow-hidden lg:flex-1 lg:min-h-64 lg:flex lg:flex-col"
      >
        {/* Table head - hidden on mobile, rows are stacked instead */}
        <div className="hidden sm:grid sm:grid-cols-12 gap-3 px-5 py-3 border-b border-[color:var(--border)] bg-[color:var(--bg-elevated)]">
          <div className="col-span-5 ui-table-head">Alert</div>
          <div className="col-span-2 ui-table-head">MITRE</div>
          <div className="col-span-3 ui-table-head">User / IP</div>
          <div className="col-span-2 ui-table-head">Action</div>
        </div>

        {/* Table body */}
        <div className="divide-y divide-[color:var(--border)] max-h-96 lg:max-h-none lg:flex-1 lg:min-h-0 overflow-y-auto">
          {filtered.length === 0 ? (
            <div className="py-14 text-center">
              <p className="ui-body text-[color:var(--text-secondary)]">
                No alerts yet
              </p>
              <p className="ui-caption mt-1">Click ▶ Run to start detection</p>
            </div>
          ) : (
            filtered.map((alert, i) => {
              const action = ACTIONS[alert.severity] || ACTIONS.LOW;
              const ActionIcon = action.Icon;

              return (
                <div
                  key={i}
                  ref={(el) => {
                    if (alert.severity === "HIGH") {
                      if (el) {
                        rowRefs.current[alert.alert_id] = el;
                      } else {
                        delete rowRefs.current[alert.alert_id];
                      }
                    }
                  }}
                  data-alert-id={
                    alert.severity === "HIGH" ? alert.alert_id : undefined
                  }
                  className="flex flex-col gap-2 sm:grid sm:grid-cols-12 sm:gap-3 px-4 sm:px-5 py-4 hover:bg-white/[0.02] transition-colors"
                >
                  {/* Alert */}
                  <div className="sm:col-span-5 flex items-start gap-2 min-w-0">
                    <SeverityBadge severity={alert.severity} size="md" />
                    <div className="min-w-0">
                      <p className="ui-body font-medium text-[color:var(--text-primary)] truncate">
                        {alert.type}
                      </p>
                      <p className="text-sm text-[color:var(--text-muted)] font-mono">
                        ALT-{alert.alert_id ? shortAlertId(alert.alert_id) : String(i).padStart(4, "0")}
                      </p>
                    </div>
                  </div>

                  {/* MITRE */}
                  <div className="sm:col-span-2 flex items-center pl-8 sm:pl-0">
                    {alert.mitre ? (
                      <a
                        href={alert.mitre.url}
                        target="_blank"
                        rel="noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="ui-body text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
                      >
                        {alert.mitre.technique_id}
                      </a>
                    ) : (
                      <span className="ui-body text-[color:var(--text-muted)] font-mono">
                        -
                      </span>
                    )}
                  </div>

                  {/* User / IP */}
                  <div className="sm:col-span-3 flex flex-col justify-center min-w-0 pl-8 sm:pl-0">
                    <p className="ui-body text-[color:var(--text-primary)] truncate">
                      {alert.user}
                    </p>
                    <p className="text-sm text-[color:var(--text-secondary)] font-mono truncate">
                      {alert.ip}
                    </p>
                  </div>

                  {/* Action */}
                  <div className="sm:col-span-2 flex items-center gap-1.5 pl-8 sm:pl-0">
                    <ActionIcon
                      className={`w-3.5 h-3.5 flex-shrink-0 ${action.color}`}
                    />
                    <span className={`text-sm font-medium ${action.color}`}>
                      {action.label}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Bottom panels */}
      <div
        id="live-alerts-actions"
        className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:flex-shrink-0"
      >
        {/* Recent Automated Actions */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-cyan-400 text-base">⚡</span>
            <p className="ui-label text-[color:var(--text-primary)]">
              Recent Automated Actions
            </p>
          </div>
          {recentActions.length === 0 ? (
            <p className="ui-body text-[color:var(--text-secondary)]">
              No actions yet
            </p>
          ) : (
            <div className="space-y-3">
              {recentActions.map((a, i) => {
                const Icon = a.Icon;
                return (
                  <div key={i} className="flex items-center gap-2 sm:gap-3">
                    <span className="text-sm text-[color:var(--text-secondary)] font-mono w-10 sm:w-12 flex-shrink-0">
                      {a.time}
                    </span>
                    <Icon className={`w-3 h-3 flex-shrink-0 ${a.color}`} />
                    <span className={`text-sm flex-1 font-medium ${a.color}`}>
                      {a.label}
                    </span>
                    <span className="text-sm text-[color:var(--text-secondary)] font-mono truncate max-w-20 sm:max-w-32">
                      {a.detail}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Blocked IP Addresses */}
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4 sm:p-5">
          <div className="flex items-center justify-between gap-2 mb-3 flex-wrap">
            <div className="flex items-center gap-2">
              <ShieldX className="w-3.5 h-3.5 text-red-400" />
              <p className="ui-label text-[color:var(--text-primary)]">
                Simulated IP Blocks
              </p>
            </div>
            <span className="text-sm bg-red-500/20 text-red-400 border border-red-500/30 rounded-full px-2 py-0.5 font-semibold">
              {blockedIPs.length} IPs
            </span>
          </div>
          {blockedIPs.length === 0 ? (
            <p className="ui-body text-[color:var(--text-secondary)]">
              No simulated blocks yet (nothing is enforced in this prototype)
            </p>
          ) : (
            <div className="space-y-3">
              {blockedIPs.map((ip, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className="text-red-500 text-sm flex-shrink-0">⚠</span>
                  <span className="text-sm font-mono text-[color:var(--text-primary)] flex-1 truncate">
                    {ip}
                  </span>
                  <button className="text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)] text-sm transition-colors flex-shrink-0">
                    ⓘ
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
