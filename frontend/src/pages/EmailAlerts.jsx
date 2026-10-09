// frontend/src/pages/EmailAlerts.jsx

import { useState, useEffect, useRef } from "react";
import { Mail, CheckCircle, Clock, AlertTriangle } from "lucide-react";
import PageHeader from "../components/PageHeader";
import SeverityBadge from "../components/SeverityBadge";

const TYPE_ICONS = {
  "Brute Force Attack": "",
  "Slow Brute Force": "",
  "Credential Stuffing": "",
  "Multiple IP Login": "",
  "ML Anomaly Detected": "",
  "Suspicious Login Time": "",
};

export default function EmailAlerts({ data }) {
  const { alerts, markAlertPageRead } = data;
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("ALL");

  // Only HIGH severity alerts trigger emails
  const emailAlerts = alerts
    .filter((a) => a.severity === "HIGH")
    .filter((a) => filter === "ALL" || a.type === filter)
    .filter(
      (a) =>
        search === "" ||
        a.ip.includes(search) ||
        a.user.toLowerCase().includes(search.toLowerCase()) ||
        a.type.toLowerCase().includes(search.toLowerCase()),
    );

  const totalEmails = alerts.filter((a) => a.severity === "HIGH").length;

  const uniqueTypes = [
    ...new Set(alerts.filter((a) => a.severity === "HIGH").map((a) => a.type)),
  ];

  const FILTERS = ["ALL", ...uniqueTypes];

  // ── IntersectionObserver for auto‑marking email rows as read ───────────
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
              markAlertPageRead?.("email-alerts", alertId);
            }
          }
        });
      },
      { threshold: 0.1 },
    );

    // Observe only rows that are currently rendered
    Object.values(rowRefs.current).forEach((el) => {
      if (el) observerRef.current.observe(el);
    });

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, [emailAlerts, markAlertPageRead]);

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader routeId="email-alerts">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-green-700 leading-none">
              {totalEmails}
            </p>
            <p className="ui-caption mt-1">Sent</p>
          </div>
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-red-700 leading-none">
              0
            </p>
            <p className="ui-caption mt-1">Failed</p>
          </div>
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-cyan-700 leading-none">
              {totalEmails > 0 ? "100%" : "-"}
            </p>
            <p className="ui-caption mt-1">Success</p>
          </div>
        </div>
      </PageHeader>

      {/* SMTP status bar */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse flex-shrink-0" />
          <p className="ui-label text-green-700">SMTP Connected</p>
        </div>
        <div className="hidden sm:block w-px h-4 bg-[color:var(--border)]" />
        <p className="ui-caption">Provider: Gmail SMTP</p>
        <div className="hidden sm:block w-px h-4 bg-[color:var(--border)]" />
        <p className="ui-caption">Port: 465 (SSL)</p>
        <div className="hidden sm:block w-px h-4 bg-[color:var(--border)]" />
        <p className="ui-caption">Trigger: HIGH severity alerts only</p>
      </div>

      {/* Search + filter */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="flex items-center gap-2 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-3 py-2.5 flex-1">
          <svg
            className="w-4 h-4 text-[color:var(--text-muted)] flex-shrink-0"
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
            placeholder="Search by IP, user, or alert type..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-transparent text-sm text-[color:var(--text-primary)] placeholder-[color:var(--text-muted)] outline-none flex-1 min-w-0"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)] text-sm flex-shrink-0"
            >
              ✕
            </button>
          )}
        </div>

        {/* Type filter */}
        <div className="flex items-center gap-1 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg p-1.5 overflow-x-auto">
          {FILTERS.slice(0, 4).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-colors ${
                filter === f
                  ? "bg-slate-700 text-white"
                  : "text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)]"
              }`}
            >
              {f === "ALL"
                ? "ALL"
                : (TYPE_ICONS[f] || "•") + " " + f.split(" ")[0]}
            </button>
          ))}
        </div>
      </div>

      {/* Empty state */}
      {emailAlerts.length === 0 && (
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl py-16 text-center">
          <Mail className="w-8 h-8 text-[color:var(--text-muted)] mx-auto mb-3" />
          <p className="ui-body font-medium text-[color:var(--text-secondary)]">
            {totalEmails === 0
              ? "No emails sent yet"
              : "No results match your filter"}
          </p>
          <p className="ui-caption mt-1">
            {totalEmails === 0
              ? "HIGH severity alerts trigger automatic email notifications"
              : "Try clearing your search or changing the filter"}
          </p>
        </div>
      )}

      {/* Email log table */}
      {emailAlerts.length > 0 && (
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl overflow-hidden">
          {/* Table header - hidden on mobile, rows are stacked instead */}
          <div className="hidden sm:grid sm:grid-cols-12 gap-3 px-5 py-3 border-b border-[color:var(--border)] bg-[color:var(--bg-elevated)]">
            <div className="col-span-1 ui-table-head">Status</div>
            <div className="col-span-3 ui-table-head">Alert Type</div>
            <div className="col-span-2 ui-table-head">Severity</div>
            <div className="col-span-2 ui-table-head">Source IP</div>
            <div className="col-span-2 ui-table-head">Target User</div>
            <div className="col-span-2 ui-table-head">Sent At</div>
          </div>

          {/* Rows */}
          <div className="divide-y divide-[color:var(--border)] max-h-[480px] overflow-y-auto">
            {emailAlerts.map((alert, i) => (
              <div
                key={i}
                ref={(el) => {
                  if (el) {
                    rowRefs.current[alert.alert_id] = el;
                  } else {
                    delete rowRefs.current[alert.alert_id];
                  }
                }}
                data-alert-id={alert.alert_id}
                className="flex flex-col items-start gap-2 sm:grid sm:grid-cols-12 sm:gap-3 sm:items-center px-4 sm:px-5 py-4 hover:bg-white/[0.02] transition-colors"
              >
                {/* Status */}
                <div className="sm:col-span-1">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                </div>

                {/* Alert type */}
                <div className="sm:col-span-3 flex items-center gap-2 pl-6 sm:pl-0">
                  <span className="text-base">
                    {TYPE_ICONS[alert.type] || ""}
                  </span>
                  <div>
                    <p className="ui-body font-medium text-[color:var(--text-primary)]">
                      {alert.type}
                    </p>
                    {alert.mitre && (
                      <p className="text-sm text-cyan-600 font-mono">
                        {alert.mitre.technique_id}
                      </p>
                    )}
                  </div>
                </div>

                {/* Severity */}
                <div className="sm:col-span-2 pl-6 sm:pl-0">
                  <SeverityBadge severity={alert.severity} size="md" />
                </div>

                {/* IP */}
                <div className="sm:col-span-2 pl-6 sm:pl-0">
                  <p className="text-sm font-mono text-[color:var(--text-primary)]">
                    {alert.ip}
                  </p>
                </div>

                {/* User */}
                <div className="sm:col-span-2 pl-6 sm:pl-0">
                  <p className="ui-body text-[color:var(--text-secondary)]">
                    {alert.user}
                  </p>
                </div>

                {/* Time */}
                <div className="sm:col-span-2 flex items-center gap-1.5 pl-6 sm:pl-0">
                  <Clock className="w-3 h-3 text-slate-700 flex-shrink-0" />
                  <span className="text-sm text-[color:var(--text-secondary)] font-mono">
                    {(alert.detected_at || "").split(" ")[1] || "-"}
                  </span>
                </div>
              </div>
            ))}
          </div>

          {/* Table footer */}
          <div className="px-5 py-3 border-t border-[color:var(--border)] bg-[color:var(--bg-elevated)] flex items-center justify-between gap-2 flex-wrap">
            <p className="ui-caption">
              Showing {emailAlerts.length} of {totalEmails} emails
            </p>
            <div className="flex items-center gap-1.5">
              <CheckCircle className="w-3 h-3 text-green-400" />
              <p className="ui-caption text-green-700">
                All delivered successfully
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Info note */}
      <div className="flex items-start gap-3 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4">
        <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="ui-label text-[color:var(--text-primary)] mb-1">
            Email Configuration
          </p>
          <p className="ui-caption leading-7">
            Emails are sent via Gmail SMTP using an app password stored securely
            in the backend environment file. Only HIGH severity alerts trigger
            notifications to avoid alert fatigue. In production this would
            connect to a dedicated alerting service such as PagerDuty or AWS
            SNS.
          </p>
        </div>
      </div>
    </div>
  );
}
