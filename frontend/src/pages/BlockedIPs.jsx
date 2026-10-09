import { useState } from "react";
import { ShieldX, Clock, AlertTriangle, CheckCircle } from "lucide-react";
import PageHeader from "../components/PageHeader";

const REASON_MAP = {
  "Brute Force Attack": {
    label: "Brute Force",
    color: "text-red-400",
    bg: "bg-red-500/20 border-red-500/30",
  },
  "Slow Brute Force": {
    label: "Slow Brute Force",
    color: "text-orange-400",
    bg: "bg-orange-500/20 border-orange-500/30",
  },
  "Credential Stuffing": {
    label: "Cred Stuffing",
    color: "text-purple-400",
    bg: "bg-purple-500/20 border-purple-500/30",
  },
  "Multiple IP Login": {
    label: "Multi-IP Login",
    color: "text-amber-400",
    bg: "bg-amber-500/20 border-amber-500/30",
  },
  "ML Anomaly Detected": {
    label: "ML Anomaly",
    color: "text-cyan-400",
    bg: "bg-cyan-500/20 border-cyan-500/30",
  },
  "Suspicious Login Time": {
    label: "Off-Hours Login",
    color: "text-blue-400",
    bg: "bg-blue-500/20 border-blue-500/30",
  },
};

function ReasonBadge({ type }) {
  const r = REASON_MAP[type] || {
    label: type,
    color: "text-slate-400",
    bg: "bg-slate-500/20 border-slate-500/30",
  };
  return (
    <span
      className={`text-xs font-semibold px-2 py-0.5 rounded border ${r.bg} ${r.color}`}
    >
      {r.label}
    </span>
  );
}

export default function BlockedIPs({ data }) {
  const { alerts } = data;
  const [search, setSearch] = useState("");

  // Build blocked IP details from HIGH severity alerts
  const ipMap = {};
  alerts.forEach((alert) => {
    if (alert.severity !== "HIGH") return;
    const ip = alert.ip;
    if (!ipMap[ip]) {
      ipMap[ip] = {
        ip,
        reason: alert.type,
        user: alert.user,
        detectedAt: alert.detected_at || "-",
        mitre: alert.mitre?.technique_id || "-",
        count: 0,
      };
    }
    ipMap[ip].count += 1;
  });

  const blockedList = Object.values(ipMap)
    .sort((a, b) => b.count - a.count)
    .filter(
      (item) =>
        search === "" ||
        item.ip.includes(search) ||
        item.user.toLowerCase().includes(search.toLowerCase()),
    );

  const totalBlocked = blockedList.length;

  // Classify IP as internal or external
  const isInternal = (ip) =>
    ip.startsWith("192.168.") ||
    ip.startsWith("10.") ||
    ip.startsWith("172.16.");

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader routeId="blocked-ips">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-red-700 leading-none">
              {totalBlocked}
            </p>
            <p className="ui-caption mt-1">Blocked</p>
          </div>
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-orange-700 leading-none">
              {blockedList.filter((b) => !isInternal(b.ip)).length}
            </p>
            <p className="ui-caption mt-1">External</p>
          </div>
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-amber-700 leading-none">
              {blockedList.filter((b) => isInternal(b.ip)).length}
            </p>
            <p className="ui-caption mt-1">Internal</p>
          </div>
        </div>
      </PageHeader>

      {/* Search */}
      <div className="flex items-center gap-2 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-3 py-2.5">
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
          placeholder="Search by IP or username..."
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

      {/* Empty state */}
      {blockedList.length === 0 && (
        <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl py-16 text-center">
          <CheckCircle className="w-8 h-8 text-green-700 mx-auto mb-3" />
          <p className="ui-body font-medium text-[color:var(--text-secondary)]">
            {search ? "No IPs match your search" : "No IPs blocked yet"}
          </p>
          <p className="ui-caption mt-1">
            {search
              ? "Try a different search term"
              : "Click ▶ Run to start detection"}
          </p>
        </div>
      )}

      {/* Blocked IP table */}
      {blockedList.length > 0 && (
        <div
          id="blocked-ip-list"
          className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl overflow-hidden"
        >
          {/* Table header - hidden on mobile, rows are stacked instead */}
          <div className="hidden sm:grid sm:grid-cols-12 gap-3 px-5 py-3 border-b border-[color:var(--border)] bg-[color:var(--bg-elevated)]">
            <div className="col-span-3 ui-table-head">IP Address</div>
            <div className="col-span-2 ui-table-head">Reason</div>
            <div className="col-span-2 ui-table-head">Target User</div>
            <div className="col-span-2 ui-table-head">MITRE</div>
            <div className="col-span-2 ui-table-head">Detected At</div>
            <div className="col-span-1 ui-table-head">Hits</div>
          </div>

          {/* Rows */}
          <div className="divide-y divide-[color:var(--border)]">
            {blockedList.map((item, i) => {
              const internal = isInternal(item.ip);
              return (
                <div
                  key={i}
                  className="flex flex-col items-start gap-2 sm:grid sm:grid-cols-12 sm:gap-3 sm:items-center px-4 sm:px-5 py-4 hover:bg-white/[0.02] transition-colors"
                >
                  {/* IP */}
                  <div className="sm:col-span-3 flex items-center gap-2">
                    <ShieldX className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                    <div>
                      <p className="text-sm font-semibold font-mono text-[color:var(--text-primary)]">
                        {item.ip}
                      </p>
                      <div className="flex items-center gap-1 mt-0.5">
                        <div
                          className={`w-1.5 h-1.5 rounded-full ${internal ? "bg-amber-400" : "bg-red-400"}`}
                        />
                        <span
                          className={`text-xs ${internal ? "text-amber-500" : "text-red-500"}`}
                        >
                          {internal ? "Internal" : "External"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Reason */}
                  <div className="sm:col-span-2 pl-6 sm:pl-0">
                    <ReasonBadge type={item.reason} />
                  </div>

                  {/* User */}
                  <div className="sm:col-span-2 pl-6 sm:pl-0">
                    <p className="ui-body text-[color:var(--text-primary)]">
                      {item.user}
                    </p>
                  </div>

                  {/* MITRE */}
                  <div className="sm:col-span-2 pl-6 sm:pl-0">
                    <span className="text-sm text-cyan-600 font-mono">
                      {item.mitre}
                    </span>
                  </div>

                  {/* Time */}
                  <div className="sm:col-span-2 flex items-center gap-1.5 pl-6 sm:pl-0">
                    <Clock className="w-3 h-3 text-slate-600 flex-shrink-0" />
                    <span className="text-sm text-[color:var(--text-secondary)] font-mono">
                      {item.detectedAt?.split(" ")[1] || "-"}
                    </span>
                  </div>

                  {/* Hit count */}
                  <div className="sm:col-span-1 pl-6 sm:pl-0">
                    <span className="text-sm font-semibold text-orange-700">
                      {item.count}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Info note */}
      <div className="flex items-start gap-3 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-xl p-4">
        <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="ui-label text-[color:var(--text-primary)] mb-1">
            Simulated Blocking
          </p>
          <p className="ui-caption leading-7">
            IP blocking in this prototype is simulated. In a production
            environment, HIGH severity detections would interface directly with
            firewall rules, iptables, or cloud security group APIs to enforce
            real network-level blocks.
          </p>
        </div>
      </div>
    </div>
  );
}
