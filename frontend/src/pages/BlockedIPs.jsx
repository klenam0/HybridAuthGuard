import { useState } from "react";
import { ShieldX, Clock, AlertTriangle, CheckCircle } from "lucide-react";
import PageHeader from "../components/PageHeader";
import TierBadge from "../components/TierBadge";
import { alertTier, enginePolicy } from "../utils/policy";

// IPv4 CIDR membership, for the internal/external split shown on this page.
function ipv4ToInt(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!/^\d+$/.test(p) || v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

function inCidr(ip, cidr) {
  const [base, bitsText] = cidr.split("/");
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(base);
  const bits = Number(bitsText);
  if (a === null || b === null || !(bits >= 0 && bits <= 32)) return false;
  const size = 2 ** (32 - bits);
  return Math.floor(a / size) === Math.floor(b / size);
}

const DEFAULT_INTERNAL_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

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
  const { alerts, stats, status, backendConfig } = data;
  const policy = enginePolicy(backendConfig, status);
  const internalNetworks =
    backendConfig?.rules?.internal_networks || DEFAULT_INTERNAL_NETWORKS;
  const [search, setSearch] = useState("");

  // IPs with a simulated response in the recent alerts: a block (legacy:
  // the recorded response, else the HIGH-severity policy for older alerts;
  // v3: the block tier) or a v3 step-up challenge (simulated MFA, recorded,
  // never enforced). A block outranks a challenge.
  const ipMap = {};
  alerts.forEach((alert) => {
    const tier = alertTier(alert);
    const blocked = tier
      ? tier === "block"
      : alert.response
        ? alert.response.simulated_block
        : alert.severity === "HIGH";
    const action = blocked ? "block" : tier === "step_up" ? "step_up" : null;
    if (!action) return;
    const ip = alert.ip;
    if (!ipMap[ip]) {
      ipMap[ip] = {
        ip,
        action,
        reason: alert.type,
        user: alert.user,
        detectedAt: alert.detected_at || "-",
        mitre: alert.mitre?.technique_id || "-",
        count: 0,
      };
    }
    if (action === "block") ipMap[ip].action = "block";
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

  const totalBlocked = blockedList.filter((b) => b.action === "block").length;
  const totalChallenged = blockedList.filter((b) => b.action === "step_up").length;
  // Whole store (v3 /api/stats), not only the recent alerts listed below.
  const storeChallenged = stats?.step_up_ips?.length;

  // Classify IP as internal or external
  const isInternal = (ip) => internalNetworks.some((net) => inCidr(ip, net));

  return (
    <div className="p-3 sm:p-6 space-y-4 sm:space-y-5">
      <PageHeader
        routeId="blocked-ips"
        description={
          policy.v3
            ? "Source IPs whose incidents reached a response tier: step-up challenges (simulated MFA, recorded, never enforced) and, if the block tier is on, simulated blocks. Nothing is enforced in this prototype."
            : undefined
        }
      >
        <div className="flex items-center gap-3 flex-wrap">
          {policy.v3 && (
            <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
              <p className="text-2xl font-semibold text-orange-700 leading-none">
                {storeChallenged ?? totalChallenged}
              </p>
              <p className="ui-caption mt-1">Challenged (simulated MFA, not enforced)</p>
            </div>
          )}
          <div className="bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg px-4 py-2 text-center">
            <p className="text-2xl font-semibold text-red-700 leading-none">
              {totalBlocked}
            </p>
            <p className="ui-caption mt-1">
              {policy.v3 && !policy.blockOn ? "Blocks (block tier off)" : "Simulated blocks"}
            </p>
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
            {search
              ? "No IPs match your search"
              : policy.v3
                ? "No IP challenged or blocked yet"
                : "No IPs blocked yet"}
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
            <div className="col-span-2 ui-table-head">Response</div>
            <div className="col-span-2 ui-table-head">Reason</div>
            <div className="col-span-2 ui-table-head">Target User</div>
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
                    <ShieldX
                      className={`w-3.5 h-3.5 flex-shrink-0 ${item.action === "block" ? "text-red-400" : "text-orange-500"}`}
                    />
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

                  {/* Response */}
                  <div className="sm:col-span-2 pl-6 sm:pl-0">
                    <TierBadge tier={item.action} long className="whitespace-normal" />
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
            {policy.v3 ? "Nothing is enforced" : "Simulated Blocking"}
          </p>
          {policy.v3 ? (
            <p className="ui-caption leading-7">
              A step-up challenge is recorded for the IP for one hour; no login
              is stopped or delayed. A production system would ask its identity
              provider for MFA here. The block tier is{" "}
              {policy.blockOn
                ? "on: blocks are simulated and recorded, not sent to a firewall."
                : "off: no rate reached a 0.80 precision lower bound on validation data, so nothing is blocked."}
            </p>
          ) : (
            <p className="ui-caption leading-7">
              IP blocking in this prototype is simulated. In a production
              environment, HIGH severity detections would interface directly with
              firewall rules, iptables, or cloud security group APIs to enforce
              real network-level blocks.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
