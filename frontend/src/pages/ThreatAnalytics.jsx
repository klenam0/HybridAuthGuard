import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from "recharts";
import { Globe, User, Target, Clock, Shield, Cpu } from "lucide-react";
import PageHeader from "../components/PageHeader";
import {
  axisTick,
  barCursor,
  chartTooltip,
  formatHour,
  lineCursor,
} from "../config/chartTheme";

const COLORS = [
  "#f97316",
  "#8b5cf6",
  "#06b6d4",
  "#22c55e",
  "#ec4899",
  "#f59e0b",
  "#3b82f6",
  "#ef4444",
];

function CardWrap({ children, className = "" }) {
  return (
    <div
      className={`bg-[#0f1629] border border-[#1e2a3d] rounded-xl p-4 ${className}`}
    >
      {children}
    </div>
  );
}

function CardTitle({ children }) {
  return (
    <p className="text-[11px] font-semibold text-slate-400 mb-3">{children}</p>
  );
}

export default function ThreatAnalytics({ data }) {
  const { alerts, timeline, stats } = data;

  // ── Derived data ────────────────────────────────────────────────────────

  // Top targeted users
  const userCounts = {};
  alerts.forEach((a) => {
    if (a.severity === "HIGH" || a.severity === "MEDIUM") {
      userCounts[a.user] = (userCounts[a.user] || 0) + 1;
    }
  });
  const topUsers = Object.entries(userCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([user, count]) => ({ user, count }));

  // Top attacker IPs
  const ipCounts = {};
  alerts.forEach((a) => {
    if (a.severity === "HIGH") {
      ipCounts[a.ip] = (ipCounts[a.ip] || 0) + 1;
    }
  });
  const topIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([ip, count]) => ({ ip, count }));

  // Detection method breakdown
  const ruleAlerts = alerts.filter(
    (a) => a.type !== "ML Anomaly Detected",
  ).length;
  const mlAlerts = alerts.filter(
    (a) => a.type === "ML Anomaly Detected",
  ).length;
  const methodData = [
    { name: "Rule-Based", value: ruleAlerts },
    { name: "ML Anomaly", value: mlAlerts },
  ].filter((d) => d.value > 0);

  // Peak hours from timeline
  const peakHours = [...timeline].sort((a, b) => b.total - a.total).slice(0, 5);

  // Alert velocity - alerts per hour
  const velocityData = timeline.filter((t) => t.total > 0);

  // Attack type severity breakdown
  const typeData = [...(stats?.type_counts || [])].sort(
    (a, b) => b.count - a.count,
  );

  // Summary stats
  const uniqueAttackers = Object.keys(ipCounts).length;
  const uniqueTargets = Object.keys(userCounts).length;
  const peakHour = peakHours[0]?.hour ?? "-";
  const mostCommonAttack = typeData[0]?.name || "-";

  return (
    <div className="p-3 sm:p-6 space-y-5 sm:space-y-6">
      <PageHeader routeId="threat-analytics" />

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          {
            icon: Target,
            label: "Unique Attackers",
            value: uniqueAttackers,
            color: "text-red-400",
            bg: "bg-red-500/20",
          },
          {
            icon: User,
            label: "Targeted Accounts",
            value: uniqueTargets,
            color: "text-orange-400",
            bg: "bg-orange-500/20",
          },
          {
            icon: Clock,
            label: "Peak Attack Hour",
            value: peakHour !== "-" ? `${peakHour}:00` : "-",
            color: "text-amber-400",
            bg: "bg-amber-500/20",
          },
          {
            icon: Shield,
            label: "Most Common Attack",
            value: mostCommonAttack.split(" ")[0],
            color: "text-cyan-400",
            bg: "bg-cyan-500/20",
          },
        ].map(({ icon: Icon, label, value, color, bg }) => (
          <CardWrap key={label}>
            <div
              className={`w-7 h-7 rounded-lg ${bg} grid place-items-center mb-2`}
            >
              <Icon className={`w-3.5 h-3.5 ${color}`} />
            </div>
            <p className={`text-xl font-bold ${color} truncate`}>{value}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">{label}</p>
          </CardWrap>
        ))}
      </div>

      {/* Alert velocity + Detection method */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alert velocity */}
        <div className="lg:col-span-2">
          <CardWrap>
            <CardTitle>Alerts by Hour of Day</CardTitle>
            {velocityData.length === 0 ? (
              <p className="text-[11px] text-slate-700 py-8 text-center">
                No alert data yet - run detection first
              </p>
            ) : (
              <ResponsiveContainer width="100%" height={160}>
                <AreaChart
                  data={timeline}
                  margin={{ top: 5, right: 5, bottom: 0, left: -25 }}
                >
                  <defs>
                    <linearGradient id="velGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--chart-total)" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="var(--chart-total)" stopOpacity={0} />
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
                    dataKey="total"
                    name="Alerts"
                    stroke="var(--chart-total)"
                    strokeWidth={2}
                    fill="url(#velGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardWrap>
        </div>

        {/* Detection method */}
        <CardWrap>
          <CardTitle>Detection Method</CardTitle>
          {methodData.length === 0 ? (
            <p className="text-[11px] text-slate-700 py-8 text-center">
              No data yet
            </p>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={120}>
                <PieChart>
                  <Pie
                    data={methodData}
                    cx="50%"
                    cy="50%"
                    innerRadius={30}
                    outerRadius={50}
                    dataKey="value"
                    strokeWidth={0}
                  >
                    <Cell fill="#06b6d4" />
                    <Cell fill="#8b5cf6" />
                  </Pie>
                  <Tooltip {...chartTooltip} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 mt-2">
                {methodData.map((d, i) => (
                  <div
                    key={d.name}
                    className="flex items-center justify-between"
                  >
                    <div className="flex items-center gap-2">
                      <div
                        className={`w-2 h-2 rounded-full ${i === 0 ? "bg-cyan-400" : "bg-purple-400"}`}
                      />
                      <span className="text-[10px] text-slate-400">
                        {d.name}
                      </span>
                    </div>
                    <span className="text-[10px] font-bold text-[color:var(--text-primary)]">
                      {d.value}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </CardWrap>
      </div>

      {/* Top users + Top IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top targeted users */}
        <CardWrap>
          <div className="flex items-center gap-2 mb-3">
            <User className="w-3.5 h-3.5 text-orange-400" />
            <CardTitle>Top Targeted Accounts</CardTitle>
          </div>
          {topUsers.length === 0 ? (
            <p className="text-[11px] text-slate-700">No data yet</p>
          ) : (
            <div className="space-y-2">
              {topUsers.map(({ user, count }, i) => (
                <div key={user} className="flex items-center gap-3">
                  <span className="text-[10px] text-slate-600 w-4 flex-shrink-0">
                    {i + 1}
                  </span>
                  <span className="text-[11px] text-slate-300 flex-1 min-w-0 truncate font-mono">
                    {user}
                  </span>
                  <div className="flex-1 bg-[#1e2a3d] rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full bg-orange-400"
                      style={{ width: `${(count / topUsers[0].count) * 100}%` }}
                    />
                  </div>
                  <span className="text-[10px] font-bold text-[color:var(--text-primary)] w-4 text-right flex-shrink-0">
                    {count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardWrap>

        {/* Top attacker IPs */}
        <CardWrap>
          <div className="flex items-center gap-2 mb-3">
            <Globe className="w-3.5 h-3.5 text-red-400" />
            <CardTitle>Top Attacker IPs</CardTitle>
          </div>
          {topIPs.length === 0 ? (
            <p className="text-[11px] text-slate-700">No data yet</p>
          ) : (
            <div className="space-y-2">
              {topIPs.map(({ ip, count }, i) => (
                <div key={ip} className="flex items-center gap-3">
                  <span className="text-[10px] text-slate-600 w-4 flex-shrink-0">
                    {i + 1}
                  </span>
                  <span className="text-[10px] text-slate-300 flex-1 min-w-0 truncate font-mono">
                    {ip}
                  </span>
                  <div className="flex-1 bg-[#1e2a3d] rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full bg-red-400"
                      style={{ width: `${(count / topIPs[0].count) * 100}%` }}
                    />
                  </div>
                  <span className="text-[10px] font-bold text-[color:var(--text-primary)] w-4 text-right flex-shrink-0">
                    {count}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardWrap>
      </div>

      {/* Alert type breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <CardWrap>
          <CardTitle>Alert Type Distribution</CardTitle>
          {typeData.length === 0 ? (
            <p className="text-[11px] text-slate-700">No data yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart
                data={typeData}
                layout="vertical"
                margin={{ top: 0, right: 20, bottom: 0, left: 10 }}
              >
                <XAxis type="number" tick={axisTick} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={axisTick}
                  width={120}
                />
                <Tooltip {...chartTooltip} cursor={barCursor} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {typeData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </CardWrap>

        {/* Peak attack hours */}
        <CardWrap>
          <div className="flex items-center gap-2 mb-3">
            <Clock className="w-3.5 h-3.5 text-amber-400" />
            <CardTitle>Peak Attack Hours</CardTitle>
          </div>
          {peakHours.length === 0 ? (
            <p className="text-[11px] text-slate-700">No data yet</p>
          ) : (
            <div className="space-y-2.5">
              {peakHours.map(({ hour, total, HIGH, MEDIUM }, i) => (
                <div key={hour} className="flex items-center gap-2 sm:gap-3">
                  <span className="text-[10px] text-slate-600 w-4 flex-shrink-0">
                    {i + 1}
                  </span>
                  <span className="text-[11px] font-mono text-slate-300 w-12 sm:w-14 flex-shrink-0">
                    {hour}:00 – {hour + 1}:00
                  </span>
                  <div className="flex-1 bg-[#1e2a3d] rounded-full h-2 overflow-hidden">
                    <div className="h-full flex">
                      {HIGH > 0 && (
                        <div
                          className="h-full bg-orange-400"
                          style={{ width: `${(HIGH / total) * 100}%` }}
                        />
                      )}
                      {MEDIUM > 0 && (
                        <div
                          className="h-full bg-amber-400"
                          style={{ width: `${(MEDIUM / total) * 100}%` }}
                        />
                      )}
                    </div>
                  </div>
                  <span className="text-[10px] font-bold text-[color:var(--text-primary)] w-4 text-right flex-shrink-0">
                    {total}
                  </span>
                </div>
              ))}
              <div className="flex items-center gap-4 pt-1">
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-sm bg-orange-400" />
                  <span className="text-[9px] text-slate-600">HIGH</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-sm bg-amber-400" />
                  <span className="text-[9px] text-slate-600">MEDIUM</span>
                </div>
              </div>
            </div>
          )}
        </CardWrap>
      </div>

      {/* Intelligence note */}
      <CardWrap>
        <div className="flex items-start gap-3">
          <Cpu className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-[11px] font-semibold text-slate-300 mb-1">
              Intelligence Notes
            </p>
            <p className="text-[10px] text-slate-600 leading-relaxed">
              Analytics are derived from the current session's alerts only. In a
              production environment, threat intelligence would aggregate across
              multiple sessions, correlate with external threat feeds
              (VirusTotal, Shodan, AbuseIPDB), and build longitudinal attack
              profiles over days and weeks. Geographic data shown above is
              derived from login event metadata - full GeoIP resolution would
              require integration with a MaxMind or IP-API data source.
            </p>
          </div>
        </div>
      </CardWrap>
    </div>
  );
}
