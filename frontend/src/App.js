// frontend/src/App.js

import { useState, useEffect, useCallback, useRef } from "react";
import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";
import Dashboard from "./pages/Dashboard";
import LiveAlerts from "./pages/LiveAlerts";
import ResponseActions from "./pages/ResponseActions";
import MITREMapping from "./pages/MITREMapping";
import BlockedIPs from "./pages/BlockedIPs";
import EmailAlerts from "./pages/EmailAlerts";
import SystemHealth from "./pages/SystemHealth";
import AlertLog from "./pages/AlertLog";
import DetectionEngine from "./pages/DetectionEngine";
import ThreatAnalytics from "./pages/ThreatAnalytics";
import Settings from "./pages/Settings";
import ConnectionBanner from "./components/ConnectionBanner";
import { API, POLLED_ENDPOINTS } from "./config/api";

const POLL_INTERVAL_MS = 2000;
const REQUEST_TIMEOUT_MS = 5000;

async function fetchJson(path) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const started = performance.now();
  try {
    const res = await fetch(`${API}/${path}`, { signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    return { data, ms: Math.round(performance.now() - started) };
  } finally {
    clearTimeout(timer);
  }
}

const PAGES = [
  "dashboard",
  "live-alerts",
  "response-actions",
  "mitre-mapping",
  "blocked-ips",
  "email-alerts",
  "system-health",
  "alert-log",
  "detection-engine",
  "threat-analytics",
  "settings",
];

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [status, setStatus] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [modelInfo, setModelInfo] = useState(null);
  const [agentsData, setAgentsData] = useState([]);
  const [detectors, setDetectors] = useState([]);
  const [pipelineStats, setPipelineStats] = useState(null);
  const [threatLevel, setThreatLevel] = useState({
    level: "NORMAL",
    color: "green",
  });
  const [enrichment, setEnrichment] = useState(null);
  // Detection/severity policy from /api/config (backend/config.py). Fetched
  // until it succeeds once; it only changes when the backend restarts.
  const [backendConfig, setBackendConfig] = useState(null);
  // Admin token for /api/run and clear/restore. Entered at runtime and held
  // in memory only: never in the bundle, never in localStorage (audit F30).
  const [adminToken, setAdminToken] = useState("");
  const [running, setRunning] = useState(false);
  // "connecting" until the first poll completes, then "online" (all
  // endpoints OK), "degraded" (some failing) or "offline" (none reachable).
  const [connection, setConnection] = useState({
    status: "connecting",
    lastSuccess: null,
    lastAttempt: null,
    endpoints: {},
  });
  const pollInFlight = useRef(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [sidebarMobileOpen, setSidebarMobileOpen] = useState(false);

  // Theme feature from the new version
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("soc-theme") || "light";
    } catch {
      return "light";
    }
  });

  // Scroll-to-section feature from the new version
  const [pendingSection, setPendingSection] = useState(null);

  const navigateTo = useCallback((nextPage, sectionId) => {
    setPage(nextPage);
    setPendingSection(() => sectionId || null);
  }, []);

  useEffect(() => {
    if (!pendingSection) return undefined;

    const id = pendingSection;
    const frame = requestAnimationFrame(() => {
      document
        .getElementById(id)
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
      setPendingSection(null);
    });

    return () => cancelAnimationFrame(frame);
  }, [page, pendingSection]);

  useEffect(() => {
    const root = document.documentElement;

    root.classList.toggle("light", theme === "light");
    root.style.colorScheme = theme;

    try {
      localStorage.setItem("soc-theme", theme);
    } catch {}

    return () => {
      root.classList.remove("light");
    };
  }, [theme]);

  // ── Navbar bell notification system - UNCHANGED ─────────────────────────
  const [notifications, setNotifications] = useState([]);
  const [targetAlertId, setTargetAlertId] = useState(null);
  const seenEnrichedIds = useRef(new Set());
  const seenAlertIds = useRef(new Set());

  // ── Sidebar-only per-page read tracking ─────────────────────────────────
  // Structure: { [pageId]: string[] of alert_ids that have been read }
  const [pageReadAlerts, setPageReadAlerts] = useState({});

  const markAlertPageRead = useCallback((pageId, alertId) => {
    if (!pageId || !alertId) return;

    setPageReadAlerts((prev) => {
      const alreadyRead = prev[pageId] || [];

      if (alreadyRead.includes(alertId)) {
        return prev; // already marked, avoid unnecessary re-render
      }

      return {
        ...prev,
        [pageId]: [...alreadyRead, alertId],
      };
    });
  }, []);

  const fetchAll = useCallback(async () => {
    // Skip a tick rather than stacking requests when the backend is slow.
    if (pollInFlight.current) return;
    pollInFlight.current = true;

    try {
      const results = await Promise.allSettled(
        POLLED_ENDPOINTS.map((path) => fetchJson(path)),
      );
      const now = Date.now();
      const endpoints = {};
      const data = {};

      results.forEach((result, i) => {
        const path = POLLED_ENDPOINTS[i];
        if (result.status === "fulfilled") {
          endpoints[path] = { ok: true, ms: result.value.ms, checkedAt: now };
          data[path] = result.value.data;
        } else {
          endpoints[path] = {
            ok: false,
            ms: null,
            checkedAt: now,
            error:
              result.reason?.name === "AbortError"
                ? "Timed out"
                : result.reason?.message || "Request failed",
          };
        }
      });

      // Only replace state for endpoints that answered; the rest keep the
      // last data received.
      if ("alerts" in data)
        setAlerts(Array.isArray(data.alerts) ? [...data.alerts].reverse() : []);
      if ("stats" in data) setStats(data.stats);
      if ("status" in data) {
        setStatus(data.status);
        setRunning(data.status?.running || false);
      }
      if ("timeline" in data) setTimeline(data.timeline);
      if ("model-info" in data) setModelInfo(data["model-info"]);
      if ("agents" in data) setAgentsData(data.agents);
      if ("detectors" in data) setDetectors(data.detectors);
      if ("pipeline-stats" in data) setPipelineStats(data["pipeline-stats"]);
      if ("threat-level" in data) setThreatLevel(data["threat-level"]);
      if ("enrichment-status" in data)
        setEnrichment(data["enrichment-status"]);

      const okCount = Object.keys(data).length;
      if (okCount < POLLED_ENDPOINTS.length) {
        console.error("API error:", endpoints);
      }
      setConnection((prev) => ({
        status:
          okCount === POLLED_ENDPOINTS.length
            ? "online"
            : okCount === 0
              ? "offline"
              : "degraded",
        lastAttempt: now,
        lastSuccess: okCount > 0 ? now : prev.lastSuccess,
        endpoints,
      }));
    } finally {
      pollInFlight.current = false;
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const id = setInterval(fetchAll, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [fetchAll]);

  useEffect(() => {
    if (backendConfig) return undefined;
    let cancelled = false;
    const load = () =>
      fetchJson("config")
        .then(({ data }) => {
          if (!cancelled) setBackendConfig(data);
        })
        .catch(() => {});
    load();
    const id = setInterval(load, POLL_INTERVAL_MS * 5);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [backendConfig]);

  // Create bell notifications for new HIGH and newly enriched alerts.
  // This is the navbar notification system and should remain unchanged.
  useEffect(() => {
    if (!alerts.length) return;
    const newNotifs = [];

    alerts.forEach((alert) => {
      const id = alert.alert_id;
      if (!id) return;

      if (alert.severity === "HIGH" && !seenAlertIds.current.has(id)) {
        seenAlertIds.current.add(id);
        newNotifs.push({
          id: `${id}-alert`,
          alert_id: id,
          type: "high_alert",
          title: alert.type,
          message: `${alert.user} from ${alert.ip}`,
          severity: alert.severity,
          timestamp: alert.detected_at || "",
          read: false,
        });
      }

      if (
        alert.enriched &&
        alert.llm_explanation &&
        !seenEnrichedIds.current.has(id)
      ) {
        seenEnrichedIds.current.add(id);
        newNotifs.push({
          id: `${id}-enriched`,
          alert_id: id,
          type: "enriched",
          title: "AI Analysis Ready",
          message: `${alert.type} · ${alert.ip}`,
          severity: alert.severity,
          timestamp: alert.enriched_at || alert.detected_at || "",
          read: false,
        });
      }
    });

    if (newNotifs.length) {
      setNotifications((prev) => [...newNotifs, ...prev].slice(0, 30));
    }
  }, [alerts]);

  const unreadCount = notifications.filter((n) => !n.read).length;

  // ── Mark all notifications read AND clear AlertLog sidebar badge ────────
  const markAllRead = useCallback(() => {
    // Existing navbar bell behavior: mark all bell notifications read
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));

    // Additionally, mark all enriched AI alerts as read for the AlertLog sidebar
    const enrichedIds = alerts
      .filter((a) => a.enriched && a.llm_explanation && a.alert_id)
      .map((a) => a.alert_id);

    if (enrichedIds.length) {
      setPageReadAlerts((prev) => ({
        ...prev,
        "alert-log": [
          ...new Set([...(prev["alert-log"] || []), ...enrichedIds]),
        ],
      }));
    }
  }, [alerts]);

  const markAsRead = useCallback((notifId) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === notifId ? { ...n, read: true } : n)),
    );
  }, []);

  const navigateToAlert = useCallback(
    (alertId, notifId) => {
      if (notifId) markAsRead(notifId);
      setTargetAlertId(alertId);
      setPage("alert-log");
    },
    [markAsRead],
  );

  const clearTargetAlertId = useCallback(() => {
    setTargetAlertId(null);
  }, []);

  const handleRun = async () => {
    let token = adminToken;
    if (!token) {
      token = (window.prompt("Admin token (ADMIN_TOKEN in backend/.env):") || "").trim();
      if (!token) return;
      setAdminToken(token);
    }
    setRunning(true);
    try {
      // Keeps existing alerts; the API only clears history on {fresh: true}.
      const res = await fetch(`${API}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Admin-Token": token },
        body: JSON.stringify({}),
      });
      if (res.status === 401) {
        setAdminToken("");
        setRunning(false);
        window.alert("The API rejected the admin token.");
        return;
      }
    } catch {}
    setTimeout(fetchAll, 800);
  };

  // ── Sidebar badge counts ────────────────────────────────────────────────
  // These are independent from navbar bell notifications.
  // They only decrease when a page explicitly marks an alert as read.
  const liveAlertsUnread = alerts.filter(
    (a) =>
      a.severity === "HIGH" &&
      !(pageReadAlerts["live-alerts"] || []).includes(a.alert_id),
  ).length;

  const emailAlertsUnread = alerts.filter(
    (a) =>
      a.severity === "HIGH" &&
      !(pageReadAlerts["email-alerts"] || []).includes(a.alert_id),
  ).length;

  const alertLogUnread = alerts.filter(
    (a) =>
      a.enriched &&
      a.llm_explanation &&
      !(pageReadAlerts["alert-log"] || []).includes(a.alert_id),
  ).length;

  const badgeCounts = {
    "live-alerts": liveAlertsUnread,
    "alert-log": alertLogUnread,
    "email-alerts": emailAlertsUnread,
  };

  const d = {
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
    backendConfig,
    adminToken,
    setAdminToken,
    connection,
    running,
    handleRun,
    targetAlertId,
    clearTargetAlertId,
    navigateToAlert,
    markAlertPageRead,
  };

  return (
    <div className="app-shell flex h-screen overflow-hidden bg-[color:var(--bg-page)] text-[color:var(--text-primary)]">
      <Sidebar
        page={page}
        setPage={navigateTo}
        badgeCounts={badgeCounts}
        alerts={alerts}
        collapsed={sidebarCollapsed}
        onToggleCollapsed={() => setSidebarCollapsed((v) => !v)}
        mobileOpen={sidebarMobileOpen}
        onCloseMobile={() => setSidebarMobileOpen(false)}
        connection={connection}
      />
      <div className="flex flex-col flex-1 overflow-hidden min-w-0">
        <Navbar
          running={running}
          handleRun={handleRun}
          threatLevel={threatLevel}
          connection={connection}
          notifications={notifications}
          unreadCount={unreadCount}
          markAllRead={markAllRead}
          navigateToAlert={navigateToAlert}
          setPage={navigateTo}
          onNavigate={navigateTo}
          theme={theme}
          onToggleTheme={() =>
            setTheme((current) => (current === "light" ? "dark" : "light"))
          }
          onOpenMobileSidebar={() => setSidebarMobileOpen(true)}
        />
        <ConnectionBanner connection={connection} apiBase={API} />
        <main className="flex-1 overflow-y-auto">
          {page === "dashboard" && <Dashboard data={d} />}
          {page === "live-alerts" && <LiveAlerts data={d} />}
          {page === "response-actions" && <ResponseActions data={d} />}
          {page === "mitre-mapping" && <MITREMapping data={d} />}
          {page === "blocked-ips" && <BlockedIPs data={d} />}
          {page === "email-alerts" && <EmailAlerts data={d} />}
          {page === "system-health" && <SystemHealth data={d} />}
          {page === "alert-log" && <AlertLog data={d} />}
          {page === "detection-engine" && <DetectionEngine data={d} />}
          {page === "threat-analytics" && <ThreatAnalytics data={d} />}
          {page === "settings" && <Settings data={d} />}
          {!PAGES.includes(page) && (
            <div className="h-full flex flex-col items-center justify-center text-slate-600">
              <p className="text-lg font-semibold mb-1">Coming Soon</p>
              <p className="text-sm">This section is under development</p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
