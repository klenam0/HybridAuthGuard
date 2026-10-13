// frontend/src/components/Navbar.jsx

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bell,
  ChevronRight,
  MoonStar,
  Search,
  Settings,
  SunMedium,
  X,
  CheckCheck,
  Cpu,
  Play,
  LoaderCircle,
} from "lucide-react";
import { searchableIndex } from "../config/appRoutes";
import { getSeverity, getThreatLevel } from "../config/severity";
import { highlightMatch, searchIndex } from "../utils/globalSearch";
import { formatUtcTime, timeAgo } from "../utils/time";
import SeverityBadge from "./SeverityBadge";
import { shortAlertId } from "../utils/alertId";

const PIPELINE = [
  { label: "Monitoring", color: "bg-blue-400" },
  { label: "Detection", color: "bg-cyan-400" },
  { label: "Analysis", color: "bg-slate-400" },
  { label: "Response", color: "bg-green-400" },
];

const CONNECTION_STYLES = {
  online: { label: "Live", dot: "bg-green-400", text: "text-green-400" },
  degraded: { label: "Degraded", dot: "bg-amber-400", text: "text-amber-400" },
  offline: { label: "Offline", dot: "bg-red-400", text: "text-red-400" },
  connecting: {
    label: "Connecting",
    dot: "bg-slate-400",
    text: "text-[color:var(--text-secondary)]",
  },
};

// The Ctrl/Cmd+K handler below accepts either key; label it for the platform.
const IS_APPLE_PLATFORM =
  typeof navigator !== "undefined" &&
  /Mac|iPhone|iPad|iPod/i.test(
    navigator.userAgentData?.platform || navigator.platform || "",
  );
const SEARCH_SHORTCUT = IS_APPLE_PLATFORM ? "⌘K" : "Ctrl K";

function NotificationIcon({ type, severity }) {
  if (type === "enriched") {
    return (
      <div className="w-8 h-8 rounded-lg bg-purple-500/20 grid place-items-center flex-shrink-0">
        <Cpu className="w-4 h-4 text-purple-400" />
      </div>
    );
  }
  const { Icon, badge } = getSeverity(severity);
  return (
    <div
      className={`w-8 h-8 rounded-lg ${badge} grid place-items-center flex-shrink-0`}
    >
      <Icon className="w-4 h-4" />
    </div>
  );
}

export default function Navbar({
  running,
  handleRun,
  threatLevel,
  connection,
  notifications = [],
  unreadCount = 0,
  markAllRead,
  navigateToAlert,
  setPage,
  theme,
  onToggleTheme,
  onNavigate,
  onOpenMobileSidebar,
}) {
  const [time, setTime] = useState("");
  const [showNotifs, setShowNotifs] = useState(false);
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const [recentIds, setRecentIds] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("global-search-recent")) || [];
    } catch {
      return [];
    }
  });

  // Notification filter state: "all" | "ai"
  const [notifFilter, setNotifFilter] = useState("all");

  const notifRef = useRef(null);
  const inputRef = useRef(null);
  const searchRef = useRef(null);

  // Clock
  useEffect(() => {
    const tick = () =>
      setTime(
        new Date().toLocaleTimeString("en-GB", {
          hour12: false,
          timeZone: "UTC",
        }) + " UTC",
      );
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  // Debounce search
  useEffect(() => {
    const timeout = setTimeout(() => setDebouncedQuery(query), 80);
    return () => clearTimeout(timeout);
  }, [query]);

  // Keyboard shortcut for search
  useEffect(() => {
    const focusSearch = (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        inputRef.current?.focus();
        setIsOpen(true);
      }
    };
    window.addEventListener("keydown", focusSearch);
    return () => window.removeEventListener("keydown", focusSearch);
  }, []);

  // Outside click for search
  useEffect(() => {
    const closeOnOutsideClick = (event) => {
      if (!searchRef.current?.contains(event.target)) setIsOpen(false);
    };
    document.addEventListener("mousedown", closeOnOutsideClick);
    return () => document.removeEventListener("mousedown", closeOnOutsideClick);
  }, []);

  // Outside click for notifications
  useEffect(() => {
    const handler = (e) => {
      if (notifRef.current && !notifRef.current.contains(e.target)) {
        setShowNotifs(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const results = useMemo(() => {
    if (debouncedQuery.trim())
      return searchIndex(searchableIndex, debouncedQuery);
    return recentIds
      .map((key) =>
        searchableIndex.find((item) => `${item.routeId}:${item.id}` === key),
      )
      .filter(Boolean)
      .slice(0, 5);
  }, [debouncedQuery, recentIds]);

  const selectResult = useCallback(
    (result) => {
      const key = `${result.routeId}:${result.id}`;
      const nextRecent = [
        key,
        ...recentIds.filter((item) => item !== key),
      ].slice(0, 5);
      setRecentIds(nextRecent);
      try {
        localStorage.setItem(
          "global-search-recent",
          JSON.stringify(nextRecent),
        );
      } catch {}
      onNavigate(
        result.routeId,
        result.type === "section" ? result.id : undefined,
      );
      setQuery("");
      setDebouncedQuery("");
      setIsOpen(false);
      setActiveIndex(-1);
    },
    [onNavigate, recentIds],
  );

  const onSearchKeyDown = (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setIsOpen(true);
      setActiveIndex((index) => Math.min(index + 1, results.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) => Math.max(index - 1, 0));
    } else if (
      event.key === "Enter" &&
      activeIndex >= 0 &&
      results[activeIndex]
    ) {
      event.preventDefault();
      selectResult(results[activeIndex]);
    } else if (event.key === "Escape") {
      setIsOpen(false);
      setActiveIndex(-1);
      inputRef.current?.blur();
    } else if (event.key === "Tab") {
      setIsOpen(false);
    }
  };

  const renderHighlight = (text) => {
    const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
    return highlightMatch(text, query).map((part, index) =>
      terms.some((term) => part.toLowerCase() === term) ? (
        <mark key={index} className="bg-cyan-500/20 text-inherit rounded">
          {part}
        </mark>
      ) : (
        part
      ),
    );
  };

  const connectionStatus = connection?.status || "connecting";
  const threat = getThreatLevel(threatLevel?.level, connectionStatus);
  const ThreatIcon = threat.Icon;
  const conn = CONNECTION_STYLES[connectionStatus] || CONNECTION_STYLES.connecting;
  const connTitle = connection?.lastSuccess
    ? `Backend ${conn.label.toLowerCase()} · last update ${formatUtcTime(connection.lastSuccess)}`
    : `Backend ${conn.label.toLowerCase()} · no data received yet`;
  const offline = connectionStatus === "offline";

  const handleBellClick = () => setShowNotifs((v) => !v);

  const handleNotifClick = (notif) => {
    navigateToAlert(notif.alert_id, notif.id);
    setShowNotifs(false);
  };

  // Filter notifications based on selected filter
  const filteredNotifications =
    notifFilter === "ai"
      ? notifications.filter((n) => n.type === "enriched")
      : notifications;

  return (
    <header className="h-14 bg-[color:var(--bg-card)] border-b border-[color:var(--border)] flex items-center justify-between px-3 sm:px-4 gap-2 sm:gap-4 flex-shrink-0 relative">
      {/* ── Mobile hamburger - only visible on small screens ─────────── */}
      <button
        onClick={onOpenMobileSidebar}
        className="lg:hidden w-8 h-8 grid place-items-center text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)] rounded hover:bg-black/5 transition-colors flex-shrink-0"
        aria-label="Open navigation"
      >
        <svg
          className="w-5 h-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M4 6h16M4 12h16M4 18h16"
          />
        </svg>
      </button>

      {/* Search */}
      <div
        ref={searchRef}
        className="relative hidden md:block flex-1 max-w-xl min-w-[200px]"
      >
        <div className="flex items-center gap-2 bg-[color:var(--bg-elevated)] border border-[color:var(--border)] rounded-lg px-3 py-2">
          <Search className="w-4 h-4 text-[color:var(--text-muted)] flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setIsOpen(true);
              setActiveIndex(-1);
            }}
            onFocus={() => setIsOpen(true)}
            onKeyDown={onSearchKeyDown}
            placeholder="Search pages, tools, settings..."
            className="bg-transparent text-sm text-[color:var(--text-primary)] placeholder-[color:var(--text-muted)] outline-none flex-1 min-w-0"
            role="combobox"
            aria-label="Global search"
            aria-expanded={isOpen}
            aria-controls="global-search-results"
            aria-activedescendant={
              activeIndex >= 0
                ? `global-search-result-${activeIndex}`
                : undefined
            }
            autoComplete="off"
          />
          {query ? (
            <button
              type="button"
              onClick={() => {
                setQuery("");
                setActiveIndex(-1);
                inputRef.current?.focus();
              }}
              className="text-[color:var(--text-muted)] hover:text-[color:var(--text-primary)]"
              aria-label="Clear search"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          ) : (
            <span className="text-xs text-[color:var(--text-muted)] border border-[color:var(--border)] rounded px-1.5 py-0.5">
              {SEARCH_SHORTCUT}
            </span>
          )}
        </div>

        {isOpen && (
          <div
            id="global-search-results"
            role="listbox"
            aria-label="Search results"
            className="absolute z-50 left-0 right-0 mt-1 bg-[color:var(--bg-card)] border border-[color:var(--border)] rounded-lg shadow-xl overflow-hidden"
          >
            <div className="px-3 py-2 text-[10px] uppercase tracking-widest text-[color:var(--text-muted)] border-b border-[color:var(--border)]">
              {query ? "Search results" : "Recent searches"}
            </div>
            {results.length ? (
              results.map((result, index) => {
                const Icon = result.Icon;
                const resultTitle =
                  result.type === "section" ? result.pageTitle : result.title;
                return (
                  <button
                    key={`${result.routeId}:${result.id}`}
                    id={`global-search-result-${index}`}
                    type="button"
                    role="option"
                    aria-selected={activeIndex === index}
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={() => selectResult(result)}
                    onMouseEnter={() => setActiveIndex(index)}
                    className={`w-full px-3 py-2.5 flex gap-3 text-left transition-colors ${
                      activeIndex === index
                        ? "bg-cyan-500/10"
                        : "hover:bg-black/5"
                    }`}
                  >
                    <Icon className="w-4 h-4 mt-0.5 text-cyan-500 flex-shrink-0" />
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm text-[color:var(--text-primary)]">
                        {renderHighlight(resultTitle)}
                      </span>
                      {result.type === "section" && (
                        <span className="block text-xs text-[color:var(--text-secondary)]">
                          {renderHighlight(result.title)}
                        </span>
                      )}
                      <span className="block text-xs text-[color:var(--text-muted)] truncate">
                        {result.description}
                      </span>
                    </span>
                    <span className="text-[10px] text-[color:var(--text-muted)] font-mono self-center flex items-center gap-1">
                      /{result.routeId}
                      {result.type === "section" ? `#${result.id}` : ""}
                      <ChevronRight className="w-3 h-3" />
                    </span>
                  </button>
                );
              })
            ) : (
              <div className="px-4 py-8 text-center text-sm text-[color:var(--text-secondary)]">
                No results found for “{query}”
              </div>
            )}
            <div className="px-3 py-2 border-t border-[color:var(--border)] text-[10px] text-[color:var(--text-muted)]">
              ↑↓ to navigate · Enter to open · Esc to close
            </div>
          </div>
        )}
      </div>

      {/* Right cluster */}
      <div className="flex items-center gap-2 sm:gap-4">
        {/* Pipeline dots */}
        <div className="hidden lg:flex items-center gap-3">
          {PIPELINE.map(({ label, color }) => (
            <div key={label} className="flex items-center gap-1.5">
              <div
                className={`w-1.5 h-1.5 rounded-full ${color} ${running ? "animate-pulse" : ""}`}
              />
              <span className="text-[10px] text-[color:var(--text-muted)]">
                {label}
              </span>
            </div>
          ))}
        </div>

        {/* Backend connection */}
        <div
          className={`flex items-center gap-1.5 ${conn.text}`}
          title={connTitle}
          role="status"
        >
          <span
            className={`w-2 h-2 rounded-full ${conn.dot} ${connectionStatus === "online" && running ? "animate-pulse" : ""}`}
            aria-hidden="true"
          />
          <span className="hidden sm:inline text-xs font-medium">
            {conn.label}
          </span>
        </div>

        {/* Threat badge - only meaningful while the backend is reachable */}
        <div
          className={`sev-badge flex items-center gap-1.5 rounded-md px-2 py-1 ${threat.className}`}
          title={
            threat.key === "UNKNOWN"
              ? "Threat level unknown: backend not reachable"
              : "Highest severity in the current alert set"
          }
        >
          <ThreatIcon className="w-3.5 h-3.5" aria-hidden="true" />
          <span className="hidden sm:inline text-[11px] font-bold tracking-wide">
            THREAT: {threat.key}
          </span>
        </div>

        {/* Timestamp */}
        <span className="text-[10px] text-[color:var(--text-muted)] font-mono hidden sm:inline">
          {time}
        </span>

        {/* Action buttons */}
        <div className="flex items-center gap-1">
          {/* Bell with notification dropdown */}
          <div className="relative" ref={notifRef}>
            <button
              onClick={handleBellClick}
              className="relative w-8 h-8 grid place-items-center text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)] rounded hover:bg-black/5 transition-colors"
            >
              <Bell className="w-3.5 h-3.5" />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[8px] font-bold rounded-full min-w-[14px] h-3.5 flex items-center justify-center px-1 leading-none">
                  {unreadCount > 9 ? "9+" : unreadCount}
                </span>
              )}
            </button>

            {showNotifs && (
              <div className="fixed left-3 right-3 top-16 sm:absolute sm:left-auto sm:right-0 sm:top-full sm:mt-1 sm:w-80 bg-[#0f1629] border border-[#1e2a3d] rounded-xl shadow-2xl z-50 overflow-hidden">
                {/* Header */}
                <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2a3d]">
                  <p className="text-[12px] font-bold text-[color:var(--text-primary)]">
                    Notifications
                  </p>
                  {unreadCount > 0 && (
                    <button
                      onClick={() => markAllRead()}
                      className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      <CheckCheck className="w-3 h-3" />
                      Mark all read
                    </button>
                  )}
                </div>

                {/* Filter tabs */}
                <div className="flex items-center gap-1 px-4 py-2 border-b border-[#1e2a3d]">
                  <button
                    onClick={() => setNotifFilter("all")}
                    className={`px-2.5 py-1 rounded-md text-[10px] font-semibold transition-colors ${
                      notifFilter === "all"
                        ? "bg-slate-700 text-white"
                        : "text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    All
                  </button>
                  <button
                    onClick={() => setNotifFilter("ai")}
                    className={`px-2.5 py-1 rounded-md text-[10px] font-semibold transition-colors ${
                      notifFilter === "ai"
                        ? "bg-purple-500/20 text-purple-400"
                        : "text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    AI Analyses
                  </button>
                </div>

                {/* Notification list */}
                <div className="max-h-80 overflow-y-auto divide-y divide-[#1e2a3d]">
                  {filteredNotifications.length === 0 ? (
                    <div className="px-4 py-8 text-center">
                      <Bell className="w-6 h-6 text-slate-700 mx-auto mb-2" />
                      <p className="text-[11px] text-slate-600">
                        {notifFilter === "ai"
                          ? "No AI analyses yet"
                          : "No notifications yet"}
                      </p>
                      <p className="text-[10px] text-slate-700 mt-1">
                        {notifFilter === "ai"
                          ? "AI‑generated explanations will appear here"
                          : "Alerts and AI analyses will appear here"}
                      </p>
                    </div>
                  ) : (
                    filteredNotifications.map((notif) => (
                      <button
                        key={notif.id}
                        onClick={() => handleNotifClick(notif)}
                        className={`w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-white/[0.03] transition-colors ${
                          !notif.read ? "bg-white/[0.02]" : ""
                        }`}
                      >
                        <NotificationIcon
                          type={notif.type}
                          severity={notif.severity}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <p className="text-[11px] font-semibold text-[color:var(--text-primary)] truncate">
                              {notif.title}
                            </p>
                            {!notif.read && (
                              <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 flex-shrink-0" />
                            )}
                          </div>
                          <p className="text-[10px] text-slate-400 truncate">
                            {notif.message}
                          </p>
                          <p className="text-[9px] text-slate-600 mt-0.5">
                            {timeAgo(notif.timestamp)} · #{shortAlertId(notif.alert_id)}
                          </p>
                        </div>
                        {notif.type === "enriched" && (
                          <span className="text-[8px] bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded px-1.5 py-0.5 flex-shrink-0">
                            AI
                          </span>
                        )}
                        {notif.type === "high_alert" && (
                          <SeverityBadge severity={notif.severity} />
                        )}
                      </button>
                    ))
                  )}
                </div>

                {filteredNotifications.length > 0 && (
                  <div className="px-4 py-2 border-t border-[#1e2a3d]">
                    <button
                      onClick={() => {
                        setPage("alert-log");
                        setShowNotifs(false);
                      }}
                      className="text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      View all alerts in Alert Log →
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Settings button */}
          <button
            onClick={() => setPage("settings")}
            className="w-8 h-8 grid place-items-center text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)] rounded hover:bg-black/5 transition-colors"
          >
            <Settings className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Theme toggle */}
        <button
          type="button"
          onClick={onToggleTheme}
          className="flex items-center gap-1.5 border border-[color:var(--border)] bg-[color:var(--bg-card)] hover:bg-[color:var(--bg-elevated)] text-[color:var(--text-primary)] text-sm font-medium px-3 py-2 rounded-lg transition-colors"
          aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
        >
          {theme === "light" ? (
            <MoonStar className="w-3.5 h-3.5" />
          ) : (
            <SunMedium className="w-3.5 h-3.5" />
          )}
          <span className="hidden sm:inline">
            {theme === "light" ? "Dark" : "Light"}
          </span>
        </button>

        {/* Run button */}
        <button
          onClick={handleRun}
          disabled={running || offline}
          title={offline ? "Backend unreachable" : undefined}
          className="flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-[11px] font-bold px-3 py-1.5 rounded transition-colors"
        >
          {running ? (
            <LoaderCircle className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
          ) : (
            <Play className="w-3.5 h-3.5" aria-hidden="true" />
          )}
          {running ? "Running..." : "Run"}
        </button>
      </div>
    </header>
  );
}
