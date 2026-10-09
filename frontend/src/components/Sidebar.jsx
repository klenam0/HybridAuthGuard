import { useEffect, useRef, useState } from "react";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { appRoutes } from "../config/appRoutes";
import socLogo from "../images/soclogo.png";

const BADGE_STYLES = {
  "live-alerts": "bg-red-500    text-white",
  "alert-log": "bg-purple-500 text-white",
  "email-alerts": "bg-green-600  text-white",
};

const FOOTER_STATUS = {
  online: { label: "Backend connected", dot: "bg-green-400", text: "text-green-400" },
  degraded: { label: "Partial connectivity", dot: "bg-amber-400", text: "text-amber-400" },
  offline: { label: "Backend offline", dot: "bg-red-400", text: "text-red-400" },
  connecting: {
    label: "Connecting…",
    dot: "bg-slate-400",
    text: "text-[color:var(--text-secondary)]",
  },
};

const BADGE_DOT = {
  "live-alerts": "bg-red-500",
  "alert-log": "bg-purple-500",
  "email-alerts": "bg-green-500",
};

function UserAvatar({ collapsed }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        title="soc-admin · Tier 2 Analyst"
        className={`
          flex items-center gap-2 w-full rounded-lg px-2 py-1.5
          hover:bg-white/[0.05] transition-colors
          ${collapsed ? "justify-center" : ""}
        `}
      >
        {/* Avatar circle */}
        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-600 to-slate-700 grid place-items-center text-xs font-bold text-white flex-shrink-0 ring-2 ring-cyan-500/30">
          SA
        </div>

        {/* Name + role - hidden when collapsed */}
        {!collapsed && (
          <div className="overflow-hidden text-left">
            <p className="ui-label text-[color:var(--text-primary)] whitespace-nowrap">
              soc-admin
            </p>
            <p className="ui-caption whitespace-nowrap">Tier 2 Analyst</p>
          </div>
        )}
      </button>

      {/* Popover - appears above the avatar */}
      {open && (
        <div
          className={`
          absolute bottom-full mb-2 z-50
          ${collapsed ? "left-full ml-2 bottom-0 mb-0" : "left-0"}
          w-52 bg-[color:var(--bg-card)] border border-[color:var(--border)]
          rounded-xl shadow-2xl overflow-hidden
        `}
        >
          {/* Header */}
          <div className="px-4 py-3 border-b border-[color:var(--border)] flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-600 to-slate-700 grid place-items-center text-sm font-bold text-white flex-shrink-0 ring-2 ring-cyan-500/30">
              SA
            </div>
            <div>
              <p className="text-[12px] font-semibold text-[color:var(--text-primary)]">
                soc-admin
              </p>
              <p className="text-[10px] text-[color:var(--text-muted)]">
                Tier 2 Analyst
              </p>
            </div>
          </div>

          {/* Status row */}
          <div className="px-4 py-2.5 flex items-center gap-2 border-b border-[color:var(--border)]">
            <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            <span className="text-[11px] text-green-400 font-medium">
              Active - SOC Platform v2.4
            </span>
          </div>

          {/* Actions */}
          <div className="p-1">
            <button
              className="w-full text-left px-3 py-2 rounded-lg text-[11px] text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)] hover:bg-white/[0.05] transition-colors"
              onClick={() => setOpen(false)}
            >
              Profile settings
            </button>
            <button
              className="w-full text-left px-3 py-2 rounded-lg text-[11px] text-red-400 hover:bg-red-500/10 transition-colors"
              onClick={() => setOpen(false)}
            >
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Sidebar({
  page,
  setPage,
  badgeCounts = {},
  unreadHighCount = 0,
  collapsed = false,
  onToggleCollapsed,
  mobileOpen = false,
  onCloseMobile,
  connection,
}) {
  const footerStatus =
    FOOTER_STATUS[connection?.status] || FOOTER_STATUS.connecting;

  // Close mobile sidebar on route change
  useEffect(() => {
    if (mobileOpen && onCloseMobile) onCloseMobile();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page]);

  // Escape key closes mobile sidebar
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape" && mobileOpen && onCloseMobile) onCloseMobile();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [mobileOpen, onCloseMobile]);

  const getBadgeCount = (id) => {
    if (badgeCounts[id] !== undefined) return badgeCounts[id];
    if (id === "live-alerts" && unreadHighCount > 0) return unreadHighCount;
    return 0;
  };

  const handleNavClick = (id) => {
    setPage(id);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      {/* ── Mobile backdrop ──────────────────────────────────────────── */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      {/* ── Sidebar panel ────────────────────────────────────────────── */}
      <aside
        className={`
          fixed lg:relative inset-y-0 left-0 z-40
          flex flex-col flex-shrink-0
          bg-[color:var(--bg-sidebar)] border-r border-[color:var(--border)]
          transition-all duration-300 ease-in-out
          ${collapsed ? "w-[60px]" : "w-60"}
          ${mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
        `}
      >
        {/* ── Header: logo + collapse toggle ───────────────────────── */}
        <div className="border-b border-[color:var(--border)] flex-shrink-0 h-14 flex items-center px-2 gap-2">
          {collapsed ? (
            /* Collapsed - only the toggle icon, centred */
            <button
              onClick={onToggleCollapsed}
              title="Expand sidebar"
              className="w-full flex justify-center items-center py-2 rounded-lg text-[color:var(--text-muted)] hover:text-[color:var(--text-primary)] hover:bg-white/[0.05] transition-colors"
            >
              <PanelLeftOpen className="w-5 h-5" />
            </button>
          ) : (
            /* Expanded - logo + name + collapse button on the right */
            <>
              <div className="flex items-center gap-2.5 flex-1 min-w-0">
                <div className="w-8 h-8 rounded-full bg-cyan-500/10 border border-cyan-500/30 grid place-items-center flex-shrink-0">
                  <img src={socLogo} alt="Logo" className="w-5 h-5" />
                </div>
                <p className="ui-label text-[color:var(--text-primary)] leading-tight whitespace-nowrap overflow-hidden">
                  HybridAuthGuard
                </p>
              </div>

              {/* Collapse button - desktop only */}
              <button
                onClick={onToggleCollapsed}
                title="Collapse sidebar"
                className="hidden lg:grid w-7 h-7 place-items-center rounded-lg text-[color:var(--text-muted)] hover:text-[color:var(--text-primary)] hover:bg-white/[0.05] transition-colors flex-shrink-0"
              >
                <PanelLeftClose className="w-5 h-5" />
              </button>
            </>
          )}
        </div>

        {/* ── Nav ──────────────────────────────────────────────────── */}
        <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto overflow-x-hidden">
          {appRoutes.map(({ id, title, Icon }) => {
            const active = page === id;
            const count = getBadgeCount(id);
            const badgeCls = BADGE_STYLES[id] || "bg-slate-600 text-white";
            const dotCls = BADGE_DOT[id] || "bg-slate-500";

            return (
              <button
                key={id}
                onClick={() => handleNavClick(id)}
                title={collapsed ? title : undefined}
                className={`
                  relative w-full flex items-center gap-2.5
                  ${collapsed ? "justify-center px-2" : "px-3"}
                  py-2 rounded-lg text-left transition-all border
                  ${
                    active
                      ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
                      : "text-[color:var(--text-secondary)] hover:text-[color:var(--text-primary)] hover:bg-white/[0.03] border-transparent"
                  }
                `}
              >
                <Icon className="w-5 h-5 flex-shrink-0" />

                {/* Label */}
                {!collapsed && (
                  <span className="ui-nav-label flex-1 whitespace-nowrap overflow-hidden">
                    {title}
                  </span>
                )}

                {/* Badge */}
                {count > 0 &&
                  (collapsed ? (
                    <span
                      className={`absolute top-1 right-1 w-2 h-2 rounded-full ${dotCls}`}
                    />
                  ) : (
                    <span
                      className={`text-[9px] font-bold rounded-full min-w-[18px] h-4 flex items-center justify-center px-1 leading-none ${badgeCls}`}
                    >
                      {count > 99 ? "99+" : count}
                    </span>
                  ))}
              </button>
            );
          })}
        </nav>

        {/* ── Footer: status + user avatar ─────────────────────────── */}
        <div
          className={`
          border-t border-[color:var(--border)] flex-shrink-0 p-2
          transition-all duration-300
        `}
        >
          {/* Active status - hidden when collapsed */}
          {!collapsed && (
            <div className="flex items-center gap-1.5 px-2 mb-2">
              <div className={`w-1.5 h-1.5 rounded-full ${footerStatus.dot}`} />
              <span className={`ui-caption whitespace-nowrap ${footerStatus.text}`}>
                {footerStatus.label}
              </span>
            </div>
          )}

          {/* User avatar - always visible, collapses to circle */}
          <UserAvatar collapsed={collapsed} />
        </div>
      </aside>
    </>
  );
}
