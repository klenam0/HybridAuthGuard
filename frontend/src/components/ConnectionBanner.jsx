import { AlertTriangle, WifiOff } from "lucide-react";
import { formatUtcTime, timeAgo } from "../utils/time";

// Shown above every page whenever the backend is not fully reachable, so
// zeros and empty lists are never mistaken for "no threats".
export default function ConnectionBanner({ connection, apiBase }) {
  const { status, lastSuccess, endpoints } = connection;
  if (status === "online" || status === "connecting") return null;

  if (status === "degraded") {
    const failing = Object.entries(endpoints)
      .filter(([, e]) => !e.ok)
      .map(([path]) => `/api/${path}`);
    return (
      <div
        role="status"
        className="flex items-start gap-2.5 px-4 sm:px-6 py-2.5 border-b border-amber-500/30 bg-amber-500/15 text-amber-400"
      >
        <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" aria-hidden="true" />
        <p className="ui-body">
          <span className="font-semibold">Partial connectivity.</span>{" "}
          {failing.length} backend endpoint{failing.length === 1 ? "" : "s"}{" "}
          failing ({failing.join(", ")}). Panels fed by them show the last
          data received.
        </p>
      </div>
    );
  }

  return (
    <div
      role="alert"
      className="flex items-start gap-2.5 px-4 sm:px-6 py-2.5 border-b border-red-500/30 bg-red-500/15 text-red-400"
    >
      <WifiOff className="w-4 h-4 mt-0.5 flex-shrink-0" aria-hidden="true" />
      <p className="ui-body">
        <span className="font-semibold">Backend unreachable.</span>{" "}
        {lastSuccess
          ? `Showing data last received at ${formatUtcTime(lastSuccess)} (${timeAgo(new Date(lastSuccess))}). Threat level and counts may be out of date.`
          : `No data has been received from ${apiBase}. Start the backend API; this page retries automatically.`}
      </p>
    </div>
  );
}
