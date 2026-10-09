// Backend timestamps look like "2026-10-06 20:40:39" (server local time).
export function parseTimestamp(ts) {
  if (!ts) return null;
  const date = new Date(String(ts).replace(" ", "T"));
  return Number.isNaN(date.getTime()) ? null : date;
}

export function timeAgo(ts, now = Date.now()) {
  const date = ts instanceof Date ? ts : parseTimestamp(ts);
  if (!date) return "";
  const diff = (now - date.getTime()) / 1000;
  if (diff < 0) return "just now";
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return typeof ts === "string" ? ts.split(" ")[0] : date.toISOString().split("T")[0];
}

export function formatUtcTime(epochMs) {
  if (!epochMs) return "-";
  return `${new Date(epochMs).toLocaleTimeString("en-GB", {
    hour12: false,
    timeZone: "UTC",
  })} UTC`;
}
