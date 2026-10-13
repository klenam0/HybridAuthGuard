// Alert IDs are full UUIDs (backend audit fix F38). Lists show the first
// 8 characters; the alert detail view shows the full ID.
export function shortAlertId(id) {
  return id ? String(id).slice(0, 8) : "-";
}
