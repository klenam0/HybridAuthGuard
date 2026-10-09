export const API = "http://localhost:5000/api";

// Endpoints App polls on every tick. Each is fetched independently so one
// failing endpoint never blanks the rest of the UI; System Health reports
// the result of each.
export const POLLED_ENDPOINTS = [
  "alerts",
  "stats",
  "status",
  "timeline",
  "model-info",
  "agents",
  "detectors",
  "pipeline-stats",
  "threat-level",
  "enrichment-status",
];
