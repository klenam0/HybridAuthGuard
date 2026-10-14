import {
  Activity,
  BarChart3,
  Ban,
  Bell,
  FileText,
  Layers,
  LayoutDashboard,
  Mail,
  Settings,
  Shield,
  Target,
  Zap,
} from "lucide-react";

// This registry is the application's route configuration. Add a page or a
// searchable section here once; navigation and global search pick it up
// automatically.
export const appRoutes = [
  {
    id: "dashboard",
    title: "Dashboard",
    Icon: LayoutDashboard,
    description:
      "Current threat posture, recent high-severity alerts and pipeline activity.",
    keywords: ["home", "overview", "metrics", "summary", "monitoring"],
    sections: [
      {
        id: "dashboard-metrics",
        title: "Security Metrics",
        description:
          "Alert totals, severity, blocked IPs, precision, and responses.",
        keywords: ["stats", "kpis", "total alerts"],
      },
      {
        id: "dashboard-pipeline",
        title: "Detection Pipeline",
        description: "Pipeline stage processing, queues, and live pipeline events.",
        keywords: ["agents", "detection engine", "events"],
      },
    ],
  },
  {
    id: "live-alerts",
    title: "Live Alerts",
    Icon: Bell,
    description:
      "Monitor current alerts, severity, MITRE techniques, and automated actions.",
    keywords: ["alerts", "incidents", "notifications", "threats", "real time"],
    sections: [
      {
        id: "live-alerts-feed",
        title: "Alert Feed",
        description: "Real-time alert list with severity filters.",
        keywords: ["high", "medium", "low", "filter"],
      },
      {
        id: "live-alerts-actions",
        title: "Recent Automated Actions",
        description: "Recent responses: challenged or blocked IPs and notifications.",
        keywords: ["response", "block", "email"],
      },
    ],
  },
  {
    id: "incidents",
    title: "Incidents",
    Icon: Layers,
    description:
      "Incidents (source IP, day) with their response tier: step-up challenge (simulated MFA, not enforced), analyst queue or log.",
    keywords: ["incident", "tier", "triage", "step-up", "queue", "mfa"],
    sections: [
      {
        id: "incident-tiers",
        title: "Incident Tiers",
        description: "Incidents per tier and each tier's daily rate.",
        keywords: ["tiers", "rates", "policy"],
      },
      {
        id: "incident-list",
        title: "Incident List",
        description: "Latest incidents with tier, detectors, alerts and email outcome.",
        keywords: ["list", "ip", "day"],
      },
    ],
  },
  {
    id: "detection-engine",
    title: "Detection Engine",
    Icon: Shield,
    description: "The rule detectors of the running engine and, in legacy ML mode only, the Isolation Forest, with their rules and activity.",
    keywords: [
      "detectors",
      "rules",
      "anomaly detection",
      "machine learning",
      "ml",
    ],
  },
  {
    id: "mitre-mapping",
    title: "MITRE Mapping",
    Icon: Target,
    description: "Techniques observed in detected alerts, mapped to MITRE ATT&CK.",
    keywords: ["attack", "techniques", "tactics", "framework", "mitre"],
    sections: [
      {
        id: "mitre-matrix",
        title: "MITRE ATT&CK Matrix",
        description: "Technique and tactic coverage for detected threats.",
        keywords: ["matrix", "coverage", "technique"],
      },
    ],
  },
  {
    id: "threat-analytics",
    title: "Threat Analytics",
    Icon: BarChart3,
    description: "Patterns across the current alert set: timing, targeted accounts and source IPs.",
    keywords: ["analytics", "reports", "trends", "reporting"],
  },
  {
    id: "response-actions",
    title: "Response Actions",
    Icon: Zap,
    description: "Automated responses taken per alert. IP blocking is simulated in this prototype.",
    keywords: [
      "respond",
      "remediation",
      "automation",
      "actions",
      "containment",
    ],
    sections: [
      {
        id: "response-timeline",
        title: "Response Timeline",
        description: "Timeline of detection and automated remediation.",
        keywords: ["history", "events", "activity"],
      },
    ],
  },
  {
    id: "blocked-ips",
    title: "Blocks & Challenges",
    Icon: Ban,
    description:
      "Source IPs with a simulated response: a block, or (v3) a step-up challenge. Nothing is enforced in this prototype.",
    keywords: ["blocked", "ip", "blacklist", "denylist", "firewall", "ban", "step-up", "mfa", "challenge"],
    sections: [
      {
        id: "blocked-ip-list",
        title: "Blocked and Challenged IPs",
        description: "IP addresses, the simulated response, and the alert that caused it.",
        keywords: ["addresses", "blacklist", "rules"],
      },
    ],
  },
  {
    id: "email-alerts",
    title: "Email Alerts",
    Icon: Mail,
    description:
      "Email notifications for HIGH-severity detections, with the recorded delivery outcome.",
    keywords: ["email", "notifications", "messages", "recipients"],
  },
  {
    id: "alert-log",
    title: "Alert Log",
    Icon: FileText,
    description:
      "Search the complete history of detected threats and analyses.",
    keywords: ["logs", "history", "records", "incidents", "audit"],
    sections: [
      {
        id: "alert-log-search",
        title: "Alert Log Search",
        description: "Search, filter, sort, and expand historical alerts.",
        keywords: ["find alert", "filter", "sort", "records"],
      },
    ],
  },
  {
    id: "system-health",
    title: "System Health",
    Icon: Activity,
    description: "Live status of the backend API, ML model, detectors and pipeline.",
    keywords: ["health", "status", "api", "uptime", "diagnostics"],
    sections: [
      {
        id: "system-api-health",
        title: "API Endpoints",
        description: "Health status for backend API endpoints.",
        keywords: ["api", "endpoints", "backend"],
      },
    ],
  },
  {
    id: "settings",
    title: "Settings",
    Icon: Settings,
    description: "Current detection, model and alerting configuration (read-only).",
    keywords: ["preferences", "configuration", "options", "theme"],
  },
];

export const searchableIndex = appRoutes.flatMap((route) => [
  { ...route, routeId: route.id, type: "page" },
  ...(route.sections || []).map((section) => ({
    ...route,
    ...section,
    routeId: route.id,
    pageTitle: route.title,
    type: "section",
  })),
]);
