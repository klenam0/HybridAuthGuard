# backend/agents/response_agent.py

import logging
from collections import deque
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.email_alerter import EmailAlerter
from utils.event_schema import epoch_seconds
import config

log = logging.getLogger(__name__)


class BlockList:
    """
    Simulated block list for the v3 response policy: ip -> expiry, in event
    time (seconds). A new block on a blocked IP extends it. Expired entries
    are swept as blocks are added, so the list stays bounded.
    """

    def __init__(self, ttl):
        self.ttl = ttl
        self.expiry = {}
        self._adds = 0

    def block(self, ip, t):
        until = t + self.ttl
        if until > self.expiry.get(ip, until - 1):
            self.expiry[ip] = until
        self._adds += 1
        if self._adds % 1024 == 0:
            for k in [k for k, v in self.expiry.items() if v <= t]:
                del self.expiry[k]

    def is_blocked(self, ip, t):
        until = self.expiry.get(ip)
        return until is not None and t < until

    def __len__(self):
        return len(self.expiry)


class ResponseAgent:
    """
    Executes the (simulated) response to alerts.

    Legacy mode (config.RULES_MODE "legacy"), by alert severity:
      HIGH   -> block IP (simulated) + email
      MEDIUM -> admin notification (simulated)
      LOW    -> log for review

    v3 mode: the graded policy of eval/PROTOCOL.md amendment 6, per incident
    (source IP, calendar day), from agents/triage.py:
      block    -> TTL block of the IP (BLOCK_TTL_SECONDS of event time)
      step_up  -> simulated MFA challenge for the IP's logins
                  (STEP_UP_TTL_SECONDS); recorded, never enforced
      queue    -> placed in the analyst queue
      log      -> logged only
    One email per incident on entering an EMAIL_TIERS tier (cooldown, hourly
    limit and digest in agents/triage.IncidentNotifier). Nothing here is
    enforced: a production system would call a firewall or IdP API.
    """

    def __init__(self, email_alerter=None, mode=None, email_log_max=1000):
        self.mode = mode or config.RULES_MODE
        self.block_list = BlockList(config.BLOCK_TTL_SECONDS)
        # Bounded: a long live run must not keep every alert in memory (F23).
        self.actions_log  = deque(maxlen=config.ACTIONS_LOG_MAX)
        # Injectable so the evaluation harness can stub email out.
        self.email_alerter = email_alerter if email_alerter is not None else EmailAlerter()
        self.last_response = None
        if self.mode == "v3":
            from agents.triage import IncidentNotifier, IncidentTriage
            self.triage = IncidentTriage()
            self.challenge_list = BlockList(config.STEP_UP_TTL_SECONDS)
            self.notifier = IncidentNotifier(self.email_alerter)
            if email_log_max is not None:
                self.notifier.log = deque(maxlen=email_log_max)
            self.queue = deque(maxlen=config.ACTIONS_LOG_MAX)   # recent queue placements

    # ── v3: per event and per incident ─────────────────────────────────────

    def status(self, event):
        """Block / challenge state of the event's IP before the event."""
        t = epoch_seconds(event["timestamp"])
        ip = event.get("ip")
        return {"blocked": self.block_list.is_blocked(ip, t),
                "challenged": self.challenge_list.is_blocked(ip, t)}

    def observe(self, event):
        """Every non-duplicate event, before its alerts are assessed."""
        t = epoch_seconds(event["timestamp"])
        self.notifier.flush(t)
        self.triage.observe(event, t)

    def assess(self, event, alerts):
        """
        Score the event's incident from its rule alerts, place the tier's
        block or challenge, and notify once per incident. Returns the
        incident (shared by every alert of the event) or None.
        """
        t = epoch_seconds(event["timestamp"])
        incident = self.triage.assess(event, t, [a.get("type") for a in alerts])
        if incident is None:
            return None
        ip, tier = incident["ip"], incident["tier"]
        if tier == "block":
            self.block_list.block(ip, t)
        elif tier == "step_up":
            self.challenge_list.block(ip, t)
        elif tier == "queue" and incident["previous_tier"] != "queue":
            self.queue.append(incident["incident_id"])
        incident["email"] = (self.notifier.notify(incident, t)
                             if self.notifier.wants(incident) else "not_required")
        return incident

    def flush(self):
        """Send a pending email digest now (end of a run)."""
        if self.mode == "v3":
            self.notifier.flush()

    def decide(self, alert):
        """
        The response policy for an alert, before anything is executed.
        email is "pending" (will be sent), "disabled" (would be sent but
        email is not configured) or "not_required"; in v3 it is the
        incident's notification outcome.
        """
        severity = alert.get("severity", "LOW")
        ip       = alert.get("ip",       "Unknown IP")
        user     = alert.get("user",     "Unknown User")

        if self.mode == "v3":
            return self._decide_v3(alert)

        if severity in config.SIMULATED_BLOCK_SEVERITIES:
            # Simulate firewall block
            action = f"Simulated: Block IP {ip} temporarily."
        elif severity in config.ADMIN_NOTIFY_SEVERITIES:
            action = f"Simulated: Notify admin about {user} at {ip}."
        else:
            action = f"Simulated: Log low severity alert for {ip}."

        if severity in config.EMAIL_SEVERITIES:
            email = "pending" if getattr(self.email_alerter, "enabled", True) else "disabled"
        else:
            email = "not_required"

        return {
            "action":            action,
            "simulated_block":   severity in config.SIMULATED_BLOCK_SEVERITIES,
            "admin_notify_simulated": severity in config.ADMIN_NOTIFY_SEVERITIES,
            "email":             email,
        }

    def _decide_v3(self, alert):
        ip = alert.get("ip", "Unknown IP")
        incident = alert.get("incident") or {}
        tier = incident.get("tier", "log")
        action = {
            "block":   f"Simulated: Block IP {ip} for {config.BLOCK_TTL_SECONDS} s (incident tier block).",
            "step_up": (f"Simulated: Step-up challenge (MFA) for logins from {ip} for "
                        f"{config.STEP_UP_TTL_SECONDS} s (not enforced)."),
            "queue":   f"Placed incident {incident.get('incident_id', ip)} in the analyst queue.",
            "log":     f"Logged alert for {ip}.",
        }[tier]
        return {
            "action":            action,
            "tier":              tier,
            "incident_id":       incident.get("incident_id"),
            "simulated_block":   tier == "block",
            "step_up":           tier == "step_up",
            "queue":             tier == "queue",
            "admin_notify_simulated": tier == "queue",
            "email":             incident.get("email", "not_required"),
        }

    def is_blocked(self, ip, timestamp):
        """True if ip is on the v3 block list at event time timestamp."""
        return self.block_list.is_blocked(ip, epoch_seconds(timestamp))

    def take_action(self, alert):
        """
        Execute the response. Returns the action text; the full outcome,
        with email "sent" or "failed" once attempted, is in last_response.
        In v3 the block, challenge and email are per incident (assess()).
        """
        response = self.decide(alert)
        action = response["action"]

        if self.mode != "v3" and response["email"] == "pending":
            sent = self.email_alerter.send_alert(alert)
            response["email"] = "sent" if sent else "failed"

        self.last_response = response
        self.actions_log.append({
            "alert":    alert,
            "action":   action,
            "response": response,
        })

        log.info("🛡️ Response Action Taken: %s", action)
        return action
