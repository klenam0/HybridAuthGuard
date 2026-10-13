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
    Executes automated responses based on alert severity.

    Severity mapping:
      HIGH   → Block IP (simulated) + Email notification
      MEDIUM → Admin notification (simulated) 
      LOW    → Log for review

    In production, the simulated actions would interface with
    a firewall API (e.g. iptables, AWS Security Groups, Palo Alto)
    and a ticketing system (e.g. PagerDuty, ServiceNow).
    """

    def __init__(self, email_alerter=None, mode=None):
        # "legacy": block on SIMULATED_BLOCK_SEVERITIES. "v3": block only on
        # alerts from config.V3_BLOCK_DETECTORS, into a TTL block list.
        self.mode = mode or config.RULES_MODE
        self.block_list = BlockList(config.BLOCK_TTL_SECONDS)
        # Bounded: a long live run must not keep every alert in memory (F23).
        self.actions_log  = deque(maxlen=config.ACTIONS_LOG_MAX)
        # Injectable so the evaluation harness can stub email out.
        self.email_alerter = email_alerter if email_alerter is not None else EmailAlerter()
        self.last_response = None

    def decide(self, alert):
        """
        The response policy for an alert, before anything is executed.
        email is "pending" (will be sent), "disabled" (would be sent but
        email is not configured) or "not_required".
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
        severity = alert.get("severity", "LOW")
        ip       = alert.get("ip",       "Unknown IP")
        user     = alert.get("user",     "Unknown User")
        block = alert.get("type") in config.V3_BLOCK_DETECTORS
        if block:
            action = f"Simulated: Block IP {ip} for {config.BLOCK_TTL_SECONDS} s."
        elif severity in config.ADMIN_NOTIFY_SEVERITIES:
            action = f"Simulated: Notify admin about {user} at {ip} (alert only)."
        else:
            action = f"Simulated: Log alert for {ip} (alert only)."
        if severity in config.EMAIL_SEVERITIES:
            email = "pending" if getattr(self.email_alerter, "enabled", True) else "disabled"
        else:
            email = "not_required"
        return {
            "action":            action,
            "simulated_block":   block,
            "admin_notify_simulated": severity in config.ADMIN_NOTIFY_SEVERITIES,
            "email":             email,
        }

    def is_blocked(self, ip, timestamp):
        """True if ip is on the v3 block list at event time timestamp."""
        return self.block_list.is_blocked(ip, epoch_seconds(timestamp))

    def take_action(self, alert):
        """
        Execute the response. Returns the action text; the full outcome,
        with email "sent" or "failed" once attempted, is in last_response.
        """
        response = self.decide(alert)
        action = response["action"]

        if response["email"] == "pending":
            sent = self.email_alerter.send_alert(alert)
            response["email"] = "sent" if sent else "failed"

        if self.mode == "v3" and response["simulated_block"] and alert.get("timestamp"):
            self.block_list.block(alert.get("ip"), epoch_seconds(alert["timestamp"]))

        self.last_response = response
        self.actions_log.append({
            "alert":    alert,
            "action":   action,
            "response": response,
        })

        log.info("🛡️ Response Action Taken: %s", action)
        return action
