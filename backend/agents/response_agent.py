# backend/agents/response_agent.py

import logging
from collections import deque
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.email_alerter import EmailAlerter
import config

log = logging.getLogger(__name__)


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

    def __init__(self, email_alerter=None):
        # Bounded: a long live run must not keep every alert in memory (F23).
        self.actions_log  = deque(maxlen=config.ACTIONS_LOG_MAX)
        # Injectable so the evaluation harness can stub email out.
        self.email_alerter = email_alerter if email_alerter is not None else EmailAlerter()

    def take_action(self, alert):
        severity = alert.get("severity", "LOW")
        ip       = alert.get("ip",       "Unknown IP")
        user     = alert.get("user",     "Unknown User")
        alert_type = alert.get("type",   "Unknown")

        if severity in config.SIMULATED_BLOCK_SEVERITIES:
            # Simulate firewall block
            action = f"Simulated: Block IP {ip} temporarily."

        elif severity in config.ADMIN_NOTIFY_SEVERITIES:
            action = f"Simulated: Notify admin about {user} at {ip}."

        else:
            action = f"Simulated: Log low severity alert for {ip}."

        if severity in config.EMAIL_SEVERITIES:
            self.email_alerter.send_alert(alert)

        self.actions_log.append({
            "alert":  alert,
            "action": action
        })

        log.info("🛡️ Response Action Taken: %s", action)
        return action

    def get_actions_log(self):
        return list(self.actions_log)