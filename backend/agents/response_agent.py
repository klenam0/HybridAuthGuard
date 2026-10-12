# backend/agents/response_agent.py

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.email_alerter import EmailAlerter
import config


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

    def __init__(self):
        self.actions_log  = []
        self.email_alerter = EmailAlerter()

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

        print(f"🛡️ Response Action Taken: {action}")
        return action

    def get_actions_log(self):
        return self.actions_log