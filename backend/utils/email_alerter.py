# backend/utils/email_alerter.py

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))


class EmailAlerter:
    """
    Sends email notifications for HIGH severity alerts.

    Uses Gmail SMTP with an app password - never stores
    the user's main account password.

    In a production system this would be replaced with a
    dedicated alerting service (PagerDuty, Splunk On-Call,
    or AWS SNS) but the pattern is identical.
    """

    def __init__(self):
        self.sender   = os.getenv("EMAIL_SENDER")
        self.password = os.getenv("EMAIL_PASSWORD")
        self.receiver = os.getenv("EMAIL_RECEIVER")
        self.enabled  = all([self.sender, self.password, self.receiver])

        if not self.enabled:
            print("⚠ Email alerting disabled - check .env file")

    def send_alert(self, alert):
        """
        Send an HTML email for a HIGH severity alert.
        Fails gracefully - a broken email never crashes the pipeline.
        """
        if not self.enabled:
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 [{alert.get('severity')}] {alert.get('type')} - SOC Alert #{alert.get('alert_id', 'N/A')}"
            msg["From"]    = self.sender
            msg["To"]      = self.receiver

            # Build MITRE section if available
            mitre = alert.get("mitre", {})
            mitre_html = ""
            if mitre:
                mitre_html = f"""
                <div style="background:#0c4a6e20; border:1px solid #38bdf840;
                            border-radius:6px; padding:10px 14px; margin:12px 0;">
                    <span style="color:#38bdf8; font-family:monospace;
                                 font-weight:700;">{mitre.get('technique_id')}</span>
                    &nbsp;|&nbsp;
                    <span style="color:#94a3b8;">{mitre.get('technique_name')}</span>
                    &nbsp;|&nbsp;
                    <span style="color:#64748b;">{mitre.get('tactic')}</span>
                    &nbsp;&nbsp;
                    <a href="{mitre.get('url')}" style="color:#38bdf8;">
                        ↗ View on MITRE ATT&CK
                    </a>
                </div>
                """

            severity_color = {
                "HIGH":   "#ef4444",
                "MEDIUM": "#f97316",
                "LOW":    "#22c55e"
            }.get(alert.get("severity"), "#94a3b8")

            html = f"""
            <html>
            <body style="background:#0f172a; color:#f1f5f9;
                         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
                         padding:24px; margin:0;">

                <!-- Header -->
                <div style="background:#1e293b; border-radius:12px;
                            padding:20px 28px; margin-bottom:20px;
                            border-left:4px solid {severity_color};">
                    <div style="font-size:13px; color:#64748b; margin-bottom:4px;">
                        HYBRIDAUTHGUARD
                    </div>
                    <div style="font-size:22px; font-weight:800; color:{severity_color};">
                        🚨 {alert.get('type')}
                    </div>
                    <div style="font-size:13px; color:#64748b; margin-top:4px;">
                        Alert #{alert.get('alert_id', 'N/A')} &nbsp;·&nbsp;
                        {alert.get('detected_at', 'N/A')}
                    </div>
                </div>

                <!-- Details -->
                <div style="background:#1e293b; border-radius:12px;
                            padding:20px 28px; margin-bottom:16px;">
                    <table style="width:100%; border-collapse:collapse;">
                        <tr>
                            <td style="padding:8px 0; color:#64748b;
                                       font-size:13px; width:140px;">Severity</td>
                            <td style="padding:8px 0;">
                                <span style="background:{severity_color}20;
                                             color:{severity_color};
                                             padding:3px 10px; border-radius:4px;
                                             font-size:12px; font-weight:700;">
                                    {alert.get('severity')}
                                </span>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 0; color:#64748b; font-size:13px;">
                                Source IP
                            </td>
                            <td style="padding:8px 0; font-family:monospace;
                                       color:#f1f5f9; font-size:14px;">
                                {alert.get('ip')}
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 0; color:#64748b; font-size:13px;">
                                Target User
                            </td>
                            <td style="padding:8px 0; font-family:monospace;
                                       color:#f1f5f9; font-size:14px;">
                                {alert.get('user')}
                            </td>
                        </tr>
                        <tr>
                            <td style="padding:8px 0; color:#64748b; font-size:13px;">
                                Description
                            </td>
                            <td style="padding:8px 0; color:#94a3b8; font-size:13px;">
                                {alert.get('description')}
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- MITRE -->
                {mitre_html}

                <!-- Explanation -->
                <div style="background:#1e293b; border-radius:12px;
                            padding:20px 28px; margin-bottom:16px;">
                    <div style="font-size:12px; color:#64748b;
                                margin-bottom:8px; font-weight:600;">
                        ANALYSIS
                    </div>
                    <div style="font-size:14px; color:#94a3b8; line-height:1.6;">
                        {alert.get('explanation')}
                    </div>
                </div>

                <!-- Footer -->
                <div style="font-size:12px; color:#475569; text-align:center;
                            padding-top:16px;">
                    HybridAuthGuard &nbsp;·&nbsp;
                    Hybrid authentication threat detection &nbsp;·&nbsp;
                    This alert was generated automatically
                </div>

            </body>
            </html>
            """

            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.sender, self.password)
                server.sendmail(self.sender, self.receiver, msg.as_string())

            print(f"📧 Alert email sent → {self.receiver} [{alert.get('type')}]")
            return True

        except Exception as e:
            print(f"⚠ Email failed: {e}")
            return False