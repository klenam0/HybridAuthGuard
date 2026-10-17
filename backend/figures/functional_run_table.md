# Functional run (S6): incidents

Source: `backend/results/phase6_s6.json` (`incidents`, `checks`); saved data only.
Protocol: eval/PROTOCOL.md amendment 9, S6 (functional test, no metrics).

Setup (`setup`): copy of the frozen backend (agents, utils, config, api, main, ml, live_simulator) in a scratch directory; empty data/ with model_v4.pkl and model_metrics.json; email variables blank; one seeded previous day (audit_scratch/phase5c_demo/warmup_yesterday.py, 50 events for 2026-10-13); live_simulator.py --rate 4 --attack-interval 15 for 150 s.

One row per incident (source IP, UTC day), ordered by day and first alert time
(UTC). Detectors, tier and email outcome are the stored values; the action is
the frozen response for that tier (`agents/response_agent.py` `_decide_v3`).
Notes quote the run's `checks` where one applies.

| Incident | Detector | Tier | Action | Note |
|---|---|---|---|---|
| 203.0.113.7, 2026-10-13 (10:00:01-10:00:04) | Brute Force Attack, Credential Stuffing | log | Logged only; email `not_required` | Seeded previous day (warm-up script, 50 events for 2026-10-13). The first day the triage saw: no earlier day had closed, so no cutoff yet and no incident qualifies for a rated tier (agents/triage.py, cutoff "none" before the first day closes) |
| 198.51.100.9, 2026-10-13 (14:20:00) | Slow Brute Force | log | Logged only; email `not_required` | Seeded previous day (warm-up script, 50 events for 2026-10-13). The first day the triage saw: no earlier day had closed, so no cutoff yet and no incident qualifies for a rated tier (agents/triage.py, cutoff "none" before the first day closes) |
| 10.0.0.10, 2026-10-14 (02:17:50) | Suspicious Login Time | log | Logged only; email `not_required` | Suspicious Login Time only, not a floor detector, so log (`checks/off_hours_only_incident_logged`) |
| 47.252.8.222, 2026-10-14 (09:02:19-09:22:19) | Slow Brute Force, Distributed Brute Force | step-up | Simulated step-up (MFA) challenge for logins from the IP, 3600 s, not enforced; email outcome `disabled` | Simulated attack: slow brute force (`checks/simulated_attack_ips_in_step_up`) |
| 71.140.157.92, 2026-10-14 (09:31:47-09:31:56) | Brute Force Attack, Distributed Brute Force | step-up | Simulated step-up (MFA) challenge for logins from the IP, 3600 s, not enforced; email outcome `disabled` | Simulated attack: fast brute force (`checks/simulated_attack_ips_in_step_up`) |
| 87.31.89.167, 2026-10-14 (09:32:47-09:32:55) | Brute Force Attack, Credential Stuffing, Distributed Brute Force | step-up | Simulated step-up (MFA) challenge for logins from the IP, 3600 s, not enforced; email outcome `disabled` | Simulated attack: credential stuffing (`checks/simulated_attack_ips_in_step_up`) |
| 192.168.1.11, 2026-10-14 (09:33:27) | Success After Failures | step-up | Simulated step-up (MFA) challenge for logins from the IP, 3600 s, not enforced; email outcome `disabled` | Ordinary user's IP challenged: Akua, Success After Failures after attacks on the account; the known limitation (`checks/ordinary_user_ips_challenged`) |
| 67.208.48.169, 2026-10-14 (09:33:30) | Success After Failures, Multiple IP Login | step-up | Simulated step-up (MFA) challenge for logins from the IP, 3600 s, not enforced; email outcome `disabled` | Simulated attack: multiple-IP scenario, external half (`checks/simulated_attack_ips_in_step_up`) |

Totals (`checks`): 8 incidents; step-up 5, queue 0, log 3; blocks 0. Emails: 5 step-up incidents, outcome 'disabled' (no SMTP configured).
Pipeline stats written while running: 88 events, 14 alerts, at 2026-10-14 09:33:50, live pipeline still running.
