"""
Figures 1 and 2 (line art): the frozen system's architecture and its
per-event flow. Every box is traced to a file:line at the v3.0.0-frozen tag:
the line is found by a search string in that version of the file (git show),
so a moved line fails loudly instead of being cited wrongly. The one
evaluation-side box (the dataset replay, eval/phase6.py, written after the
freeze) is traced in the working tree and marked so.

Called from make_figures.py, which owns the output format (save()) and
FIGURE_DATA.md.
"""
import subprocess
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

BACKEND = Path(__file__).resolve().parent.parent
FROZEN = "v3.0.0-frozen"
CM = 1 / 2.54
FS = 8                      # every label, pt
LINE = 0.36                 # cm per text line at 8 pt
PAD = 0.16                  # cm, text inset from the box edge
LW = 0.7
DASH = (0, (4, 2))

FIG1_STEM = "fig1_architecture"
FIG2_STEM = "fig2_event_flow"

_cache = {}


def _lines(path, ref):
    key = (path, ref)
    if key not in _cache:
        if ref is None:
            text = (BACKEND / path).read_text(encoding="utf-8")
        else:
            text = subprocess.run(["git", "show", f"{ref}:backend/{path}"], cwd=BACKEND,
                                  capture_output=True, check=True).stdout.decode("utf-8")
        _cache[key] = text.splitlines()
    return _cache[key]


def where(path, pattern, after=None, ref=FROZEN):
    """(file:line, code) of the one line containing pattern (the first one
    after the line containing `after`, if given)."""
    lines = _lines(path, ref)
    start = 0
    if after is not None:
        a = [i for i, s in enumerate(lines) if after in s]
        assert len(a) == 1, (path, after, len(a))
        start = a[0] + 1
    hits = [i for i in range(start, len(lines)) if pattern in lines[i]]
    assert hits and (after is not None or len(hits) == 1), (path, pattern, len(hits))
    i = hits[0]
    tag = "" if ref is None else f" @{ref}"
    return f"{path}:{i + 1}{tag}", lines[i].strip().replace("|", "\\|")


class Canvas:
    """A figure whose data coordinates are centimetres from the bottom left."""

    def __init__(self, w, h):
        self.fig = plt.figure(figsize=(w * CM, h * CM))
        self.ax = self.fig.add_axes([0, 0, 1, 1])
        self.ax.set_xlim(0, w)
        self.ax.set_ylim(0, h)
        self.ax.axis("off")
        self.fits = []

    def box(self, x, top, w, title, body="", dashed=False, align="center", lines=None, h=None):
        """A box whose top edge is at `top`; height from its text (or `lines`
        text lines, or h cm). Returns (x0, y0, x1, y1)."""
        n = 1 + (len(body.split("\n")) if body else 0) if lines is None else lines
        h = n * LINE + 2 * PAD if h is None else h
        y = top - h
        patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.1",
                               fc="white", ec="black", lw=LW, ls=DASH if dashed else "-")
        self.ax.add_patch(patch)
        tx = {"center": x + w / 2, "left": x + PAD}[align]
        t = self.ax.text(tx, top - PAD, title, ha=align, va="top", fontsize=FS,
                         fontweight="bold", linespacing=1.15)
        self.fits.append((t, patch))
        if body:
            b = self.ax.text(tx, top - PAD - LINE, body, ha=align, va="top", fontsize=FS,
                             linespacing=1.15)
            self.fits.append((b, patch))
        return x, y, x + w, top

    def frame(self, x0, y0, x1, y1, title):
        """An unfilled group frame with its title inside the top edge."""
        patch = FancyBboxPatch((x0, y0), x1 - x0, y1 - y0, boxstyle="round,pad=0,rounding_size=0.1",
                               fc="none", ec="black", lw=LW)
        self.ax.add_patch(patch)
        t = self.ax.text(x0 + PAD, y1 - PAD, title, ha="left", va="top", fontsize=FS,
                         fontweight="bold")
        self.fits.append((t, patch))

    def arrow(self, p0, p1, dashed=False):
        self.ax.annotate("", xy=p1, xytext=p0,
                         arrowprops=dict(arrowstyle="-|>", color="black", lw=LW,
                                         ls=DASH if dashed else "-", shrinkA=0, shrinkB=0,
                                         mutation_scale=7))

    def line(self, pts):
        xs, ys = zip(*pts)
        self.ax.plot(xs, ys, color="black", lw=LW, solid_capstyle="butt")

    def label(self, x, y, s, ha="left", va="center"):
        self.ax.text(x, y, s, ha=ha, va=va, fontsize=FS)

    def check(self):
        """Every text lies inside its box (the 900 dpi render is the same
        geometry), and nothing is below 8 pt."""
        self.fig.canvas.draw()
        r = self.fig.canvas.get_renderer()
        for t, patch in self.fits:
            tb, pb = t.get_window_extent(r), patch.get_window_extent(r)
            assert (tb.x0 >= pb.x0 and tb.x1 <= pb.x1 and tb.y0 >= pb.y0 and tb.y1 <= pb.y1), \
                (t.get_text()[:40], tb, pb)
        assert all(t.get_fontsize() >= 8 for t in self.ax.texts)


def _section(L, title, notes, boxes):
    L.sections.append({"title": title, "notes": notes, "rows": [],
                       "boxes": [(label, *where(*src[:2], **src[2])) if len(src) == 3
                                 else (label, *where(*src)) for label, src in boxes]})


# ── Figure 1: architecture ──────────────────────────────────────────────────

def figure1(L, save):
    MA, RA, TR, CF = ("agents/monitoring_agent.py", "agents/response_agent.py",
                      "agents/triage.py", "config.py")
    _section(L, "Figure 1: architecture of the frozen system (v3.0.0-frozen)", [
        "Line art; boxes and arrows only, no data. Each box is traced below to the",
        "line(s) of code it depicts, at the `v3.0.0-frozen` tag (`@v3.0.0-frozen`;",
        "`agents/`, `config.py` and the other system files in the working tree are",
        "identical to the tag). The dataset replay of the evaluation",
        "(`eval/phase6.py`) is not part of the frozen system and is traced in the",
        "working tree. Not drawn: the analysis step between tier and store (severity",
        "from the tier, MITRE mapping, template explanation), and the ML step,",
        "which is retired (`ML_V4_IFOREST = \"retired\"`: no ML alerts). The LLM",
        "layer reads saved alerts and writes only their explanation text back to the",
        "store; nothing in the detection or response path reads that text.",
    ], [
        ("Event source: replay (log file, batch mode)", (MA, "def stream_logs(self, delay=1):")),
        ("Event source: replay (log file, batch mode)", ("main.py", "agent.stream_logs(delay=delay)")),
        ("Event source: replay (evaluation, dataset)", ("eval/phase6.py", "mon._process_event(e)",
                                                        {"ref": None})),
        ("Event source: live ingest (HTTP)", ("api.py", '@app.route("/api/ingest", methods=["POST"])')),
        ("Event source: live ingest (queue file)", ("api.py", "f.write(json.dumps(event) + \"\\n\")")),
        ("Event source: live loop reads the queue", (MA, "def stream_live(self, poll_interval=1.0):")),
        ("Event source: per event", (MA, "self._process_event(event)", {"after": "def _handle_queue_line"})),
        ("Rule detectors (8)", ("agents/rules_v3.py",
                                "RULE_DETECTORS = (BF, SLOW, CS, INVALID, DIST, SAF, MULTI, OFF_HOURS)")),
        ("Rule detectors (8): called per event", (MA, "det = self.detector.analyze(event)")),
        ("Rule detectors (8): v3 engine", (CF, 'RULES_MODE = os.environ.get("RULES_MODE", "v3")')),
        ("Incidents (IP, day): only rule detectors form incidents", (TR, "j = _BIT.get(a)")),
        ("Incidents (IP, day): UTC calendar day", (TR, "day = t // 86400")),
        ("Incidents (IP, day): id", (TR, 'return {"incident_id": f"{ip}|{self.day}"')),
        ("Triage T2: setting", (CF, 'TRIAGE_SCORE = "T2"')),
        ("Triage T2: score", (TR, 'return (top, n_det) if name == "T0" else (top, d.asn_max)')),
        ("Triage T2: detector precision", (TR, "top = max(p for j, p in enumerate(self.prec)")),
        ("Response tiers: rates", (CF, 'RESPONSE_TIER_RATES = {"block": 0, "step_up": 200, "queue": 500}')),
        ("Response tiers: order", (TR, 'TIERS = ("block", "step_up", "queue", "log")')),
        ("Block: inactive (k = 0 admits nothing)", (TR, "if k and self.admitted[tier] < k")),
        ("Block: action (never reached)", (RA, "self.block_list.block(ip, t)", {"after": "def assess"})),
        ("Block: TTL", (CF, "BLOCK_TTL_SECONDS = 3600")),
        ("Step-up: action", (RA, "self.challenge_list.block(ip, t)")),
        ("Step-up: TTL", (CF, "STEP_UP_TTL_SECONDS = 3600")),
        ("Step-up: simulated, not enforced", (RA, "(STEP_UP_TTL_SECONDS); recorded, never enforced")),
        ("Queue: action", (RA, 'self.queue.append(incident["incident_id"])')),
        ("Log: every incident in no rated tier", (TR, 'inc.tier = next((x for x in RATED_TIERS if x in inc.regions), "log")')),
        ("Alert store: save", (MA, "self.alert_manager.save_alert(analyzed)", {"after": "def _process_event_v3"})),
        ("Alert store: SQLite in v3", ("utils/alert_manager.py", "return SqliteAlertStore(path)")),
        ("Notifications: email tiers", (CF, 'EMAIL_TIERS = ("block", "step_up")')),
        ("Notifications: once per incident on entry", (TR, 'and incident["previous_tier"] not in self.tiers)')),
        ("Notifications: per-IP cooldown", (CF, "EMAIL_IP_COOLDOWN_SECONDS = int(")),
        ("Notifications: hourly limit", (CF, "EMAIL_MAX_PER_HOUR = int(")),
        ("Notifications: hourly digest", (TR, "self.digest.append(incident)")),
        ("Notifications: called", (RA, 'incident["email"] = (self.notifier.notify(incident, t)')),
        ("LLM explanation layer: started by the API on the store", ("api.py", "_llm_analyzer = LLMAnalyzer(alerts_path=ALERTS_PATH, store=_alert_store())")),
        ("LLM explanation layer: reads saved alerts", ("utils/llm_analyzer.py", "for alert in self.store.load_cached():")),
        ("LLM explanation layer: writes explanation text only", ("utils/llm_analyzer.py", "self.store.update_explanation(alert_id, explanation)")),
    ])

    W, H = 16.0, 14.7
    c = Canvas(W, H)
    X0, X1, GAP = 0.15, 11.25, 0.5
    w = X1 - X0
    cx = (X0 + X1) / 2
    top = H - 0.05
    b = c.box(X0, top, w, "Event source",
              "Replay: a log file (batch mode) or the evaluation replay of a dataset\n"
              "Live ingest: POST /api/ingest \u2192 queue file \u2192 live loop")
    c.arrow((cx, b[1]), (cx, b[1] - GAP))
    b = c.box(X0, b[1] - GAP, w, "Rule detectors (8)",
              "Brute Force Attack, Slow Brute Force, Credential Stuffing,\n"
              "Invalid Account Spraying, Distributed Brute Force,\n"
              "Success After Failures, Multiple IP Login, Suspicious Login Time")
    c.arrow((cx, b[1]), (cx, b[1] - GAP))
    b = c.box(X0, b[1] - GAP, w, "Incidents",
              "one per (source IP, UTC calendar day), formed by the rule alerts")
    c.arrow((cx, b[1]), (cx, b[1] - GAP))
    b = c.box(X0, b[1] - GAP, w, "Triage T2: running score per incident, compared in order",
              "(1) highest val_a alert precision among the incident's detectors\n"
              "(2) highest ASN prior failure ratio of the IP that day")
    c.arrow((cx, b[1]), (cx, b[1] - GAP))

    # Tier frame with four tier boxes.
    ftop = b[1] - GAP
    title_h = LINE + PAD
    inner_top = ftop - title_h - 0.12
    gap_in = 0.2
    tw = (w - 2 * gap_in - 3 * gap_in) / 4
    tiers = [("Block", "inactive (k = 0)\nTTL block, 3600 s", True),
             ("Step-up", "200 incidents/day\nsimulated MFA\nchallenge, 3600 s\nnot enforced", False),
             ("Queue", "500 incidents/day\nanalyst queue", False),
             ("Log", "all other incidents\nlogged only", False)]
    bottoms, centres = [], []
    for i, (t, body, dashed) in enumerate(tiers):
        x = X0 + gap_in + i * (tw + gap_in)
        bb = c.box(x, inner_top, tw, t, body, dashed=dashed, lines=5)
        bottoms.append(bb[1])
        centres.append((bb[0] + bb[2]) / 2)
    fbot = min(bottoms) - gap_in
    c.frame(X0, fbot, X1, ftop,
            "Response tiers: at most k incidents a day each; cutoff from the previous day")

    # Store and notifications under the frame; LLM to the right of the store.
    rtop = fbot - GAP
    nw = (w - 0.5) / 2
    nb = c.box(X0, rtop, nw, "Notifications",
               "one email per incident on entering\nblock or step-up; per-IP cooldown,\n"
               "hourly limit, hourly digest")
    sb = c.box(X0 + nw + 0.5, rtop, nw, "Alert store (SQLite)",
               "every alert, with its incident,\ntier, severity and action", lines=4)
    c.arrow(((nb[0] + nb[2]) / 2, fbot), ((nb[0] + nb[2]) / 2, rtop))
    c.arrow(((sb[0] + sb[2]) / 2, fbot), ((sb[0] + sb[2]) / 2, rtop))
    lx = X1 + 0.5
    lb = c.box(lx, rtop, W - 0.05 - lx, "LLM explanation",
               "display only: reads saved\nalerts, adds explanation\ntext; not in the\n"
               "decision path", dashed=True)
    ym = (sb[1] + sb[3]) / 2
    c.arrow((sb[2], ym), (lb[0], ym), dashed=True)
    c.check()
    save(c.fig, FIG1_STEM, L.sections[-1]["notes"])


# ── Figure 2: per-event flow ────────────────────────────────────────────────

def figure2(L, save):
    MA, RA, TR, CF, RV = ("agents/monitoring_agent.py", "agents/response_agent.py",
                          "agents/triage.py", "config.py", "agents/rules_v3.py")
    _section(L, "Figure 2: per-event flow in the frozen system (v3.0.0-frozen)", [
        "Line art; boxes and arrows only, no data. The flow is",
        "`MonitoringAgent._process_event_v3`; each box is traced below to the",
        "line(s) of code it depicts, at the `v3.0.0-frozen` tag. \"Previous day\" is",
        "the most recent earlier day that had incidents; before the first day",
        "closes no incident qualifies, and if that day had fewer than k incidents",
        "every incident qualifies. The floor check uses every detector the incident",
        "has had so far that day, so once it passes it stays passed.",
    ], [
        ("Login event", (MA, "def _process_event_v3(self, event):")),
        ("Login event: state before the event", (MA, "state = self.responder.status(event)")),
        ("Login event: repeated delivery skipped", (MA, "if det.duplicate:")),
        ("Rule detectors (8)", (RV, "def analyze(self, log_event):")),
        ("Rule detectors (8): cooldown per detector and key", (RV, "if not self.cooldowns.fire((name, key), t, cooldown):")),
        ("No alert: daily counts updated (every event)", (MA, "self.responder.observe(event)")),
        ("No alert: daily counts updated (every event)", (TR, "def observe(self, event, t):")),
        ("No alert: end", (MA, "if not det.alerts:")),
        ("Alert(s)", (RV, "det.alerts.append(alert)")),
        ("Incident update: called", (MA, "incident = self.responder.assess(event, det.alerts)")),
        ("Incident update: detectors and alert count", (TR, "inc.mask |= bits")),
        ("Incident update: detectors and alert count", (TR, "inc.alerts += n")),
        ("Running T2 score", (TR, "inc.score = self.score(inc, d)")),
        ("Running T2 score: (1) detector precision", (TR, "top = max(p for j, p in enumerate(self.prec)")),
        ("Running T2 score: (2) ASN ratio, max over the IP's day", (TR, "if ratio > d.asn_max:")),
        ("Running T2 score: values", (CF, "TRIAGE_DETECTOR_PRECISION = {")),
        ("Floor check", (TR, "floor_ok = not self.floor or inc.mask & self.floor")),
        ("Floor check: the five detectors", (CF, "RESPONSE_FLOOR_DETECTORS = (")),
        ("Floor not met: log, no slot used", (TR, "for tier in (RATED_TIERS if floor_ok else ()):")),
        ("Admission: top down, highest tier kept", (TR, "if tier in inc.regions:")),
        ("Admission: score >= cutoff and fewer than k today", (TR, "if k and self.admitted[tier] < k and self._qualifies(inc.score, tier):")),
        ("Admission: cutoff test", (TR, "return c == ALL or (c != NONE and score >= c)")),
        ("Admission: cutoff from the previous day", (TR, "self.cutoffs[tier] = finals[k - 1] if len(finals) >= k else ALL")),
        ("Admission: rates", (CF, 'RESPONSE_TIER_RATES = {"block": 0, "step_up": 200, "queue": 500}')),
        ("Tier", (TR, 'inc.tier = next((x for x in RATED_TIERS if x in inc.regions), "log")')),
        ("Action: block (never reached, k = 0)", (RA, "self.block_list.block(ip, t)", {"after": "def assess"})),
        ("Action: step-up challenge", (RA, "self.challenge_list.block(ip, t)")),
        ("Action: queue", (RA, 'self.queue.append(incident["incident_id"])')),
        ("Action: email on entering block or step-up", (RA, 'incident["email"] = (self.notifier.notify(incident, t)')),
        ("Action: severity from the tier", ("agents/analysis_agent.py", "severity = self.severity_mapping.get(tier, config.DEFAULT_SEVERITY)")),
        ("Action: every alert saved", (MA, "self.alert_manager.save_alert(analyzed)", {"after": "def _process_event_v3"})),
    ])


    W, H = 16.0, 18.4
    c = Canvas(W, H)
    X0, X1, GAP = 0.15, 9.6, 0.5
    w = X1 - X0
    cx = (X0 + X1) / 2
    SX0, SX1 = 11.0, W - 0.05
    top = H - 0.05

    b = c.box(X0, top, w, "Login event",
              "time, user, IP, status, ASN; a repeated delivery is skipped")
    c.arrow((cx, b[1]), (cx, b[1] - GAP))
    det = c.box(X0, b[1] - GAP, w, "Rule detectors (8)",
                "windowed per-IP and per-account counts; an alert is\n"
                "raised when a detector fires outside its cooldown")
    # no alert -> side exit
    ym = (det[1] + det[3]) / 2
    c.box(SX0, det[3], SX1 - SX0, "No alert",
          "the IP's daily counts and ASN\nratio are updated; end", h=det[3] - det[1])
    c.arrow((X1, ym), (SX0, ym))
    c.label((X1 + SX0) / 2, ym + 0.08, "no alert", ha="center", va="bottom")
    c.arrow((cx, det[1]), (cx, det[1] - GAP))
    c.label(cx + 0.12, det[1] - GAP / 2, "alert", va="center")
    b = c.box(X0, det[1] - GAP, w, "Alert(s)", "one or more rule alerts for the event")
    c.arrow((cx, b[1]), (cx, b[1] - GAP))
    b = c.box(X0, b[1] - GAP, w, "Incident update",
              "incident (IP, UTC day) opened or updated:\ndetectors seen, alert count")
    c.arrow((cx, b[1]), (cx, b[1] - GAP))
    b = c.box(X0, b[1] - GAP, w, "Running T2 score",
              "(1) highest val_a alert precision among the incident's detectors\n"
              "(2) highest ASN prior failure ratio of the IP that day")
    c.arrow((cx, b[1]), (cx, b[1] - GAP))
    fl = c.box(X0, b[1] - GAP, w, "Floor check",
               "has the incident had an alert from a floor detector?\n"
               "Slow Brute Force, Credential Stuffing, Invalid Account\n"
               "Spraying, Distributed Brute Force, Success After Failures")
    c.arrow((cx, fl[1]), (cx, fl[1] - GAP))
    c.label(cx + 0.12, fl[1] - GAP / 2, "yes", va="center")
    ad = c.box(X0, fl[1] - GAP, w, "Admission (block, step-up, queue in turn, top down)",
               "enter a tier if the score ≥ its cutoff (the k-th highest\n"
               "final score of the previous day with incidents) and fewer\n"
               "than k incidents entered it today. block k = 0 (off),\n"
               "step-up k = 200, queue k = 500. The highest tier entered\n"
               "is kept; a slot once used is not returned.")
    # Log box spanning the floor and admission rows: two straight arrows in.
    y_fl = (fl[1] + fl[3]) / 2
    y_ad = (ad[1] + ad[3]) / 2
    lg = c.box(SX0, y_fl + 0.6, SX1 - SX0, "Log tier", "logged only;\nno daily slot used",
               h=(y_fl + 0.6) - (y_ad - 0.6))
    for y, lab in ((y_fl, "no"), (y_ad, "none")):
        c.arrow((X1, y), (SX0, y))
        c.label((X1 + SX0) / 2, y + 0.08, lab, ha="center", va="bottom")
    c.arrow((cx, ad[1]), (cx, ad[1] - GAP))
    c.label(cx + 0.12, ad[1] - GAP / 2, "tier entered or kept", va="center")
    ta = c.box(X0, ad[1] - GAP, w, "Tier and action",
               "step-up: simulated MFA challenge for the IP, 3600 s,\n"
               "not enforced; email on entry. queue: analyst queue.\n"
               "log: logged only. block (off): 3600 s block.\n"
               "Then every alert of the event is analysed (severity\n"
               "from the tier) and saved to the alert store.")
    xl = (lg[0] + lg[2]) / 2
    yt = (ta[1] + ta[3]) / 2
    c.line([(xl, lg[1]), (xl, yt)])
    c.arrow((xl, yt), (X1, yt))
    c.check()
    save(c.fig, FIG2_STEM, L.sections[-1]["notes"])
