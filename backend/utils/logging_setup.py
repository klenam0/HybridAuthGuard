# backend/utils/logging_setup.py
"""
Console logging for the entry points (main.py, api.py, live_simulator.py).

Audit F15: emoji status lines crashed the pipeline with UnicodeEncodeError
whenever stdout was a file or pipe in a non-UTF-8 code page (e.g.
`python main.py --live > log.txt` on Windows). Library code now logs
through `logging`, which never raises from a failed write, and the console
streams are switched to errors="replace" so unencodable characters print
as "?" instead of raising.
"""

import logging
import os
import sys

_HANDLER_FLAG = "_hybridauthguard_console"


def configure_logging(level=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    root = logging.getLogger()
    if not any(getattr(h, _HANDLER_FLAG, False) for h in root.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        setattr(handler, _HANDLER_FLAG, True)
        root.addHandler(handler)
    root.setLevel((level or os.environ.get("LOG_LEVEL", "INFO")).upper())
