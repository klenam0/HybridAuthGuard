# backend/utils/event_schema.py
"""
Validation and normalisation for login events entering the live pipeline
(/api/ingest and the live queue consumer). Audit F05, F32, F36.

normalize_event(raw) returns (event, None) on success or (None, error).
The normalised event holds only the known fields:

  timestamp    "%Y-%m-%d %H:%M:%S". Accepts that legacy format or ISO-8601
               (fromisoformat: "T" separator, fractional seconds, "Z" or an
               offset). Timezone-aware values are converted to the server's
               local time, the same clock the server uses when it stamps an
               event that arrives without a timestamp. Fractional seconds are
               dropped.
  user         non-empty string, kept verbatim (no case or whitespace
               folding, which would change detection results).
  ip           parsed with ipaddress and stored in canonical form.
  status       "SUCCESS" or "FAILED" (case-insensitive on input).
  country,     optional strings.
  device_type
"""

import ipaddress
from datetime import datetime

import config

LEGACY_TS_FMT = "%Y-%m-%d %H:%M:%S"
STATUSES = {"SUCCESS", "FAILED"}
REQUIRED = ("user", "ip", "status")
OPTIONAL = ("country", "device_type")


def parse_timestamp(value):
    """Legacy or ISO-8601 string -> legacy-format string, or raise ValueError."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    text = value.strip()
    try:
        return datetime.strptime(text, LEGACY_TS_FMT).strftime(LEGACY_TS_FMT)
    except ValueError:
        pass
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(
            "timestamp must be 'YYYY-MM-DD HH:MM:SS' or ISO-8601") from None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt.strftime(LEGACY_TS_FMT)


def normalize_event(raw, now=None):
    if not isinstance(raw, dict):
        return None, "body must be a JSON object"

    missing = [k for k in REQUIRED if k not in raw]
    if missing:
        return None, f"missing fields: {', '.join(missing)}"

    limits = config.INGEST_MAX_FIELD_CHARS
    event = {}
    for key in REQUIRED + OPTIONAL:
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, str):
            return None, f"{key} must be a string"
        if len(value) > limits[key]:
            return None, f"{key} longer than {limits[key]} characters"
        event[key] = value

    if not event["user"].strip():
        return None, "user must not be empty"

    try:
        event["ip"] = str(ipaddress.ip_address(event["ip"].strip()))
    except ValueError:
        return None, "ip is not a valid IPv4 or IPv6 address"

    status = event["status"].strip().upper()
    if status not in STATUSES:
        return None, "status must be SUCCESS or FAILED"
    event["status"] = status

    if "timestamp" in raw and raw["timestamp"] is not None:
        try:
            event["timestamp"] = parse_timestamp(raw["timestamp"])
        except ValueError as e:
            return None, str(e)
    else:
        event["timestamp"] = (now or datetime.now()).strftime(LEGACY_TS_FMT)

    return event, None
