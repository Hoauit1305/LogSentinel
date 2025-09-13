#!/usr/bin/env python3
# detect_bruteforce.py
"""
Detect brute-force attempts from unified logs.
Usage:
  python detect_bruteforce.py <input_log_or_json> [--json-input] [--out alerts.jsonl]

- If --json-input is given: input is a JSON array file (output of read_* scripts).
- Otherwise input is a plain mixed log file; script will try to parse using read_mix_logs.read_mixed_log()
  (the unified parser you already have).
"""

import sys
import argparse
import json
from collections import deque, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Any, List

# Try to import user's parser (read_mix_logs.py)
try:
    import read_mix_logs as unified_parser  # your file that contains read_mixed_log / parse functions
except Exception:
    unified_parser = None

# ---- helper parse for time strings ----
def parse_time_str(t: str) -> datetime:
    # accept formats:
    # - "13/Sep/2025:10:15:32 +0700"
    # - "13/Sep/2025:10:15:32" (no tz)
    # - or already ISO-like (fallback)
    from datetime import datetime
    try:
        # try with tz offset
        return datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z")
    except Exception:
        pass
    try:
        return datetime.strptime(t, "%d/%b/%Y:%H:%M:%S")
    except Exception:
        try:
            return datetime.fromisoformat(t)
        except Exception:
            # fallback: now
            return datetime.now()

# ---- detector class ----
class BruteForceDetector:
    def __init__(self,
                 window_seconds_failed: int = 120,
                 threshold_failed: int = 5,
                 cooldown_seconds: int = 600,
                 window_seconds_access: int = 120,
                 threshold_access_failed: int = 5):
        # auth (failed-password)
        self.window_failed = window_seconds_failed
        self.th_failed = threshold_failed
        self.cooldown = cooldown_seconds
        self.failed_windows: Dict[str, deque] = defaultdict(deque)   # ip -> deque[timestamps]
        self.last_alert_time: Dict[str, datetime] = {}

        # access-based (POST login / status)
        self.window_access = window_seconds_access
        self.th_access = threshold_access_failed
        self.access_windows: Dict[str, deque] = defaultdict(deque)

    def _can_alert(self, ip: str, now: datetime) -> bool:
        last = self.last_alert_time.get(ip)
        if not last:
            return True
        return (now - last).total_seconds() >= self.cooldown

    def process_entry(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        entry: unified record with keys:
          - source: "auth" or "access"
          - ip, time (string), action/username, status/method/url, raw
        Returns list of alert dicts (maybe empty).
        """
        alerts = []
        ip = entry.get("ip")
        if not ip:
            return alerts
        t_field = entry.get("time")
        now = parse_time_str(t_field) if isinstance(t_field, str) else (t_field or datetime.now())

        src = entry.get("source")

        # AUTH-based detection
        if src == "auth":
            action = entry.get("action")
            if action in ("failed", "invalid_user"):
                dq = self.failed_windows[ip]
                dq.append(now)
                cutoff = now - timedelta(seconds=self.window_failed)
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if len(dq) >= self.th_failed and self._can_alert(ip, now):
                    alert = {
                        "alert_id": f"ALERT-auth-bruteforce-{ip}-{now.isoformat()}",
                        "type": "ssh_bruteforce",
                        "ip": ip,
                        "count": len(dq),
                        "window_seconds": self.window_failed,
                        "start_time": dq[0].isoformat(),
                        "end_time": dq[-1].isoformat(),
                        "sample_raw": dq and entry.get("raw"),
                        "reason": f"{len(dq)} failed auth attempts in last {self.window_failed}s"
                    }
                    alerts.append(alert)
                    self.last_alert_time[ip] = now

        # ACCESS-based detection (POST to login endpoints or many 401/403)
        if src == "access":
            # treat POST /login-like as suspicious
            method = (entry.get("method") or "").upper()
            url = entry.get("url") or ""
            status = entry.get("status")
            is_login_try = False
            # heuristic: url contains 'login' or '/wp-login.php' or '/admin'
            if method == "POST" and ("login" in url.lower() or "wp-login" in url.lower() or "/admin" in url.lower()):
                is_login_try = True
            # or many 401/403 statuses
            if is_login_try or (status in (401,403)):
                dq2 = self.access_windows[ip]
                dq2.append(now)
                cutoff2 = now - timedelta(seconds=self.window_access)
                while dq2 and dq2[0] < cutoff2:
                    dq2.popleft()
                if len(dq2) >= self.th_access and self._can_alert(ip, now):
                    alert = {
                        "alert_id": f"ALERT-web-bruteforce-{ip}-{now.isoformat()}",
                        "type": "web_bruteforce",
                        "ip": ip,
                        "count": len(dq2),
                        "window_seconds": self.window_access,
                        "start_time": dq2[0].isoformat(),
                        "end_time": dq2[-1].isoformat(),
                        "sample_raw": entry.get("raw"),
                        "reason": f"{len(dq2)} suspicious requests (POST/login or 401/403) in last {self.window_access}s"
                    }
                    alerts.append(alert)
                    self.last_alert_time[ip] = now

        return alerts

# ---- runner ----
def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", help="input log file (mixed raw) or JSON array")
    p.add_argument("--json-input", action="store_true", help="treat input as JSON array file")
    p.add_argument("--out", default="alerts.jsonl", help="output alerts JSONL")
    p.add_argument("--th-failed", type=int, default=5, help="threshold failed auth attempts")
    p.add_argument("--window-failed", type=int, default=120, help="window seconds for failed auth")
    p.add_argument("--cooldown", type=int, default=600, help="cooldown seconds per IP between alerts")
    p.add_argument("--th-access", type=int, default=5, help="threshold access failed/login attempts")
    p.add_argument("--window-access", type=int, default=120, help="window seconds for access-based rule")
    args = p.parse_args()

    detector = BruteForceDetector(window_seconds_failed=args.window_failed,
                                  threshold_failed=args.th_failed,
                                  cooldown_seconds=args.cooldown,
                                  window_seconds_access=args.window_access,
                                  threshold_access_failed=args.th_access)

    # load entries
    entries = []
    if args.json_input:
        with open(args.input, "r", encoding="utf-8") as f:
            entries = json.load(f)
    else:
        # try to use your unified parser if available
        if unified_parser and hasattr(unified_parser, "read_mixed_log"):
            entries = unified_parser.read_mixed_log(args.input)
        else:
            # fallback: try to read JSON lines
            try:
                with open(args.input, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            entries.append(obj)
                        except Exception:
                            # could not parse line; skip
                            continue
            except Exception as e:
                print("Cannot read input file. Provide --json-input or ensure parser module available.", file=sys.stderr)
                sys.exit(1)

    alerts_all = []
    for entry in entries:
        alerts = detector.process_entry(entry)
        for a in alerts:
            alerts_all.append(a)
            print(json.dumps(a, ensure_ascii=False))

    # save alerts
    if alerts_all:
        with open(args.out, "w", encoding="utf-8") as f:
            for a in alerts_all:
                f.write(json.dumps(a, ensure_ascii=False) + "\n")
        print(f"Wrote {len(alerts_all)} alerts to {args.out}")
    else:
        print("No alerts detected with current thresholds.")

if __name__ == "__main__":
    import argparse
    main()
