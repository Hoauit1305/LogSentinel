# unified_log_parser.py

import re
import sys
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

# =========================
# AUTH.LOG PARSER
# =========================

HDR_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>\S+):\s+(?P<msg>.+)$'
)
FAILED_RE = re.compile(
    r'Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
ACCEPTED_RE = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)
INVALID_RE = re.compile(
    r'Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)

MONTHS = {
    'Jan': 1,'Feb': 2,'Mar': 3,'Apr': 4,'May': 5,'Jun': 6,
    'Jul': 7,'Aug': 8,'Sep': 9,'Oct': 10,'Nov': 11,'Dec': 12
}

def _parse_time(month: str, day: str, timestr: str, base_year: Optional[int] = None) -> datetime:
    now = datetime.now()
    year = base_year or now.year
    dt = datetime.strptime(f"{year}-{MONTHS[month]:02d}-{int(day):02d} {timestr}", "%Y-%m-%d %H:%M:%S")
    if base_year is None and dt - now > timedelta(days=2):  # fix rollover
        dt = dt.replace(year=year - 1)
    return dt

def _format_time(dt: datetime, tz_offset: str = "+0700") -> str:
    return f"{dt.day:02d}/{dt.strftime('%b')}/{dt.year}:{dt.strftime('%H:%M:%S')} {tz_offset}"

def parse_auth_line(line: str, tz_offset: str = "+0700", base_year: Optional[int] = None) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    m = HDR_RE.match(line)
    if not m:
        return None

    ts = _parse_time(m.group("month"), m.group("day"), m.group("time"), base_year)
    msg = m.group("msg")

    username, ip, port, action = None, None, None, "other"

    if (mf := FAILED_RE.search(msg)):
        username, ip, port = mf.group("user"), mf.group("ip"), mf.group("port")
        action = "invalid_user" if "invalid user" in msg else "failed"
    elif (ma := ACCEPTED_RE.search(msg)):
        username, ip, port = ma.group("user"), ma.group("ip"), ma.group("port")
        action = "accepted"
    elif (mi := INVALID_RE.search(msg)):
        username, ip, port = mi.group("user"), mi.group("ip"), mi.group("port")
        action = "invalid_user"

    return {
        "source": "auth",
        "ip": ip,
        "time": _format_time(ts, tz_offset),
        "username": username,
        "action": action,
        "method": None,
        "url": None,
        "status": None,
        "port": int(port) if port and port.isdigit() else None,
        "raw": line
    }

def read_auth_log(path: str, tz_offset: str = "+0700", base_year: Optional[int] = None) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            e = parse_auth_line(line, tz_offset=tz_offset, base_year=base_year)
            if e:
                entries.append(e)
    return entries

# =========================
# ACCESS.LOG PARSER
# =========================

ACCESS_RE = re.compile(
    r'^(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "([A-Z]+) (.*?) HTTP.*" (\d{3}) \d+'
)

def parse_access_line(line: str) -> Optional[Dict[str, Any]]:
    match = ACCESS_RE.match(line)
    if not match:
        return None
    ip, timestamp, method, url, status = match.groups()
    return {
        "source": "access",
        "ip": ip,
        "time": timestamp,
        "username": None,
        "action": "request",
        "method": method,
        "url": url,
        "status": int(status),
        "port": None,
        "raw": line.strip()
    }

def read_access_log(path: str) -> List[Dict[str, Any]]:
    results = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            e = parse_access_line(line)
            if e:
                results.append(e)
    return results

# =========================
# MIXED LOG READER
# =========================

def read_mixed_log(path: str, tz_offset: str = "+0700") -> List[Dict[str, Any]]:
    results = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = parse_auth_line(line, tz_offset=tz_offset)
            if not e:
                e = parse_access_line(line)
            if e:
                results.append(e)
    return results

# =========================
# MAIN
# =========================

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python unified_log_parser.py <input_log> <output_json>")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2]

    logs = read_mixed_log(infile, tz_offset="+0700")

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)

    print(f"✅ Đã xuất {len(logs)} entries từ {infile} → {outfile}")
