"""
read_auth_log.py

Đọc file auth.log (Linux SSH) và xuất ra JSON array theo format thống nhất.
"""

import re
import sys
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

# Regex patterns
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
    now = datetime.now()   # dùng local time, không còn utcnow()
    year = base_year or now.year
    dt = datetime.strptime(f"{year}-{MONTHS[month]:02d}-{int(day):02d} {timestr}", "%Y-%m-%d %H:%M:%S")
    # Nếu parse ra tương lai >2 ngày so với bây giờ thì lùi 1 năm (xử lý rollover)
    if base_year is None and dt - now > timedelta(days=2):
        dt = dt.replace(year=year - 1)
    return dt

def _format_time(dt: datetime, tz_offset: str = "+0700") -> str:
    return f"{dt.day:02d}/{dt.strftime('%b')}/{dt.year}:{dt.strftime('%H:%M:%S')} {tz_offset}"

def parse_line(line: str, tz_offset: str = "+0700", base_year: Optional[int] = None) -> Optional[Dict[str, Any]]:
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
        "port": int(port) if port and port.isdigit() else None,
        "raw": line
    }

def read_auth_log(path: str, tz_offset: str = "+0700", base_year: Optional[int] = None) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            e = parse_line(line, tz_offset=tz_offset, base_year=base_year)
            if e:
                entries.append(e)
    return entries

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python read_auth_log.py /path/to/auth.log")
        sys.exit(1)

    logs = read_auth_log(sys.argv[1], tz_offset="+0700")
    print(json.dumps(logs, ensure_ascii=False, indent=2))
