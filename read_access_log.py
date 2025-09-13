import re
import json

# Regex mẫu cho access.log
pattern = re.compile(
    r'^(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "([A-Z]+) (.*?) HTTP.*" (\d{3}) \d+'
)

def parse_access_log(filepath):
    results = []
    with open(filepath, "r") as f:
        for line in f:
            match = pattern.match(line)
            if match:
                ip, timestamp, method, url, status = match.groups()
                log_entry = {
                    "source": "access",
                    "ip": ip,
                    "time": timestamp,
                    "method": method,
                    "url": url,
                    "status": int(status),
                    "username": None
                }
                results.append(log_entry)
    return results

if __name__ == "__main__":
    logs = parse_access_log("access.log")
    print(json.dumps(logs, indent=4))
