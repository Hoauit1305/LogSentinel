import requests
import time
import json

# URL của API server mà bạn đã tạo (trong app.py)
API_ENDPOINT = "http://127.0.0.1:5000/analyze_log"

# --- Kịch bản 1: Tấn công SSH Brute-force (6 log) ---
# (Vì luật của bạn là 5 log, 6 log sẽ kích hoạt 1 cảnh báo)
ssh_logs = [
    'Nov 16 10:30:01 server sshd[1001]: Failed password for root from 192.0.2.10 port 12345 ssh2',
    'Nov 16 10:30:02 server sshd[1002]: Failed password for root from 192.0.2.10 port 12346 ssh2',
    'Nov 16 10:30:03 server sshd[1003]: Failed password for root from 192.0.2.10 port 12347 ssh2',
    'Nov 16 10:30:04 server sshd[1004]: Failed password for root from 192.0.2.10 port 12348 ssh2',
    'Nov 16 10:30:05 server sshd[1005]: Failed password for root from 192.0.2.10 port 12349 ssh2',
    'Nov 16 10:30:06 server sshd[1006]: Failed password for root from 192.0.2.10 port 12350 ssh2'
]

# --- Kịch bản 2: Tấn công Web Scanning (11 log) ---
# (Vì luật của bạn là 10 log, 11 log sẽ kích hoạt 1 cảnh báo)
web_scan_logs = [
    '198.51.100.5 - - [16/Nov/2025:10:31:01 +0700] "GET /admin HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:01 +0700] "GET /.git/config HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:02 +0700] "GET /wp-admin HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:02 +0700] "GET /phpmyadmin HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:03 +0700] "GET /backup.zip HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:03 +0700] "GET /db/ HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:04 +0700] "GET /old/ HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:04 +0700] "GET /test.php HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:05 +0700] "GET /shell.php HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:05 +0700] "GET /backup/ HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:06 +0700] "GET /logs/ HTTP/1.1" 404 209 "-" "dirb/2.22"'
]

def send_log(log_line):
    """Gửi 1 dòng log đến API server."""
    payload = {'log': log_line}
    try:
        response = requests.post(API_ENDPOINT, json=payload, timeout=5)
        print(f"  -> Đã gửi: {log_line[:60]}... (Server phản hồi: {response.json()})")
    except requests.exceptions.RequestException as e:
        print(f"[LỖI] Không thể kết nối đến {API_ENDPOINT}. Bạn đã chạy 'app.py' chưa?")
        print(e)
        return False
    return True

# --- Chạy mô phỏng ---
print("--- Bắt đầu mô phỏng tấn công (gửi log) ---")

print("\n[KỊCH BẢN 1: SSH Brute-force] (Đang gửi 6 log...)")
for log in ssh_logs:
    if not send_log(log):
        break
    time.sleep(0.5) # Gửi nhanh để kích hoạt luật

print("\n[KỊCH BẢN 2: Web Scanning] (Đang gửi 11 log...)")
for log in web_scan_logs:
    if not send_log(log):
        break
    time.sleep(0.5) # Gửi nhanh

print("\n--- Mô phỏng hoàn tất ---")