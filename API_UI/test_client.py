import requests
import time
import random
import sys

# URL của API server
API_ENDPOINT = "http://127.0.0.1:5000/analyze_log"

# --- [KHO LOG MẪU] ---

# 1. Log Lành tính (Hệ thống không nên báo động)
BENIGN_LOGS = [
    'Nov 16 11:01:01 server sshd[1007]: Accepted password for user_normal from 192.168.1.10 port 5678 ssh2',
    '192.168.1.11 - - [16/Nov/2025:11:01:05 +0700] "GET /index.html HTTP/1.1" 200 1234 "http://google.com" "Mozilla/5.0"',
    'Nov 16 11:01:10 server CRON[1010]: (root) CMD (run-parts /etc/cron.hourly)',
    '192.168.1.12 - - [16/Nov/2025:11:01:15 +0700] "GET /old-page HTTP/1.1" 301 567 "-" "Mozilla/5.0"',
    'Nov 16 11:02:00 server systemd: Starting daily apt upgrade service...',
    '192.168.1.11 - - [16/Nov/2025:11:02:05 +0700] "GET /styles.css HTTP/1.1" 200 500 "http://127.0.0.1/index.html" "Mozilla/5.0"',
]

# 2. Log Tấn công SSH (Chỉ 1 IP)
SSH_BRUTEFORCE_LOGS = [
    'Nov 16 10:30:01 server sshd[1001]: Failed password for root from 192.0.2.10 port 12345 ssh2',
    'Nov 16 10:30:02 server sshd[1002]: Failed password for invalid user admin from 192.0.2.10 port 12346 ssh2',
    'Nov 16 10:30:03 server sshd[1003]: Failed password for root from 192.0.2.10 port 12347 ssh2',
    'Nov 16 10:30:04 server sshd[1004]: Failed password for invalid user test from 192.0.2.10 port 12348 ssh2',
]

# 3. Log Tấn công Web Scan (Chỉ 1 IP)
WEB_SCAN_LOGS = [
    '198.51.100.5 - - [16/Nov/2025:10:31:01 +0700] "GET /admin HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:01 +0700] "GET /.git/config HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:02 +0700] "GET /wp-admin HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:02 +0700] "GET /phpmyadmin HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:03 +0700] "GET /backup.zip HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:03 +0700] "GET /db/ HTTP/1.1" 404 209 "-" "dirb/2.22"',
    '198.51.100.5 - - [16/Nov/2025:10:31:04 +0700] "GET /old/ HTTP/1.1" 404 209 "-" "dirb/2.22"',
]

# 4. Log Tấn công ML (SQLi, XSS, Unknown...)
ML_ATTACK_LOGS = [
    # SQLi (Apache)
    '203.0.113.10 - - [16/Nov/2025:10:32:01 +0700] "GET /index.php?id=1\' OR 1=1 HTTP/1.1" 200 1234 "-" "SQLMap"',
    # XSS (Apache)
    '10.0.0.1 - - [16/Nov/2025:10:33:01 +0700] "GET /search.php?query=<script>alert(1)</script> HTTP/1.1" 200 1500 "-" "Mozilla/5.0"',
    # Directory Traversal (Apache)
    '10.0.0.2 - - [16/Nov/2025:10:33:02 +0700] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    # Log 'Unknown' (Apache Error log mà parser không biết)
    '[Sat Nov 16 10:32:03 2025] [error] [client 203.0.113.12] (1064) You have an error in your SQL syntax; check the manual... near \'\' OR 1=1\'\' at line 1',
    # Log 'Unknown' (Nginx)
    '203.0.113.11 - [16/Nov/2025:10:32:02 +0700] "GET /users.php?id=1 UNION SELECT 1,2,3,user,pass FROM users HTTP/1.1" 200 404 "-" "SQLMap"',
]


def send_log(log_line):
    """Gửi 1 dòng log đến API server và chỉ in ra nếu có cảnh báo."""
    payload = {'log': log_line}
    try:
        response = requests.post(API_ENDPOINT, json=payload, timeout=2)
        response_data = response.json()
        status = response_data.get('status', 'error')
        
        # Chỉ in ra nếu có gì đó đáng chú ý để tránh làm ngập console
        if "alert" in status or "stateful" in status:
            # In hoa cho nổi bật
            print(f"[ALERT!] -> {log_line[:70]}... (Status: {status.upper()})")
        
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"\n[LỖI] Không thể kết nối đến {API_ENDPOINT}.")
        print("Hãy đảm bảo 'api.py' đang chạy.")
        print(f"Chi tiết: {e}\n")
        return False # Trả về False để dừng kịch bản

def main():
    """Hàm chính chạy vòng lặp gửi log."""
    print(f"--- Bắt đầu gửi log liên tục đến: {API_ENDPOINT} ---")
    print("Nhấn Ctrl+C để dừng.")
    log_count = 0

    try:
        while True:
            # Chọn một kịch bản ngẫu nhiên
            # Chúng ta tăng 'benign' để nó xuất hiện thường xuyên hơn
            scenario = random.choice(['benign', 'benign', 'benign', 'benign', 
                                      'ssh_attack', 'web_scan', 'ml_attack'])
            
            if scenario == 'benign':
                # Kịch bản: Gửi 1 log lành tính
                log = random.choice(BENIGN_LOGS)
                if not send_log(log):
                    break # Dừng nếu lỗi kết nối
                log_count += 1
                sys.stdout.write(f"\rĐã gửi {log_count} log (Đang gửi log lành tính...)")
                sys.stdout.flush()
                time.sleep(random.uniform(0.5, 2.0)) # Delay ngẫu nhiên

            elif scenario == 'ssh_attack':
                # Kịch bản: Tấn công SSH
                print(f"\n[--- KỊCH BẢN: TẤN CÔNG SSH BRUTEFORCE (Gửi {random.randint(5, 8)} log) ---]")
                for _ in range(random.randint(5, 8)): # Gửi 1 loạt để kích hoạt luật (5)
                    log = random.choice(SSH_BRUTEFORCE_LOGS)
                    if not send_log(log):
                        break
                    log_count += 1
                    time.sleep(random.uniform(0.1, 0.5)) # Tấn công thường nhanh
                print("[--- KẾT THÚC KỊCH BẢN SSH ---]")
                time.sleep(2) # Nghỉ 2 giây sau cuộc tấn công

            elif scenario == 'web_scan':
                # Kịch bản: Tấn công Web Scan
                print(f"\n[--- KỊCH BẢN: TẤN CÔNG WEB SCAN 404 (Gửi {random.randint(10, 15)} log) ---]")
                for _ in range(random.randint(10, 15)): # Gửi 1 loạt để kích hoạt luật (10)
                    log = random.choice(WEB_SCAN_LOGS)
                    if not send_log(log):
                        break
                    log_count += 1
                    time.sleep(random.uniform(0.1, 0.3)) # Tấn công quét rất nhanh
                print("[--- KẾT THÚC KỊCH BẢN WEB SCAN ---]")
                time.sleep(2)

            elif scenario == 'ml_attack':
                # Kịch bản: Tấn công ML (SQLi/XSS)
                print(f"\n[--- KỊCH BẢN: TẤN CÔNG ML (Gửi {random.randint(2, 4)} log) ---]")
                for _ in range(random.randint(2, 4)):
                    log = random.choice(ML_ATTACK_LOGS)
                    if not send_log(log):
                        break
                    log_count += 1
                    time.sleep(random.uniform(0.5, 1.0))
                print("[--- KẾT THÚC KỊCH BẢN ML ---]")
                time.sleep(2)

    except KeyboardInterrupt:
        print("\n\nĐã nhận lệnh (Ctrl+C). Dừng gửi log.")
        print(f"Tổng cộng đã gửi: {log_count} log.")

if __name__ == "__main__":
    main()