import requests
import time
import sys
import os

API_URL = "http://127.0.0.1:5000/analyze_log"

# 3 file log gốc của bạn
LOG_FILES = [
    r"C:\nt140\LogSentinel\DATALOG\SSH.log",
    r"C:\nt140\LogSentinel\DATALOG\clean_access.log",
    r"C:\nt140\LogSentinel\DATALOG\attack_webscan_access.log",
]

def send_log(line):
    payload = {"log": line}
    try:
        r = requests.post(API_URL, json=payload, timeout=3)
        if r.status_code != 200:
            print("Lỗi gửi:", r.text)
    except Exception as e:
        print("Không gửi được:", e)

def simulate():
    for file in LOG_FILES:
        if not os.path.exists(file):
            print("[CẢNH BÁO] Không tìm thấy file", file)
            continue

        print(f"\nĐang mô phỏng gửi log: {file}")
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Gửi log vào API
                send_log(line)

                # để dashboard kịp update
                time.sleep(0.02)   # 20 ms / log ─ bạn có thể giảm nếu muốn nhanh hơn

    print("\n--- MÔ PHỎNG HOÀN TẤT ---")

if __name__ == "__main__":
    simulate()
