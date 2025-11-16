# File: rules_engine.py

import re
from datetime import datetime, timedelta

# --- Cấu hình luật tương quan (Stateful) ---
SSH_BRUTEFORCE_THRESHOLD = 5
SSH_BRUTEFORCE_WINDOW = timedelta(seconds=60)
WEB_SCAN_THRESHOLD = 10
WEB_SCAN_WINDOW = timedelta(seconds=60)
# --- --- ---

def _check_stateful_rule(tracker, key, timestamp, window, threshold):
    """
    (Lấy từ app.py)
    Kiểm tra một luật stateful (như brute-force, scan).
    Trả về True nếu vi phạm.
    """
    tracker[key] = [t for t in tracker[key] if timestamp - t < window]
    tracker[key].append(timestamp)
    if len(tracker[key]) >= threshold:
        tracker[key] = [] 
        return True 
    return False

def apply_stateful_rules(prediction, data, current_time, trackers, save_alert_func):
    """
    Hàm này được gọi bởi 'analysis_engine'.
    Nó áp dụng logic đếm dựa trên nhãn (1 hoặc 2) mà ML đã dự đoán.
    """
    
    # --- Luật 1: SSH Brute-force (Stateful) ---
    # Nếu ML nói đây là "Bruteforce" (Nhãn 1)
    if prediction == 1:
        message = data.get('message', '')
        # Trích xuất IP từ message
        ip_match = re.search(r'from ([\d\.]+)', message)
        if ip_match:
            ssh_ip = ip_match.group(1)
            # Đưa vào bộ đếm stateful
            if _check_stateful_rule(trackers['ssh'], ssh_ip, current_time, SSH_BRUTEFORCE_WINDOW, SSH_BRUTEFORCE_THRESHOLD):
                details = f"{SSH_BRUTEFORCE_THRESHOLD} lần thất bại trong {SSH_BRUTEFORCE_WINDOW.seconds} giây"
                save_alert_func('SSH Brute-force', details, ssh_ip, 1.0, data)
    
    # --- Luật 2: Web Scan (Stateful) ---
    # Nếu ML nói đây là "WebScan" (Nhãn 2)
    elif prediction == 2:
        ip = data.get('ip_address')
        if ip:
            # Đưa vào bộ đếm stateful
            if _check_stateful_rule(trackers['web'], ip, current_time, WEB_SCAN_WINDOW, WEB_SCAN_THRESHOLD):
                details = f"{WEB_SCAN_THRESHOLD} lỗi 404 trong {WEB_SCAN_WINDOW.seconds} giây"
                save_alert_func('Web Scan', details, ip, 1.0, data)

    # --- Luật 3 (Tùy chọn): Cảnh báo ML đơn lẻ ---
    # Bạn có thể thêm luật: nếu là nhãn 3 (ví dụ: SQLi) thì cảnh báo ngay
    # elif prediction == 3:
    #     save_alert_func('SQLi Attack (ML)', data.get('request'), data.get('ip_address'), 0.9, data)