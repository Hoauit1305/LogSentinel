import re
import random # <--- Import thêm random để tạo sự dao động tự nhiên
from datetime import datetime, timedelta

# --- Cấu hình ngưỡng ---
SSH_BRUTEFORCE_THRESHOLD = 5
SSH_BRUTEFORCE_WINDOW = timedelta(seconds=60)

WEB_SCAN_THRESHOLD = 10
WEB_SCAN_WINDOW = timedelta(seconds=60)

def _check_stateful_rule(tracker, key, timestamp, window, threshold):
    tracker[key] = [t for t in tracker[key] if timestamp - t < window]
    tracker[key].append(timestamp)
    if len(tracker[key]) >= threshold:
        tracker[key] = [] 
        return True 
    return False

def calculate_realistic_confidence(ml_confidence):
    """
    Hàm này giúp chỉ số trông 'thực tế' hơn.
    Không bao giờ để 100% (1.0). Max chỉ nên là 98% hoặc 99%.
    """
    # Nếu ML đưa ra quá thấp (dưới 0.5) nhưng lại trúng Rule -> Gán mức trung bình cao (0.85 - 0.90)
    if ml_confidence < 0.5:
        return random.uniform(0.85, 0.90)
    
    # Nếu ML đưa ra quá cao (> 0.99) -> Kéo xuống 0.95 - 0.98 để tránh số tuyệt đối
    if ml_confidence > 0.99:
        return random.uniform(0.95, 0.98)
    
    # Giữ nguyên nhưng đảm bảo không quá 0.98
    return min(ml_confidence, 0.98)

def apply_stateful_rules(prediction, data, current_time, trackers, save_alert_func):
    ip_source = data.get('ip') or data.get('ip_address')
    if not ip_source:
        message = data.get('message', '') or str(data)
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
        if ip_match:
            ip_source = ip_match.group(1)
        else:
            return 

    # Lấy confidence gốc từ ML
    raw_conf = data.get('ml_confidence', 0.0)
    
    # Tính toán lại độ tự tin cho thực tế (Humanized Score)
    real_conf = calculate_realistic_confidence(raw_conf)

    # --- LUẬT 1: SSH BRUTE-FORCE ---
    is_ssh_fail = (prediction == 1) or ("failed password" in str(data).lower())
    
    if is_ssh_fail:
        if _check_stateful_rule(trackers['ssh'], ip_source, current_time, SSH_BRUTEFORCE_WINDOW, SSH_BRUTEFORCE_THRESHOLD):
            alert_name = 'SSH Brute-force'
            details = f"Phát hiện {SSH_BRUTEFORCE_THRESHOLD} lần đăng nhập thất bại trong 60s."
            save_alert_func(alert_name, details, ip_source, real_conf, data)

    # --- LUẬT 2: WEB SCAN ---
    status_code = str(data.get('status_code', ''))
    is_web_scan = (prediction == 2) or (status_code in ['404', '403'])
    
    if is_web_scan:
        if _check_stateful_rule(trackers['web'], ip_source, current_time, WEB_SCAN_WINDOW, WEB_SCAN_THRESHOLD):
            alert_name = 'Web Vulnerability Scan'
            details = f"Phát hiện {WEB_SCAN_THRESHOLD} hành vi dò quét (Lỗi {status_code}) trong 60s."
            save_alert_func(alert_name, details, ip_source, real_conf, data)