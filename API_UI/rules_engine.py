import re
from datetime import datetime, timedelta

# ================== CẤU HÌNH NGƯỠNG ==================

SSH_BRUTEFORCE_THRESHOLD = 5
SSH_BRUTEFORCE_WINDOW = timedelta(seconds=60)

WEB_SCAN_THRESHOLD = 10
WEB_SCAN_WINDOW = timedelta(seconds=60)

# ================== CORE STATEFUL CHECK ==================

def _check_stateful_rule(tracker, key, timestamp, window, threshold):
    """
    Theo dõi hành vi theo cửa sổ thời gian.
    Khi đủ ngưỡng → trigger và reset.
    """
    tracker[key] = [t for t in tracker[key] if timestamp - t < window]
    tracker[key].append(timestamp)

    if len(tracker[key]) >= threshold:
        tracker[key] = []
        return True

    return False

# ================== RULE ENGINE ==================

def apply_stateful_rules(prediction, data, current_time, trackers, save_alert_func):
    """
    Rule engine KHÔNG tính confidence.
    Nó chỉ dùng confidence đã được ML engine tính toán khoa học.
    """

    # ---------- Xác định IP ----------
    ip_source = data.get('ip') or data.get('ip_address')

    if not ip_source:
        message = data.get('message', '') or str(data)
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
        if ip_match:
            ip_source = ip_match.group(1)
        else:
            return  # Không có IP → bỏ qua

    # ---------- Confidence gốc từ ML ----------
    confidence = float(data.get('ml_confidence', 0.0))

    # ================== RULE 1: SSH BRUTE FORCE ==================

    is_ssh_fail = (
        prediction == 1 or
        "failed password" in str(data).lower()
    )

    if is_ssh_fail:
        if _check_stateful_rule(
            trackers['ssh'],
            ip_source,
            current_time,
            SSH_BRUTEFORCE_WINDOW,
            SSH_BRUTEFORCE_THRESHOLD
        ):
            alert_name = "SSH Brute-force"
            details = f"Phát hiện {SSH_BRUTEFORCE_THRESHOLD} lần đăng nhập thất bại trong 60 giây."
            save_alert_func(alert_name, details, ip_source, confidence, data)

    # ================== RULE 2: WEB SCAN ==================

    status_code = str(data.get('status_code', ''))
    is_web_scan = (
        prediction == 2 or
        status_code in ('403', '404')
    )

    if is_web_scan:
        if _check_stateful_rule(
            trackers['web'],
            ip_source,
            current_time,
            WEB_SCAN_WINDOW,
            WEB_SCAN_THRESHOLD
        ):
            alert_name = "Web Vulnerability Scan"
            details = f"Phát hiện {WEB_SCAN_THRESHOLD} request lỗi ({status_code}) trong 60 giây."
            save_alert_func(alert_name, details, ip_source, confidence, data)
