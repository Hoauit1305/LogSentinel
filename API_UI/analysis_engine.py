import pandas as pd
import joblib
import sys
import os
import re
from datetime import datetime
from collections import defaultdict

# --- Import các script ---
script_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(script_dir, '..'))
processing_dir = os.path.join(root_dir, 'processing')
sys.path.append(root_dir)
sys.path.append(processing_dir)
sys.path.append(script_dir)

try:
    from auto_parser import auto_detect_and_parse
    from rules_engine import apply_stateful_rules
except ImportError:
    print(f"[LỖI ENGINE] Không thể import từ 'processing' hoặc 'rules_engine.py'.")
    sys.exit(1)

# --- CẤU HÌNH & TẢI MÔ HÌNH ---
MODEL_FILE = 'logsentinel_multiclass_model.joblib' 
MODEL_FEATURES = ['full_log_text', 'status_code', 'detected_log_type', 'process_info']

try:
    model = joblib.load(MODEL_FILE)
    print(f"[ENGINE] Tải mô hình {MODEL_FILE} thành công.")
except Exception as e:
    print(f"[LỖI ENGINE] Không thể tải mô hình {MODEL_FILE}: {e}")
    sys.exit(1)

def prepare_ml_dataframe(data_dict):
    """(Giữ nguyên) Chuẩn bị DataFrame cho mô hình ML."""
    input_data = pd.DataFrame([data_dict])
    
    if 'request' not in input_data.columns: input_data['request'] = ''
    if 'message' not in input_data.columns: input_data['message'] = ''
    
    input_data['request'] = input_data['request'].fillna('')
    input_data['message'] = input_data['message'].fillna('')
    
    input_data['full_log_text'] = input_data['request'] + ' ' + input_data['message']
    
    cat_cols = ['status_code', 'detected_log_type', 'process_info']
    for col in cat_cols:
        if col not in input_data.columns:
            input_data[col] = 'missing'
        input_data[col] = input_data[col].fillna('missing').astype(str)
            
    return input_data[MODEL_FEATURES]

# --- [LOGIC ĐÃ SỬA] ---
def process_log_for_alerting(data_payload, trackers, save_alert_func):
    """
    Hàm điều phối chính, sử dụng logic 2 tầng (Rule-First).
    """
    try:
        # 1. Lấy và Parse log
        raw_log_line = data_payload.get('log')
        if not raw_log_line:
            return
        
        raw_log_lower = raw_log_line.lower()
        log_type, parsed_data = auto_detect_and_parse(raw_log_line)
        
        # SỬA: Cho phép log 'Unknown' đi tiếp để ML xử lý
        if log_type == 'Unknown':
            if 'raw_message' in parsed_data:
                parsed_data['message'] = parsed_data.pop('raw_message')
            # Không return, để log đi tiếp Tầng 2 (ML)
        
        parsed_data['detected_log_type'] = log_type

        # 2. Trích xuất các trường quan trọng
        ip = parsed_data.get('ip_address') or parsed_data.get('ip')
        status_code = str(parsed_data.get('status_code', 'missing'))

        # --- 3. [TẦNG 1] Kiểm tra luật Stateful (Bruteforce, Web Scan) TRƯỚC ---
        prediction_rule = 0 # 0 = Bỏ qua, 1 = Bruteforce, 2 = Web Scan
        
        # 3a. Kiểm tra Bruteforce
        if ('ssh' in log_type or 'linux' in log_type or 'auth' in log_type) and 'failed password' in raw_log_lower:
            prediction_rule = 1
            if not ip: # Nếu parser không tìm thấy IP
                ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', raw_log_lower)
                if ip_match:
                    ip = ip_match.group(1)
        
        # 3b. Kiểm tra Web Scan
        elif ('web' in log_type or 'apache' in log_type or 'nginx' in log_type) and status_code == '404':
            prediction_rule = 2
            # (Parser web thường đã có IP, không cần trích xuất lại)

        # 4. Xử lý kết quả Tầng 1
        if prediction_rule > 0:
            if not ip:
                print(f"[ENGINE T1] Bỏ qua, không tìm thấy IP cho log stateful: {raw_log_line[:60]}...")
                return
            
            parsed_data['ip'] = ip # Đảm bảo key 'ip' tồn tại
            current_time = datetime.now()
            
            apply_stateful_rules(
                prediction_rule, 
                parsed_data,
                current_time, 
                trackers, 
                save_alert_func
            )
            # DỪNG LẠI: Log đã được Tầng 1 xử lý, không cần chạy ML
            return 

        # --- 5. [TẦNG 2] Xử lý ML (Stateless: SQLi, XSS, Unknown...) ---
        # Chỉ chạy nếu Tầng 1 bỏ qua (prediction_rule == 0)
        
        input_features = prepare_ml_dataframe(parsed_data)
        prediction_ml = model.predict(input_features)[0] # Dự đoán 0, 1, hoặc 2
        
        # Chúng ta chỉ tin mô hình ML nếu nó nói là TẤN CÔNG
        # (Lưu ý: mô hình này có thể dự đoán 1 hoặc 2, nhưng chúng ta sẽ gộp chung)
        if prediction_ml != 0: 
            # LƯU Ý: Chúng ta đang ở Tầng 2, vì vậy chúng ta ghi
            # cảnh báo là "ML Attack" (tấn công stateless)
            # thay vì "Bruteforce" hay "Web Scan" (tấn công stateful)
            
            # (Phần này bạn có thể tùy chỉnh)
            # Nếu bạn muốn ML cũng có thể kích hoạt rules_engine, hãy bỏ
            # comment phần code bên dưới và xóa `save_alert('ML Attack'...)`
            
            # --- Tùy chọn A (Đang dùng): ML tạo cảnh báo trực tiếp ---
            details = parsed_data.get('request', '') or parsed_data.get('message', raw_log_line[:100])
            save_alert_func(
                'ML Attack', 
                details, 
                ip or 'N/A', 
                0.9, # Giả sử độ tự tin 90%
                parsed_data
            )
            
            # --- Tùy chọn B: Gửi kết quả ML cho Rules Engine (giống logic cũ) ---
            # (Điều này có thể gây nhầm lẫn, vì ML đã bỏ lỡ Tầng 1)
            # parsed_data['ip'] = ip
            # current_time = datetime.now()
            # apply_stateful_rules(prediction_ml, parsed_data, current_time, trackers, save_alert_func)
            
    except Exception as e:
        print(f"\n[!!! LỖI KHI DỰ ĐOÁN ML TRONG ENGINE !!!]")
        print(e)
        traceback.print_exc()
        print("[!!! KẾT THÚC LỖI !!!]\n")