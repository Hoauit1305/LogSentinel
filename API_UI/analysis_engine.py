# File: analysis_engine.py (ĐÃ SỬA LẠI LOGIC PARSE)

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
    # Import các hàm parser
    from auto_parser import auto_detect_and_parse, normalize_timestamp
    from parsers_config import PARSERS
    # Import hàm xử lý luật
    from rules_engine import apply_stateful_rules
except ImportError:
    print(f"[LỖI ENGINE] Không thể import từ 'processing' hoặc 'rules_engine.py'.")
    sys.exit(1)

# --- CẤU HÌNH & TẢI MÔ HÌNH (1 LẦN) ---
MODEL_FILE = 'logsentinel_multiclass_model.joblib' 
MODEL_FEATURES = ['full_log_text', 'status_code', 'detected_log_type', 'process_info']

try:
    model = joblib.load(MODEL_FILE)
    print(f"[ENGINE] Tải mô hình {MODEL_FILE} thành công.")
except Exception as e:
    print(f"[LỖI ENGINE] Không thể tải mô hình {MODEL_FILE}: {e}")
    sys.exit(1)
# --- --- ---


def prepare_ml_dataframe(data_dict):
    """
    (Hàm này giữ nguyên)
    Chuẩn bị DataFrame 1 dòng từ log (dict) ĐÃ ĐƯỢC PARSE.
    """
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

def process_log_for_alerting(data_payload, trackers, save_alert_func):
    """
    Đây là hàm điều phối chính.
    data_payload là dictionary thô từ API (ví dụ: {'log': '...'})
    """
    try:
        # --- SỬA ĐỔI QUAN TRỌNG ---
        # 1. Lấy log thô từ payload
        raw_log_line = data_payload.get('log')
        if not raw_log_line:
            print("[ENGINE] Bỏ qua, payload không có key 'log'.")
            return

        # 2. Phân tích (Parse) log thô (Bước 1)
        log_type, parsed_data = auto_detect_and_parse(raw_log_line)
        
        if log_type == 'Unknown':
            print(f"[ENGINE] Bỏ qua, log không nhận diện được: {raw_log_line[:50]}...")
            return

        # 3. Chuẩn bị dữ liệu cho ML (Bước 2)
        # (parsed_data là dictionary đã được parse, VÍ DỤ: {'message': 'Failed..', 'process_info': 'sshd...'})
        input_features = prepare_ml_dataframe(parsed_data)
        
        # 4. Dự đoán (ML) - Ra nhãn 0, 1, hoặc 2
        prediction = model.predict(input_features)[0]
        
        # 5. Áp dụng luật (Rules Engine - Bước 4)
        if prediction != 0:
            current_time = datetime.now()
            
            # Bổ sung các trường còn thiếu mà bộ luật cần
            parsed_data['ip_address'] = parsed_data.get('ip_address')
            parsed_data['status_code'] = parsed_data.get('status_code')

            apply_stateful_rules(
                prediction, 
                parsed_data, # Gửi dữ liệu ĐÃ ĐƯỢC PARSE
                current_time, 
                trackers, 
                save_alert_func
            )
        # --- KẾT THÚC SỬA ĐỔI ---
            
    except Exception as e:
        print(f"\n[!!! LỖI KHI DỰ ĐOÁN ML !!!]")
        print(e)
        print("[!!! KẾT THÚC LỖI !!!]\n")