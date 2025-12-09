import pandas as pd
import joblib
import sys
import os
import traceback
import numpy as np
from datetime import datetime

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(script_dir)

try:
    from auto_parser import auto_detect_and_parse
    from rules_engine import apply_stateful_rules
except ImportError as e:
    print(f"[LỖI ENGINE] Thiếu file phụ trợ: {e}")
    sys.exit(1)

MODEL_FILE = 'logsentinel_multiclass_model.joblib' 
MODEL_FEATURES = ['full_log_text', 'status_code', 'detected_log_type', 'process_info']
CONFIDENCE_THRESHOLD = 0.60  

model = None
try:
    if os.path.exists(MODEL_FILE):
        model = joblib.load(MODEL_FILE)
        print(f"[ENGINE] Đã tải mô hình ML: {MODEL_FILE}")
    else:
        print(f"[CẢNH BÁO] Không tìm thấy file model '{MODEL_FILE}'.")
except Exception as e:
    print(f"[LỖI ENGINE] Lỗi khi tải mô hình: {e}")

def calculate_pure_entropy_confidence(probs):
    """
    Tính độ tự tin dựa trên THUẦN TÚY SHANNON ENTROPY.
    Không lai ghép, không dùng hệ số phụ. Đây là thước đo chuẩn xác nhất
    về độ 'bối rối' (uncertainty) của mô hình.
    """
    probs = np.array(probs)
    
    # 1. Clip để tránh lỗi log(0)
    # Giữ giá trị trong khoảng [1e-15, 1.0]
    epsilon = 1e-15
    probs = np.clip(probs, epsilon, 1.0)
    
    # 2. Tính Entropy: H = -sum(p * log(p))
    entropy = -np.sum(probs * np.log(probs))
    
    # 3. Tính Max Entropy (Độ hỗn loạn lớn nhất có thể với N lớp)
    # Ví dụ với 3 lớp, Max Entropy = log(3) ≈ 1.098
    num_classes = len(probs)
    if num_classes <= 1: 
        return 1.0
    max_entropy = np.log(num_classes)
    
    # 4. Chuẩn hóa Entropy về [0, 1]
    normalized_entropy = entropy / max_entropy
    
    # 5. Độ tự tin = 1 - Độ hỗn loạn
    confidence = 1.0 - normalized_entropy
    
    return float(confidence)

def prepare_features_for_prediction(parsed_data, raw_log):
    data = {
        'request': parsed_data.get('request', ''),
        'message': parsed_data.get('message', ''),
        'status_code': parsed_data.get('status_code', 'missing'),
        'detected_log_type': parsed_data.get('detected_log_type', 'Unknown'),
        'process_info': parsed_data.get('process_info', 'missing')
    }
    df = pd.DataFrame([data])
    
    df['request'] = df['request'].fillna('')
    df['message'] = df['message'].fillna('')
    full_text = df['request'] + ' ' + df['message']
    
    if full_text.iloc[0].strip() == '':
        df['full_log_text'] = raw_log
    else:
        df['full_log_text'] = full_text

    cat_cols = ['status_code', 'detected_log_type', 'process_info']
    for col in cat_cols:
        df[col] = df[col].fillna('missing').astype(str)
    
    return df[MODEL_FEATURES]

def process_log_for_alerting(data_payload, trackers, save_alert_func):
    global model

    try:
        raw_log_line = data_payload.get('log')
        if not raw_log_line: return

        # 1. Parse Log
        log_type, parsed_data = auto_detect_and_parse(raw_log_line)
        parsed_data['detected_log_type'] = log_type 
        
        # 2. ML Dự đoán
        prediction = 0
        confidence_score = 0.0
        
        if model:
            try:
                input_features = prepare_features_for_prediction(parsed_data, raw_log_line)
                
                # Lấy vector xác suất gốc [p1, p2, p3]
                all_probs = model.predict_proba(input_features)[0]
                
                # --- DÙNG THUẬT TOÁN ENTROPY THUẦN TÚY ---
                confidence_score = calculate_pure_entropy_confidence(all_probs)
                
                prediction = int(np.argmax(all_probs))
                
            except Exception as ml_error:
                print(f"[ML ERROR] {ml_error}")

        # Lọc bỏ nếu độ tự tin thấp (Model đang bối rối)
        if confidence_score < CONFIDENCE_THRESHOLD:
            prediction = 0 
        
        parsed_data['ml_confidence'] = confidence_score
        current_time = datetime.now()

        # 3. Gửi sang Rule Engine
        apply_stateful_rules(prediction, parsed_data, current_time, trackers, save_alert_func)

    except Exception as e:
        print(f"[LỖI ENGINE] {e}")
        traceback.print_exc()