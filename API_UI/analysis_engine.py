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

# Ngưỡng tự tin (Có thể cần giảm nhẹ ngưỡng này vì Temperature Scaling sẽ làm giảm điểm số chung)
CONFIDENCE_THRESHOLD = 0.60  

# Hệ số nhiệt độ (Temperature)
# T = 1.0: Giữ nguyên
# T > 1.0 (VD: 1.5 - 2.0): Trừng phạt sự tự tin thái quá (Làm phẳng phân phối)
# T < 1.0: Làm nhọn phân phối (Không dùng)
TEMPERATURE_FACTOR = 1.5 

model = None
try:
    if os.path.exists(MODEL_FILE):
        model = joblib.load(MODEL_FILE)
        print(f"[ENGINE] Đã tải mô hình ML: {MODEL_FILE}")
    else:
        print(f"[CẢNH BÁO] Không tìm thấy file model '{MODEL_FILE}'.")
except Exception as e:
    print(f"[LỖI ENGINE] Lỗi khi tải mô hình: {e}")

def calculate_entropy_with_temperature(probs, temperature=1.0):
    probs = np.array(probs)
    
    # --- BƯỚC QUAN TRỌNG: Ép xác suất không được tuyệt đối ---
    # Nếu để 1.0 hoặc 0.0 thì Temperature Scaling không có tác dụng toán học
    # Ta ép nó vào khoảng [0.001, 0.999] để tạo "không gian" cho việc làm mềm
    epsilon = 1e-3  # 0.001
    probs = np.clip(probs, epsilon, 1.0 - epsilon)
    
    # Chuẩn hóa lại cho tổng = 1 sau khi clip
    probs = probs / np.sum(probs)

    # --- Áp dụng Temperature Scaling ---
    if temperature != 1.0 and temperature > 0:
        # Cách 1: Dùng lũy thừa (Code cũ của bạn)
        # inv_temp = 1.0 / temperature
        # scaled_probs = np.power(probs, inv_temp)
        
        # Cách 2: Chuyển về Logits -> Chia Temp -> Softmax lại (Chính xác hơn về mặt toán học)
        # Logits giả định = log(p)
        logits = np.log(probs)
        scaled_logits = logits / temperature
        
        # Softmax function
        exp_logits = np.exp(scaled_logits - np.max(scaled_logits)) # Trừ max để ổn định số học
        probs = exp_logits / np.sum(exp_logits)
    
    # --- Tính Entropy & Confidence ---
    entropy = -np.sum(probs * np.log(probs))
    
    num_classes = len(probs)
    if num_classes <= 1: 
        return 1.0
    
    max_entropy = np.log(num_classes)
    normalized_entropy = entropy / max_entropy
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
                
                # --- DÙNG ENTROPY + TEMPERATURE SCALING ---
                # Sử dụng TEMPERATURE_FACTOR đã định nghĩa ở trên (VD: 1.5)
                confidence_score = calculate_entropy_with_temperature(all_probs, temperature=TEMPERATURE_FACTOR)
                
                prediction = int(np.argmax(all_probs))
                
            except Exception as ml_error:
                print(f"[ML ERROR] {ml_error}")

        # Lọc bỏ nếu độ tự tin thấp (Model đang bối rối hoặc bị trừng phạt bởi Temperature)
        if confidence_score < CONFIDENCE_THRESHOLD:
            prediction = 0 # Fallback về lớp 0 (Bình thường/Không xác định)
        
        parsed_data['ml_confidence'] = confidence_score
        current_time = datetime.now()

        # 3. Gửi sang Rule Engine
        apply_stateful_rules(prediction, parsed_data, current_time, trackers, save_alert_func)

    except Exception as e:
        print(f"[LỖI ENGINE] {e}")
        traceback.print_exc()