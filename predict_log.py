import pandas as pd
import joblib
import sys
import os
import re
import datetime
from collections import Counter

# --- QUAN TRỌNG: Import các script từ thư mục 'processing' ---
# (Phần này giữ nguyên)
script_dir = os.path.dirname(__file__)
processing_dir = os.path.join(script_dir, 'processing')
sys.path.append(processing_dir)

try:
    # Import các hàm từ Bước 1
    from auto_parser import auto_detect_and_parse, normalize_timestamp
    from parsers_config import PARSERS
except ImportError:
    print(f"[LỖI] Không thể import từ thư mục 'processing'.")
    print("Hãy đảm bảo file 'auto_parser.py' và 'parsers_config.py' nằm trong thư mục 'processing'.")
    sys.exit(1)

# --- Cấu hình (CẬP NHẬT) ---
# Tải mô hình ĐA LỚP mới
MODEL_FILE = 'logsentinel_multiclass_model.joblib' 

# Test trên cả 2 file
LOG_FILES_TO_TEST = [
    'all_attacks.log',
    'Linux_2k.log',
    'OpenSSH_2k.log',
    'apache.log'
] 
# (Bạn có thể dùng đường dẫn đầy đủ nếu cần)

MODEL_FEATURES = ['full_log_text', 'status_code', 'detected_log_type', 'process_info']

# --- THÊM MỚI: Map nhãn số sang tên ---
LABEL_MAP = {
    0: "Benign",
    1: "Bruteforce",
    2: "WebScan"
}

def prepare_log_for_prediction(raw_log_line):
    """
    Hàm này lấy 1 dòng log thô và xử lý nó thành 
    DataFrame 1 dòng mà mô hình có thể hiểu được.
    (Hàm này giữ nguyên - nó đã đúng)
    """
    
    # 1. Parse và Chuẩn hóa (Giống Bước 1)
    try:
        log_type, data = auto_detect_and_parse(raw_log_line)
        if log_type == 'Unknown': # Nếu parser không nhận diện được
            return None # Bỏ qua dòng này
            
        normalized_ts = normalize_timestamp(log_type, data)
    except Exception as e:
        return None # Bỏ qua dòng này

    if 'timestamp' in data:
        del data['timestamp']
    data['timestamp'] = normalized_ts
    data['detected_log_type'] = log_type
    
    # 2. Chuyển thành DataFrame (1 dòng)
    df = pd.DataFrame([data])
    
    # 3. Xây dựng lại các Feature y hệt như lúc train
    # (Phần này đã đúng, nó xử lý trường hợp
    # parser không trả về 'request' hoặc 'message')
    
    # -- Xử lý NaN cho các cột văn bản --
    if 'request' not in df.columns:
        df['request'] = ''
    if 'message' not in df.columns:
        df['message'] = ''
    
    df['request'] = df['request'].fillna('')
    df['message'] = df['message'].fillna('')
    df['full_log_text'] = df['request'] + ' ' + df['message']
    
    # -- Xử lý NaN cho các cột hạng mục --
    cat_cols = ['status_code', 'detected_log_type', 'process_info']
    for col in cat_cols:
        if col not in df.columns:
            df[col] = 'missing' 
        
        df[col] = df[col].fillna('missing')
        df[col] = df[col].astype(str)

    # 4. Trả về DataFrame với các cột chính xác
    try:
        return df[MODEL_FEATURES]
    except KeyError as e:
        print(f"[LỖI] Thiếu feature quan trọng khi chuẩn bị dữ liệu: {e}")
        return None

def main():
    # --- 1. Tải mô hình ---
    print(f"Tải mô hình từ {MODEL_FILE}...")
    try:
        model = joblib.load(MODEL_FILE)
    except FileNotFoundError:
        print(f"[LỖI] Không tìm thấy file mô hình: {MODEL_FILE}")
        print("Bạn đã chạy 'train_model.py' (bản đa lớp) chưa?")
        sys.exit(1)
    
    print("Tải mô hình thành công.")

    # --- 2. Đọc file log và dự đoán (CẬP NHẬT) ---
    
    # Dùng Counter để đếm tất cả các loại nhãn
    total_counts = Counter() 
    total_processed = 0
    total_skipped = 0

    for log_file in LOG_FILES_TO_TEST:
        print(f"\n--- Bắt đầu dự đoán trên file: {log_file} ---")
        
        if not os.path.exists(log_file):
            print(f"[CẢNH BÁO] Bỏ qua, không tìm thấy file: {log_file}")
            continue

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_processed += 1
                    raw_log_line = line.strip()

                    if not raw_log_line: # Bỏ qua các dòng trống
                        total_skipped += 1
                        continue
                    
                    # 3. Chuẩn bị 1 dòng log
                    prepared_df = prepare_log_for_prediction(raw_log_line)
                    
                    if prepared_df is None:
                        total_skipped += 1
                        continue
                    
                    # 4. Dự đoán (Predict)
                    prediction = model.predict(prepared_df)
                    label = prediction[0] # Nhãn sẽ là 0, 1, hoặc 2
                    
                    # 5. Đếm và In kết quả (Chỉ in ra các ca tấn công)
                    total_counts[label] += 1
                    

                    result_name = LABEL_MAP.get(label, "TẤN CÔNG KHÔNG RÕ")
                    print(f"  [{result_name}] (Dòng {total_processed}): {raw_log_line[:120]}...")
                    
                    if total_processed % 500 == 0: # Cứ mỗi 500 dòng in 1 thông báo
                        print(f"  ... Đã xử lý {total_processed} dòng ...")

        except Exception as e:
            print(f"[LỖI] Gặp lỗi nghiêm trọng khi đọc file {log_file}: {e}")

    # --- 6. In Báo cáo Tổng kết (CẬP NHẬT) ---
    print("\n--- HOÀN TẤT DỰ ĐOÁN (TẤT CẢ CÁC FILE) ---")
    print(f"Tổng số dòng đã xử lý: {total_processed}")
    print(f"Dòng bị bỏ qua (Unknown/Lỗi): {total_skipped}")
    print("-" * 30)
    print("Thống kê kết quả:")
    
    # In ra kết quả đếm được
    for label_id, count in total_counts.items():
        label_name = LABEL_MAP.get(label_id, f"Không rõ (Nhãn {label_id})")
        print(f"  {label_name}: {count} dòng")

if __name__ == "__main__":
    main()