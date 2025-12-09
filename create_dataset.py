import pandas as pd
import sys
import os
import re
import datetime
from tqdm import tqdm # Thư viện cho thanh tiến trình

# --- QUAN TRỌNG: Import các script từ thư mục 'processing' ---
script_dir = os.path.dirname(__file__)
processing_dir = os.path.join(script_dir, 'processing')
sys.path.append(processing_dir)

try:
    from auto_parser import auto_detect_and_parse, normalize_timestamp
    from parsers_config import PARSERS
except ImportError:
    print(f"[LỖI] Không thể import từ thư mục 'processing'.")
    sys.exit(1)

# --- Cấu hình ---
# Trỏ đến 3 file log thô "uy tín" của bạn
LOG_FILES_TO_PROCESS = [
    r'C:\nt140\LogSentinel\DATALOG\SSH.log',           # [HỖN HỢP] Chứa Nhãn 0 và Nhãn 1
    r'C:\nt140\LogSentinel\DATALOG\clean_access.log', # [SẠCH] Chỉ chứa Nhãn 0
    r'C:\nt140\LogSentinel\DATALOG\attack_webscan_access.log' # [TẤN CÔNG] Chỉ chứa Nhãn 2
]

OUTPUT_CSV_FILE = 'training_dataset.csv' # Tên file CSV đầu ra

# --- Định nghĩa Nhãn ---
# 0: Bình thường (Normal)
# 1: Bruteforce (Dò mật khẩu SSH)
# 2: WebScan (Quét lỗ hổng web)

def assign_ssh_attack_type(log_type, data):
    """
    Hàm gán nhãn NÀY CHỈ DÙNG CHO FILE SSH.LOG
    Nó chỉ trả về 0 (Bình thường) hoặc 1 (Tấn công).
    """
    # --- Nhãn 1: Bruteforce (Dò mật khẩu SSH) ---
    is_ssh_log = False
    if 'process_info' in data and 'sshd' in str(data['process_info']).lower():
        is_ssh_log = True
    elif 'auth_syslog' in log_type: 
        is_ssh_log = True

    if is_ssh_log and 'message' in data:
        msg = str(data['message']).lower()
        bruteforce_keywords = [
            'authentication failure', 
            'failed password', 
            'invalid user', 
            'check pass; user unknown'
        ]
        for keyword in bruteforce_keywords:
            if keyword in msg:
                return 1 # Bruteforce

    # --- Nhãn 0: Bình thường (phần còn lại của SSH.log) ---
    return 0

def main():
    print(f"Bắt đầu tạo dataset 3 lớp (Tối ưu)...")
    all_data = []

    for log_file in LOG_FILES_TO_PROCESS:
        if not os.path.exists(log_file):
            print(f"[CẢNH BÁO] Bỏ qua, không tìm thấy file: {log_file}")
            continue

        print(f"\nĐang xử lý file: {log_file}...")
        
        # --- LOGIC GÁN NHÃN MỚI ---
        # Xác định trước nhãn cho file
        forced_label = None
        if 'clean_access.log' in log_file:
            forced_label = 0 # File này 100% là Nhãn 0
            print("  -> Chế độ: Gán nhãn 0 (Sạch) cho tất cả.")
        elif 'attack_webscan_access.log' in log_file:
            forced_label = 2 # File này 100% là Nhãn 2
            print("  -> Chế độ: Gán nhãn 2 (WebScan) cho tất cả.")
        elif 'SSH.log' in log_file:
            forced_label = None # File này Hỗn hợp, cần dùng regex
            print("  -> Chế độ: Dùng regex để phân loại Nhãn 0/1.")
        # --- KẾT THÚC LOGIC MỚI ---
            
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in tqdm(f, desc=f"File {os.path.basename(log_file)}"):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        log_type, data = auto_detect_and_parse(line)
                        if log_type == 'Unknown':
                            continue 
                        
                        # --- ÁP DỤNG LOGIC GÁN NHÃN ---
                        if forced_label is not None:
                            # 1. Gán nhãn "cứng" (cho file access.log)
                            attack_label = forced_label
                        else:
                            # 2. Dùng Regex (chỉ cho file SSH.log)
                            attack_label = assign_ssh_attack_type(log_type, data)
                        # --- --- ---
                        
                        data['attack_type'] = attack_label
                        data['detected_log_type'] = log_type
                        data['timestamp'] = normalize_timestamp(log_type, data)
                        
                        all_data.append(data)
                        
                    except Exception as e:
                        pass 
                        
        except Exception as e:
            print(f"[LỖI] Không thể đọc file {log_file}: {e}")
            
    if not all_data:
        print("[LỖI] Không có dữ liệu nào được xử lý. Dừng lại.")
        sys.exit(1)

    print(f"\nĐã xử lý xong. Chuyển đổi {len(all_data)} dòng sang DataFrame...")
    df = pd.DataFrame(all_data)

    print("Xây dựng các đặc trưng (features) cho mô hình...")
    
    if 'request' not in df.columns: df['request'] = ''
    else: df['request'] = df['request'].fillna('') 
    
    if 'message' not in df.columns: df['message'] = ''
    else: df['message'] = df['message'].fillna('') 
    
    df['full_log_text'] = df['request'] + ' ' + df['message']
    
    if 'status_code' not in df.columns: df['status_code'] = 'missing'
    else: df['status_code'] = df['status_code'].fillna('missing')

    final_columns = [
        'full_log_text', 
        'status_code', 
        'detected_log_type', 
        'process_info',
        'attack_type'
    ]
    
    columns_to_save = [col for col in final_columns if col in df.columns]
    
    print(f"Lưu dataset vào: {OUTPUT_CSV_FILE}")
    df[columns_to_save].to_csv(OUTPUT_CSV_FILE, index=False)
    
    print("\n--- HOÀN THÀNH TẠO DATASET ---")
    print("Phân bố nhãn (Attack Type Distribution):")
    print(df['attack_type'].value_counts().sort_index())
    print("\n(0: Bình thường, 1: Bruteforce, 2: WebScan)")

if __name__ == "__main__":
    main()