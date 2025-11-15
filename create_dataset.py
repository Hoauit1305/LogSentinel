import pandas as pd
import sys
import os
import re
import datetime
from tqdm import tqdm # Thư viện cho thanh tiến trình (cài bằng: pip install tqdm)

# --- QUAN TRỌNG: Import các script từ thư mục 'processing' ---
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

# --- Cấu hình ---
# Đảm bảo bạn đã thêm file 'apache.log' vào đây
LOG_FILES_TO_PROCESS = [
    'Linux_2k.log',
    'OpenSSH_2k.log',
    'apache.log'
]

OUTPUT_CSV_FILE = 'training_dataset.csv' # Tên file CSV đầu ra

# --- Định nghĩa 3 Nhãn Tấn công ---
# 0: Bình thường (Normal)
# 1: Bruteforce (Dò mật khẩu SSH, FTP...)
# 2: WebScan (Quét lỗ hổng web)

def assign_attack_type(log_type, data):
    """
    Hàm gán nhãn dựa trên luật (Rule-based Labeling).
    Chỉ trả về 0, 1, hoặc 2.
    """
    
    # --- Nhãn 1: Bruteforce (Dò mật khẩu SSH) ---
    # (Phần này đã đúng, giữ nguyên)
    is_ssh_log = False
    if 'process_info' in data and 'sshd' in str(data['process_info']).lower():
        is_ssh_log = True
    elif 'ssh' in log_type: # Giữ lại cách kiểm tra cũ
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

    # --- Nhãn 2: WebScan (Từ log web) ---
    
    # (CẬP NHẬT) Check 1: Dành cho 'access.log' (kiểm tra trường 'request')
    if 'request' in data and data['request']:
        request_line = str(data['request']).lower() 
        
        # Thêm các mẫu từ file apache.log của bạn (xmlrpc, wordpress...)
        webscan_patterns = r'\.git/config|\.env|wp-admin|phpmyadmin|/etc/passwd' \
                           r'|xmlrpc\.php|/wordpress|/b2evo|/drupal|/community'
                           
        if re.search(webscan_patterns, request_line):
            return 2 # WebScan

        # Kiểm tra User-Agent
        if 'user_agent' in data and data['user_agent']:
            user_agent = str(data['user_agent']).lower()
            tool_patterns = r'nikto|sqlmap|nmap|dirb|wpscan|feroxbuster'
            if re.search(tool_patterns, user_agent):
                return 2 # WebScan
    
    # (CẬP NHẬT) Check 2: Dành cho 'error.log' (kiểm tra trường 'message')
    # Kiểm tra xem log_type có phải là log apache không VÀ trường message có tồn tại không
    if 'apache' in log_type and 'message' in data:
        msg = str(data['message']).lower()
        
        # "File does not exist" là dấu hiệu của việc quét
        if 'file does not exist' in msg:
            # Kiểm tra thêm các từ khóa quét thư mục (từ file apache.log)
            scan_keywords = ['wordpress', 'b2evo', 'b2', 'blogtest', 'blog', 
                             'blogs', 'community', 'drupal', 'xmlsrv']
            for keyword in scan_keywords:
                if keyword in msg:
                    return 2 # WebScan

    # --- Nhãn 0: Bình thường ---
    # Nếu không khớp với 2 luật tấn công ở trên,
    # chúng ta giả định nó là log "Bình thường".
    return 0

def main():
    print(f"Bắt đầu tạo dataset 3 lớp...")
    all_data = []

    for log_file in LOG_FILES_TO_PROCESS:
        if not os.path.exists(log_file):
            print(f"[CẢNH BÁO] Bỏ qua, không tìm thấy file: {log_file}")
            continue

        print(f"\nĐang xử lý file: {log_file}...")
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Dùng tqdm để hiện thanh tiến trình
                for line in tqdm(f, desc=f"File {log_file}"):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        log_type, data = auto_detect_and_parse(line)
                        if log_type == 'Unknown':
                            continue # Bỏ qua các dòng không parse được
                        
                        # GỌI HÀM GÁN NHÃN MỚI (chỉ 0, 1, 2)
                        attack_label = assign_attack_type(log_type, data)
                        
                        # Thêm các trường cần thiết vào data
                        data['attack_type'] = attack_label # Đây là nhãn mới
                        data['detected_log_type'] = log_type
                        data['timestamp'] = normalize_timestamp(log_type, data)
                        
                        all_data.append(data)
                        
                    except Exception as e:
                        pass # Bỏ qua lỗi parse trên 1 dòng
                        
        except Exception as e:
            print(f"[LỖI] Không thể đọc file {log_file}: {e}")
            
    if not all_data:
        print("[LỖI] Không có dữ liệu nào được xử lý. Dừng lại.")
        sys.exit(1)

    print(f"\nĐã xử lý xong. Chuyển đổi {len(all_data)} dòng sang DataFrame...")
    df = pd.DataFrame(all_data)

# --- Xử lý Feature (Đã sửa lỗi KeyError) ---
    print("Xây dựng các đặc trưng (features) cho mô hình...")
    
    # Kiểm tra 'request' trước khi dùng
    if 'request' not in df.columns:
        df['request'] = '' # Nếu không tồn tại, tạo cột rỗng
    else:
        df['request'] = df['request'].fillna('') # Nếu tồn tại, fillna
    
    # Kiểm tra 'message' trước khi dùng
    if 'message' not in df.columns:
        df['message'] = '' # Nếu không tồn tại, tạo cột rỗng
    else:
        df['message'] = df['message'].fillna('') # Nếu tồn tại, fillna
    
    df['full_log_text'] = df['request'] + ' ' + df['message']
    
    # (THÊM MỚI) Xử lý cột status_code (quan trọng cho log web)
    if 'status_code' not in df.columns:
        df['status_code'] = 'missing'
    else:
        df['status_code'] = df['status_code'].fillna('missing')

    # --- Lưu file ---
    final_columns = [
        'full_log_text', 
        'status_code', 
        'detected_log_type', 
        'process_info',
        'attack_type' # Cột nhãn 3 LỚP
    ]
    
    # Lọc ra các cột có tồn tại trong df
    columns_to_save = [col for col in final_columns if col in df.columns]
    
    print(f"Lưu dataset vào: {OUTPUT_CSV_FILE}")
    df[columns_to_save].to_csv(OUTPUT_CSV_FILE, index=False)
    
    print("\n--- HOÀN THÀNH TẠO DATASET 3 LỚP ---")
    print("Phân bố nhãn (Attack Type Distribution):")
    print(df['attack_type'].value_counts().sort_index())
    print("\n(0: Bình thường, 1: Bruteforce, 2: WebScan)")

if __name__ == "__main__":
    main()