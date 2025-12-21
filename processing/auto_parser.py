import re
import pandas as pd
from processing.parsers_config import PARSERS
import datetime
import sys
import argparse  # <<< THÊM THƯ VIỆN NÀY

def auto_detect_and_parse(log_line):
    """
    Hàm này nhận 1 dòng log, thử tất cả các parser,
    và trả về (tên_parser, dữ_liệu_đã_parse) nếu khớp.
    """
    
    # Lặp qua từng parser được định nghĩa trong config
    for parser_name, config in PARSERS.items():
        log_regex = config['regex']
        column_names = config['columns']
        
        match = re.search(log_regex, log_line)
        
        if match:
            # KHỚP!
            parsed_values = match.groups()
            parsed_data = dict(zip(column_names, parsed_values))
            
            # Trả về loại log và dữ liệu đã bóc tách
            return parser_name, parsed_data
            
    # Nếu lặp hết mà không có parser nào khớp
    return 'unknown', {'raw_message': log_line.strip()}

def normalize_timestamp(log_type, data):
    """
    Hàm mới: Chuẩn hóa các timestamp khác nhau về định dạng ISO 8601.
    """
    original_timestamp = data.get('timestamp')
    normalized_timestamp = None
    
    if original_timestamp is None:
        return None

    if log_type in ('apache_common', 'apache_combined'):
        try:
            # Parse format: '08/Nov/2025:15:50:01 +0700'
            dt = datetime.datetime.strptime(original_timestamp, '%d/%b/%Y:%H:%M:%S %z')
            normalized_timestamp = dt.isoformat()
        except (ValueError, TypeError):
            pass # Giữ là None nếu lỗi

    elif log_type == 'auth_syslog':
        try:
            # *** PHẦN ĐÃ SỬA ĐỂ XỬ LÝ CẢNH BÁO ***
            
            # 1. Lấy thời gian hiện tại
            now = datetime.datetime.now()
            
            # 2. Tạo chuỗi timestamp mới bằng cách thêm năm vào
            # Ví dụ: '2025' + ' ' + 'Nov 8 16:01:15'
            timestamp_with_year = f"{now.year} {original_timestamp}"
            
            # 3. Parse chuỗi mới với format CÓ NĂM (%Y)
            dt_obj = datetime.datetime.strptime(timestamp_with_year, '%Y %b %d %H:%M:%S')

            # 4. Kiểm tra xem log có bị "roll-over" không 
            if dt_obj > now:
                dt_obj = dt_obj.replace(year=now.year - 1)
                
            normalized_timestamp = dt_obj.isoformat()
        except (ValueError, TypeError):
            pass # Giữ là None nếu lỗi
            
    return normalized_timestamp

def main():
    # --- PHẦN MỚI: Xử lý tham số đầu vào ---
    parser = argparse.ArgumentParser(
        description="LogSentinel - Bộ tiền xử lý log tự động.",
        epilog="Ví dụ: python auto_parser.py D:\\LogSentinel\\all_logs.log -o logs_da_xu_ly.csv"
    )
    
    # Tham số bắt buộc: file input
    parser.add_argument(
        "input_file", 
        help="Đường dẫn đến file log thô cần xử lý (ví dụ: all_logs.log)"
    )
    
    # Tham số tùy chọn (-o): file output
    parser.add_argument(
        "-o", "--output", 
        default="processed_logs_combined.csv", 
        help="Tên file CSV đầu ra (mặc định: processed_logs_combined.csv)"
    )
    
    args = parser.parse_args()
    
    # --- Sử dụng tham số thay vì hardcode ---
    input_log_file = args.input_file
    output_csv_file = args.output
    
    all_parsed_logs = []
    
    print(f"Bắt đầu xử lý file: {input_log_file}...")
    try:
        with open(input_log_file, 'r', encoding='utf-8') as f: # Thêm encoding='utf-8' cho chắc
            for line in f:
                if not line.strip():
                    continue 
                
                log_type, data = auto_detect_and_parse(line)
                
                # *** NÂNG CẤP ***
                normalized_ts = normalize_timestamp(log_type, data)
                
                if 'timestamp' in data:
                    del data['timestamp']
                    
                data['timestamp'] = normalized_ts 
                data['detected_log_type'] = log_type
                data['original_line'] = line.strip()
                
                all_parsed_logs.append(data)
                
    except FileNotFoundError:
        print(f"[LỖI] Không tìm thấy file: {input_log_file}")
        return
    except Exception as e:
        print(f"[LỖI] Một lỗi không xác định đã xảy ra: {e}")
        return

    print(f"Đã xử lý tổng cộng {len(all_parsed_logs)} dòng log.")
    
    if all_parsed_logs:
        df = pd.DataFrame(all_parsed_logs)
        
        # Sắp xếp lại cột để dễ nhìn
        cols = ['timestamp', 'detected_log_type', 'original_line'] + [c for c in df.columns if c not in ['timestamp', 'detected_log_type', 'original_line']]
        df = df[cols]
        
        # --- SỬA DÒNG NÀY ---
        df.to_csv(output_csv_file, index=False, encoding='utf-8-sig')
        print(f"Đã lưu tất cả log vào: {output_csv_file}")

if __name__ == "__main__":
    main()