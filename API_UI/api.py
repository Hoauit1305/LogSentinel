import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template
import sqlite3
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict
import os
import traceback

# --- 1. Cấu hình & Khởi tạo ---
app = Flask(__name__)

# Cấu hình file
MODEL_FILE = 'logsentinel_model.joblib'
DB_FILE = 'alerts.db'
MODEL_FEATURES = ['full_log_text', 'status_code', 'detected_log_type', 'process_info']

# Cấu hình luật tương quan (Stateful)
SSH_BRUTEFORCE_THRESHOLD = 5
SSH_BRUTEFORCE_WINDOW = timedelta(seconds=60)
WEB_SCAN_THRESHOLD = 10
WEB_SCAN_WINDOW = timedelta(seconds=60)

# Bộ nhớ đệm (tracker) cho các luật
ssh_tracker = defaultdict(list)
web_scan_tracker = defaultdict(list)

# Tải mô hình
try:
    print(f"Đang tải mô hình từ: {MODEL_FILE}...")
    model_pipeline = joblib.load(MODEL_FILE)
    print("Tải mô hình thành công!")
except FileNotFoundError:
    print(f"[LỖI] Không tìm thấy file mô hình: {MODEL_FILE}")
    model_pipeline = None
except Exception as e:
    print(f"[LỖI] Không thể tải mô hình: {e}")
    model_pipeline = None

# --- 2. Các hàm trợ giúp (Helpers) ---

def init_db():
    """Khởi tạo cơ sở dữ liệu và bảng 'alerts' nếu chưa tồn tại."""
    print("Khởi tạo database...")
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # Dùng CREATE TABLE IF NOT EXISTS để an toàn,
        # việc reset DB sẽ do hàm main xử lý
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts ( 
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                alert_type TEXT,
                details TEXT,
                ip_address TEXT,
                confidence REAL,
                raw_log_data TEXT
            )
        ''')
        conn.commit()
        conn.close()
        print("Database sẵn sàng.")
    except Exception as e:
        print(f"Lỗi khi khởi tạo DB: {e}")

def save_alert(alert_type, details, ip, confidence, raw_data):
    """Lưu một cảnh báo mới vào database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (timestamp, alert_type, details, ip_address, confidence, raw_log_data) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now(), alert_type, details, ip, float(confidence), json.dumps(raw_data))
        )
        conn.commit()
        conn.close()
        print(f"[CẢNH BÁO MỚI] Đã lưu: {alert_type} từ IP {ip}")
    except Exception as e:
        print(f"LỖI: Không thể lưu cảnh báo DB: {e}")

def check_stateful_rule(tracker, key, timestamp, window, threshold):
    """
    Kiểm tra một luật stateful (như brute-force, scan).
    Trả về True nếu vi phạm.
    """
    # 1. Xóa các timestamp cũ (ngoài cửa sổ)
    tracker[key] = [t for t in tracker[key] if timestamp - t < window]
    # 2. Thêm timestamp mới
    tracker[key].append(timestamp)
    # 3. Kiểm tra vi phạm
    if len(tracker[key]) >= threshold:
        tracker[key] = [] # Reset để tránh spam
        return True # Vi phạm
    return False # Chưa vi phạm

def prepare_ml_dataframe(data_dict):
    """
    Chuẩn bị DataFrame 1 dòng từ log (dict) để mô hình ML dự đoán.
    Xử lý tất cả các trường hợp thiếu cột hoặc NaN.
    """
    input_data = pd.DataFrame([data_dict])
    
    # Đảm bảo các cột text chính tồn tại
    if 'request' not in input_data.columns: input_data['request'] = ''
    if 'message' not in input_data.columns: input_data['message'] = ''
    
    input_data['request'] = input_data['request'].fillna('')
    input_data['message'] = input_data['message'].fillna('')
    
    input_data['full_log_text'] = input_data['request'] + ' ' + input_data['message']
    
    # Xử lý các cột hạng mục
    cat_cols = ['status_code', 'detected_log_type', 'process_info']
    for col in cat_cols:
        if col not in input_data.columns:
            input_data[col] = 'missing'
        input_data[col] = input_data[col].fillna('missing').astype(str)
        
    return input_data[MODEL_FEATURES]

# --- 3. Các Endpoint (Routes) ---

@app.route('/analyze_log', methods=['POST'])
def analyze_log():
    """Endpoint chính nhận và phân tích log real-time."""
    if model_pipeline is None:
        return jsonify({'error': 'Mô hình chưa được tải.'}), 500

    data = request.json
    if not data:
        return jsonify({'error': 'Không nhận được dữ liệu JSON.'}), 400

    current_time = datetime.now()
    ip = data.get('ip_address')
    status_code = str(data.get('status_code', 'missing'))
    message = data.get('message', '')
    request_str = data.get('request', '')
    process_info = data.get('process_info', '')

    # --- CHẠY LUẬT 1: ML Attack (Stateless) ---
    try:
        input_features = prepare_ml_dataframe(data)
        
        prediction = model_pipeline.predict(input_features)[0]
        
        if prediction == 1: # 1 là 'Attack'
            probability_attack = model_pipeline.predict_proba(input_features)[0][1]
            
            if probability_attack > 0.7: # Ngưỡng 70%
                print(f"[ML] Phát hiện 'Attack' (Conf: {probability_attack:.2f}). Đang lưu...")
                save_alert('ML Attack', request_str, ip, probability_attack, data)
                
    except Exception as e:
        print(f"\n[!!! LỖI KHI DỰ ĐOÁN ML !!!]")
        traceback.print_exc()
        print("[!!! KẾT THÚC LỖI !!!]\n")

    # --- CHẠY LUẬT 2: SSH Brute-force (Stateful) ---
    if 'sshd' in process_info and 'failed' in message.lower():
        ip_match = re.search(r'from ([\d\.]+)', message)
        if ip_match:
            ssh_ip = ip_match.group(1)
            if check_stateful_rule(ssh_tracker, ssh_ip, current_time, SSH_BRUTEFORCE_WINDOW, SSH_BRUTEFORCE_THRESHOLD):
                details = f"{SSH_BRUTEFORCE_THRESHOLD} lần thất bại trong {SSH_BRUTEFORCE_WINDOW.seconds} giây"
                save_alert('SSH Brute-force', details, ssh_ip, 1.0, data)
    
    # --- CHẠY LUẬT 3: Web Scan (Stateful) ---
    if status_code == '404' and ip:
        if check_stateful_rule(web_scan_tracker, ip, current_time, WEB_SCAN_WINDOW, WEB_SCAN_THRESHOLD):
            details = f"{WEB_SCAN_THRESHOLD} lỗi 404 trong {WEB_SCAN_WINDOW.seconds} giây"
            save_alert('Web Scan', details, ip, 1.0, data)
            
    return jsonify({'status': 'processed'})

@app.route('/dashboard')
def dashboard():
    """Endpoint hiển thị giao diện Dashboard UI."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # 1. Lấy tổng số cảnh báo
        cursor.execute("SELECT COUNT(*) as count FROM alerts")
        total_alerts = cursor.fetchone()['count']
        
        # 2. Lấy loại tấn công phổ biến nhất
        cursor.execute("""
            SELECT alert_type, COUNT(*) as count 
            FROM alerts 
            GROUP BY alert_type 
            ORDER BY count DESC 
            LIMIT 1
        """)
        top_type_row = cursor.fetchone()
        top_attack_type = top_type_row['alert_type'] if top_type_row else "N/A"
        
        # 3. Lấy 100 cảnh báo mới nhất
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
        alerts = cursor.fetchall()
        
        conn.close()
        
        return render_template(
            'dashboard.html', 
            alerts=alerts,
            total_alerts=total_alerts,
            top_attack_type=top_attack_type
        )
        
    except Exception as e:
        print(f"LỖI: Không thể tải dashboard: {e}")
        return f"Lỗi: {e}", 500

# --- 4. Chạy App ---
if __name__ == '__main__':
    # Xóa DB cũ khi khởi động ở chế độ debug để đảm bảo cấu trúc mới
    if os.path.exists(DB_FILE):
        print("Phát hiện DB cũ, đang xóa để tạo cấu trúc mới...")
        os.remove(DB_FILE)
    
    init_db() 
    app.run(host='0.0.0.0', port=5000, debug=True)