import sqlite3
import json
import sys
from datetime import datetime
from collections import defaultdict
import os
import traceback

from flask import Flask, request, jsonify, render_template

# ---Import bộ não xử lý ---
# (Giả sử analysis_engine.py nằm cùng thư mục với api.py)
try:
    import analysis_engine
except ImportError:
    print("[LỖI API] Không tìm thấy file 'analysis_engine.py'.")
    print("Hãy đảm bảo 'analysis_engine.py' nằm cùng thư mục với 'api.py'.")
    sys.exit(1)

# --- 1. Cấu hình & Khởi tạo ---
app = Flask(__name__)

# Cấu hình file (Chỉ cần DB)
DB_FILE = 'alerts.db'

# Bộ nhớ đệm (tracker) cho các luật
# API vẫn phải quản lý các tracker này để chúng tồn tại giữa các request
ssh_tracker = defaultdict(list)
web_scan_tracker = defaultdict(list)

# --- 2. Các hàm trợ giúp (Database & Dashboard) ---
# (Các hàm này giữ nguyên, vì API chịu trách nhiệm lưu trữ và hiển thị)

def init_db():
    """Khởi tạo cơ sở dữ liệu và bảng 'alerts' nếu chưa tồn tại."""
    print("Khởi tạo database...")
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
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
    """
    Lưu một cảnh báo mới vào database.
    Hàm này sẽ được truyền vào 'analysis_engine' như một callback.
    """
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

def get_dashboard_data():
    """Lấy dữ liệu cho dashboard (dùng cho cả /dashboard và /dashboard_data)."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM alerts")
    total_alerts = cursor.fetchone()['count']
    
    cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
    alerts = cursor.fetchall()
    alerts_list = []
    for row in alerts:
        alert_dict = dict(row)
        alert_dict.setdefault('timestamp', '')
        alert_dict.setdefault('alert_type', 'Unknown')
        alert_dict.setdefault('ip_address', '')
        alert_dict.setdefault('details', '')
        alert_dict.setdefault('confidence', 0)
        
        raw = alert_dict.get('raw_log_data')
        if raw:
            try: alert_dict['raw_log_data'] = json.loads(raw)
            except Exception: alert_dict['raw_log_data'] = raw
        else: alert_dict['raw_log_data'] = {}
        
        alerts_list.append(alert_dict)

    cursor.execute("SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type ORDER BY cnt DESC")
    rows = cursor.fetchall()
    chart_labels = [r['alert_type'] for r in rows] if rows else []
    chart_data_counts = [r['cnt'] for r in rows] if rows else []

    conn.close()
    
    return {
        "total_alerts": total_alerts,
        "alerts": alerts_list,
        "chart_labels": chart_labels,
        "chart_data_counts": chart_data_counts
    }

# --- 3. Các Endpoint (Routes) ---

@app.route('/analyze_log', methods=['POST'])
def analyze_log():
    """
    Endpoint chính nhận log và ủy thác xử lý cho analysis_engine.
    """
    data_payload = request.json
    if not data_payload or 'log' not in data_payload:
        return jsonify({'error': 'Không nhận được "log" trong JSON payload.'}), 400
    
    # Chuẩn bị các đối tượng mà engine cần
    trackers = {'ssh': ssh_tracker, 'web': web_scan_tracker}
    
    try:
        # Gọi hàm xử lý chính từ analysis_engine
        # Truyền 3 thứ: 
        # 1. Toàn bộ payload JSON (chứa log thô)
        # 2. Các bộ đếm (trackers)
        # 3. Hàm 'save_alert' để engine có thể gọi lại và lưu DB
        analysis_engine.process_log_for_alerting(
            data_payload, 
            trackers, 
            save_alert
        )
        
        # Phản hồi chung (engine sẽ tự in ra lỗi nếu có)
        return jsonify({'status': 'processed_by_engine'})
        
    except Exception as e:
        print(f"\n[!!! LỖI NGHIÊM TRỌNG TẠI TẦNG API !!!]")
        traceback.print_exc()
        return jsonify({'error': 'Lỗi engine nội bộ', 'details': str(e)}), 500


@app.route('/dashboard')
def dashboard():
    """Endpoint hiển thị giao diện Dashboard UI (Tải lần đầu)."""
    try:
        data = get_dashboard_data()
        template_name = 'index.html' if os.path.exists(os.path.join(app.template_folder, 'index.html')) else 'dashboard.html'
        
        return render_template(
            template_name, 
            alerts=data['alerts'],
            total_alerts=data['total_alerts'],
            chart_labels=data['chart_labels'],
            chart_data_counts=data['chart_data_counts']
        )
    except Exception as e:
        print(f"LỖI: Không thể tải dashboard: {e}")
        traceback.print_exc()
        return f"Lỗi: {e}", 500

@app.route('/dashboard_data')
def dashboard_data():
    """Endpoint này chỉ trả về dữ liệu JSON để dashboard tự cập nhật."""
    try:
        data = get_dashboard_data()
        return jsonify(data)
    except Exception as e:
        print(f"LỖI: Không thể gửi dữ liệu dashboard: {e}")
        return jsonify({"error": str(e)}), 500

# --- 4. Chạy App ---
if __name__ == '__main__':
    # Chỉ xóa DB nếu có flag --reset
    reset_db = '--reset' in sys.argv or os.getenv('RESET_DB', '').lower() == 'true'
    
    if reset_db and os.path.exists(DB_FILE):
        print("[RESET] Đang xóa DB cũ để tạo cấu trúc mới...")
        os.remove(DB_FILE)
    elif os.path.exists(DB_FILE):
        print(f"[INFO] DB '{DB_FILE}' tồn tại, sẽ sử dụng dữ liệu hiện tại.")
    
    init_db() 
    app.run(host='0.0.0.0', port=5000, debug=True)