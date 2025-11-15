import pandas as pd
import joblib
import sys
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

# --- Cấu hình ---
DATA_FILE = r'training_dataset.csv' 
MODEL_OUTPUT_FILE = 'logsentinel_multiclass_model.joblib'

# --- --- ---

def main():
    print("Bắt đầu quy trình huấn luyện mô hình (Bước 2 - Đa lớp)...")
    
    # --- 1. Tải và chuẩn bị dữ liệu ---
    print(f"Đọc dữ liệu từ: {DATA_FILE}")
    try:
        df = pd.read_csv(DATA_FILE, low_memory=False)
    except FileNotFoundError:
        print(f"[LỖI] Không tìm thấy file dataset: {DATA_FILE}")
        sys.exit(1)
    except pd.errors.EmptyDataError:
        print(f"[LỖI] File dataset rỗng: {DATA_FILE}")
        sys.exit(1)


    df['full_log_text'] = df['full_log_text'].fillna('')
    
    # --- HẾT PHẦN SỬA LỖI ---
    
    # Xử lý NaN cho các cột hạng mục
    cat_cols = ['status_code', 'detected_log_type', 'process_info']
    for col in cat_cols:
        if col in df.columns:
            df[col] = df[col].fillna('missing') # Điền giá trị 'missing'
            df[col] = df[col].astype(str) # Ép kiểu về string
        else:
            print(f"[CẢNH BÁO] Không tìm thấy cột hạng mục: {col}. Tạo cột 'missing'.")
            df[col] = 'missing' # Tạo cột nếu không có

    print(f"Đã đọc và chuẩn bị {len(df)} dòng log.")

    # --- Xác định Đặc trưng (X) và Nhãn (y) ---
    X = df[['full_log_text', 'status_code', 'detected_log_type', 'process_info']]
    
    try:
        y = df['attack_type']
    except KeyError:
        print("[LỖI] Không tìm thấy cột 'attack_type' trong file CSV.")
        sys.exit(1)
        
    print("Phân bố nhãn trong dataset:")
    print(y.value_counts().sort_index())

    # --- 2. Xây dựng Pipeline xử lý (Giữ nguyên) ---
    print("Xây dựng pipeline xử lý...")

    text_processor = TfidfVectorizer(
        max_features=5000,
        stop_words='english',
        ngram_range=(1, 2)
    )
    categorical_processor = OneHotEncoder(
        handle_unknown='ignore'
    )
    preprocessor = ColumnTransformer(
        transformers=[
            ('text', text_processor, 'full_log_text'),
            ('categorical', categorical_processor, ['status_code', 'detected_log_type', 'process_info'])
        ],
        remainder='drop'
    )

    # --- 3. Tạo mô hình Logistic Regression (Giữ nguyên) ---
    model_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', LogisticRegression(
            solver='liblinear',
            max_iter=1000,
            class_weight='balanced' 
        ))
    ])

    # --- 4. Huấn luyện và Đánh giá ---
    print("Chia dữ liệu thành 80% train / 20% test...")
    
    # Thêm kiểm tra nếu chỉ có 1 lớp
    if len(y.unique()) < 2:
        print("[LỖI] Dataset chỉ chứa 1 loại nhãn. Không thể huấn luyện.")
        print("Hãy kiểm tra lại file create_dataset.py (hàm assign_attack_type).")
        sys.exit(1)
        
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print(f"Bắt đầu huấn luyện trên {len(X_train)} dòng...")
    model_pipeline.fit(X_train, y_train)
    print("Huấn luyện hoàn tất.")

    print("Đánh giá hiệu năng mô hình trên tập test...")
    y_pred = model_pipeline.predict(X_test)
    
    print("\n--- BÁO CÁO KẾT QUẢ (ĐA LỚP) ---")
    print(f"Độ chính xác (Accuracy): {accuracy_score(y_test, y_pred):.4f}")
    
    # --- Cập nhật target_names ---
    # Lấy các nhãn duy nhất từ y_test và y_pred để đảm bảo chúng ta có đủ tên
    labels_present = sorted(list(set(y_test) | set(y_pred)))
    
    # Map nhãn số sang tên
    label_map = {
        0: 'Bình thường (0)',
        1: 'Bruteforce (1)',
        2: 'WebScan (2)' 
        # (Thêm nhãn 2 vào đây, dù nó chưa có, để chuẩn bị cho tương lai)
    }
    
    # Chỉ lấy tên của các nhãn CÓ XUẤT HIỆN
    class_labels = [label_map.get(label, f"Không rõ ({label})") for label in labels_present]

    print("\nBáo cáo chi tiết (Classification Report):")
    # labels=labels_present để đảm bảo thứ tự
    print(classification_report(y_test, y_pred, labels=labels_present, target_names=class_labels, zero_division=0))

    # --- 5. Lưu mô hình ---
    print(f"\nLưu mô hình đã huấn luyện vào file: {MODEL_OUTPUT_FILE}")
    joblib.dump(model_pipeline, MODEL_OUTPUT_FILE)
    print("--- HOÀN THÀNH BƯỚC 2 ---")

if __name__ == "__main__":
    main()