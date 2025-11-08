# DATALOG: Bộ dữ liệu Huấn luyện

Thư mục này chứa tất cả dữ liệu thô, và bộ dữ liệu training cuối cùng (`training_dataset.csv`) được sử dụng cho bước **Machine Learning**.

---

## Dữ liệu Huấn luyện Cuối cùng

**File:** `training_dataset.csv`
**Link tải:** [Tại đây](https://drive.google.com/file/d/1w9QK1y9Y_aaRDgA8hBb3uXPn4fKlfLO_/view?usp=drive_link)
**Mô tả:** 
* Đây là file dữ liệu "sạch", đã được gán nhãn và xáo trộn (shuffle), sẵn sàng để huấn luyện mô hình Machine Learning.
* Bao gồm các trường của **access.log** và **auth.log**, loại log và nhãn dán (is attack)

**Thống kê (Dựa trên kết quả chạy `combine_csv.py`):**
* **Tổng số dòng:** 630,814
* **Log "Sạch" (Nhãn 0):** 570,814 dòng
    * `AccessLog` (sạch): 440,992 dòng
    * `AuthLog` (sạch): 129,822 dòng
* **Log "Tấn công" (Nhãn 1):** 60,000 dòng
* **Tỷ lệ (Sạch:Tấn công):** Khoảng 9.5 : 1

---

## Quy trình tạo Dữ liệu (Pipeline)

File `training_dataset.csv` được tạo ra thông qua 5 bước chính, sử dụng các script từ thư mục `/processing`:

### 1. Thu thập (Collect)
* **Log Sạch:** Lấy mẫu ~500k `access.log` và ~500k `auth.log` từ dữ liệu thực tế (Lưu vào `access_500k.log` và `SSH_500K.log`).
* **Log Tấn công:** Dùng `generate_attacks.py` để tạo 60,000 dòng log tấn công đa dạng (Lưu vào `all_attacks.log`).

### 2. Phân tích (Parse)
* Dùng `auto_parser.py` để chuyển đổi 3 file log thô trên thành 3 file `.csv` có cấu trúc:
    * `access_500k.csv`
    * `SSH_500K.csv`
    * `attacks_parsed.csv`

### 3. Lọc (Filter)
* Dùng `filter_logs.py` để "làm sạch" 2 file log "sạch", loại bỏ các dòng đáng ngờ (lỗi 404, 401, "Failed password", v.v.).
* **Kết quả:**
    * `clean_access_500k.csv` (còn 440,992 dòng)
    * `clean_SSH_500K.csv` (còn 129,822 dòng)

### 4. Gán nhãn (Label)
* Dùng `label_data.py` để thêm cột `is_attack`:
    * Gán **nhãn 0** (Bình thường) cho `clean_access_500k.csv` -> `clean_access_500k_labeled.csv`.
    * Gán **nhãn 0** (Bình thường) cho `clean_SSH_500K.csv` -> `clean_SSH_500K_labeled.csv`.
    * Gán **nhãn 1** (Tấn công) cho `attacks_parsed.csv` -> `attacks_labeled.csv`.

### 5. Gộp (Combine)
* Dùng `combine_csv.py` để gộp 3 file đã gán nhãn ở trên lại, xáo trộn (shuffle) chúng và tạo ra file `training_dataset.csv` cuối cùng.