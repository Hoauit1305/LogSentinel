# Bộ tiền xử lý Log (Processing)

Nhiệm vụ của module này là đọc các file log thô từ nhiều nguồn khác nhau, tự động nhận diện loại log (ví dụ: `access.log`, `auth.log`), bóc tách thông tin, chuẩn hóa dữ liệu, và xuất ra một file CSV đồng nhất để phục vụ các phần sau.

---

## 1. `parsers_config.py`

* **Vai trò:** Chứa định dạng của các loại log.
* **Khả năng mở rộng:** Có thể dễ dàng mở rộng thêm nhiều loại log mới (như Nginx, Windows Event Log...) bằng cách thêm một mục mới vào file config.

## 2. `auto_parser.py`

* **Vai trò:** Đây là script chính để chạy toàn bộ quá trình xử lý.

* **Cách hoạt động:**
    1.  Đọc file `parsers_config.py` để lấy danh sách các parser (Regex và tên cột).
    2.  Đọc từng dòng trong file log đầu vào (`all_logs.log`).
    3.  **Tự động nhận diện (Auto-detection):** Với từng dòng log, script sẽ "thử" lần lượt các regex từ config cho đến khi tìm thấy một mẫu khớp.
    4.  **Tổng hợp:** Tập hợp tất cả các dòng log (từ các nguồn khác nhau) vào một DataFrame (bảng) duy nhất của Pandas.
    5.  **Xuất file:** Lưu DataFrame này thành file `processed_logs_combined.csv`.

## 3. Cách sử dụng

1.  **Chuẩn bị file log:** Đảm bảo có file `all_logs.log` (hoặc file log đầu vào) trong cùng thư mục.
2.  **Chạy script:**
    * Mở terminal và đảm bảo đã cài đặt thư viện `pandas`:
        ```bash
        pip install pandas
        ```
    * Chạy script:
        ```bash
        cd processing

        python auto_parser.py "<input_path>"
        # Hoặc chỉ định đường dẫn output
        python auto_parser.py "<input_path>" -o "<output_path>"
        ```