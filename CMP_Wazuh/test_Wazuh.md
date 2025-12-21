# WAZUH SQL INJECTION TEST – UBUNTU 20.04

## Môi trường thử nghiệm

- OS: Ubuntu 20.04 LTS
- Wazuh: 4.7 (All-in-One)
- Web Server: Apache 2
- PHP: 7.x
- Test method: Log-based detection

## Mục tiêu
- Cài đặt **Wazuh** 
- Cài **Apache + PHP**  
- Tạo trang `index.php` để tránh lỗi **404**  
- Theo dõi log Apache  
- Theo dõi alert và lỗi của Wazuh  
- Test phát hiện **SQL Injection (SQLi)** bằng `curl`

---

## 1. Cài đặt Wazuh (All-in-One)

### Cập nhật hệ thống
```bash
sudo apt update && sudo apt upgrade -y
```

### Cài đặt Wazuh (Manager + Indexer + Dashboard)
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

### Kiểm tra trạng thái dịch vụ
```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

---

## 2. Cài đặt Apache & PHP

### Cài Apache
```bash
sudo apt install apache2 -y
```

### Cài PHP
```bash
sudo apt install php libapache2-mod-php php-cli php-mysql -y
```

### Khởi động Apache
```bash
sudo systemctl enable apache2
sudo systemctl start apache2
```

### Kiểm tra
```
http://localhost
```

---

## 3. Tạo file `index.php` (tránh lỗi 404)

### Tạo file
```bash
sudo nano /var/www/html/index.php
```

### Nội dung `index.php`
```php
<?php
echo "Wazuh SQLi Test Page";
if (isset($_GET['id'])) {
    echo "<br>ID = " . $_GET['id'];
}
?>
```

### Phân quyền
```bash
sudo chown www-data:www-data /var/www/html/index.php
sudo chmod 644 /var/www/html/index.php
```

### Test
```
http://localhost/index.php
```

---

## 4. Theo dõi log Apache

### Log truy cập (lấy log ở đây để test với mô hình ML)
```bash
sudo tail -f /var/log/apache2/access.log
```

### Log lỗi
```bash
sudo tail -f /var/log/apache2/error.log
```

---

## 5. Theo dõi log & alert của Wazuh

### Log chính của Wazuh
```bash
sudo tail -f /var/ossec/logs/ossec.log
```

### Alert dạng text (dễ quan sát nhất)
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

### Alert dạng JSON 
```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

---

## 6. Test SQL Injection bằng `curl`

### UNION SELECT (phát hiện SQLi)
```bash
curl "http://localhost/index.php?id=1+UNION+SELECT+user,password+FROM+users"
```

### OR logic (không phát hiện)
```bash
curl "http://localhost/index.php?id=1+OR+2>1"
```

### AND + function (không phát hiện)
```bash
curl "http://localhost/index.php?id=1+AND+LENGTH(USER())>1"
```

---

**Hoàn tất bài test.**

