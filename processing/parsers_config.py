# File: parsers_config.py

PARSERS = {
    # THỨ TỰ RẤT QUAN TRỌNG:
    # Phải đặt các regex "phức tạp" hoặc "dài" (nhiều trường) lên trên.
    # 'apache_combined' (9 trường) phải đứng TRƯỚC 'apache_common' (7 trường).
    # Nếu không, một log "combined" sẽ bị khớp nhầm thành "common".

    'apache_combined': {
        'regex': r'([\d\.]+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"',
        'columns': [
            'ip_address', 
            'client_id', 
            'user_id', 
            'timestamp', 
            'request', 
            'status_code', 
            'size', 
            'referer', 
            'user_agent'
        ]
    },
    
    'apache_common': {
        'regex': r'([\d\.]+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "([^"]*)" (\d{3}) (\S+)',
        'columns': [
            'ip_address', 
            'client_id', 
            'user_id', 
            'timestamp', 
            'request', 
            'status_code', 
            'size'
        ]
    },
    
    'auth_syslog': {
        'regex': r'^(\w{3}\s+\d+\s[\d:]+) (\S+) ([^:]+): (.*)$',
        'columns': [
            'timestamp', 
            'hostname', 
            'process_info', 
            'message'
        ]
    }
    
    # Có thể thêm các parser mới (ví dụ: 'nginx', 'windows_event') ở đây
}