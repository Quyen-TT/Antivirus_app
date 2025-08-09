# BTL Phân tích mã độc - PTIT 

# Virus Scanner v1.0.0 – Ứng dụng quét virus với YARA & Cuckoo Sandbox

## Giới thiệu

Dự án này là một ứng dụng Python đơn giản với giao diện Tkinter, cho phép người dùng quét virus/malware trên tệp hoặc thư mục bằng YARA rules.

Ngoài ra, các tệp nghi ngờ nhưng không xác định được sẽ được gửi đến Cuckoo Sandbox để phân tích động.

Ứng dụng hỗ trợ giải nén tự động các tệp nén nhiều định dạng (ZIP, RAR, 7z, TAR, GZ) và có thể xử lý cả tệp nén lồng nhau (nested archives) với mật khẩu (yêu cầu người dùng nhập khi cần).

## Chức năng chính

### 1. Quét tệp hoặc thư mục

Người dùng có thể chọn tệp đơn lẻ hoặc thư mục để quét.

Ứng dụng sẽ duyệt toàn bộ cây thư mục, bao gồm cả tệp bên trong các file nén.

Hỗ trợ quét nhiều định dạng tệp nén:

- `.zip`, `.rar`, `.7z`, `.tar`, `.gz`

- Giải nén lồng nhau tối đa 5 cấp.

### 2. Quét bằng YARA rules

Sử dụng YARA để phát hiện mẫu (pattern) trong file.

Có hai nhóm rule:

- White list: Tệp an toàn (bỏ qua khi phát hiện match).

- Black list: Tệp chứa dấu hiệu malware (xử lý ngay).

Nếu không match cả white list và black list ⇒ tệp được coi là "unknown" và gửi đến Cuckoo.

### 3. Xử lý khi phát hiện malware

Khi phát hiện match black list rule, chương trình hiện cửa sổ cảnh báo cho từng tệp và cho phép:

- Delete – Xóa tệp khỏi hệ thống.

- Freeze – Đổi tên tệp và chặn quyền truy cập (Windows icacls deny Everyone).

### 4. Gửi file đến Cuckoo Sandbox

Các file unknown sẽ được gửi đến Cuckoo API (http://192.168.10.100:1337/tasks/create/file) kèm API Token.

Hỗ trợ upload file trực tiếp và nhận phản hồi từ Cuckoo.

### 5. Hiển thị kết quả

Khu vực log để theo dõi quá trình quét.

Nút "View Details" cho phép xem chi tiết các chuỗi match từ YARA rules.

Báo cáo tổng kết:

- Tổng số rule

- Số file match white list

- Số file chứa malware

- Số file gửi Cuckoo

## Cấu trúc hoạt động

### 1. Giao diện Tkinter

- Entry nhập đường dẫn file/thư mục.

- Nút Open File, Open Folder, Scan.

- Khu vực ScrolledText để log.

- Nút View Details để xem match strings.

### 2. Luồng xử lý scan

- Lấy danh sách file cần quét.

- Nếu file là archive ⇒ giải nén ⇒ quét các file con.

- Kiểm tra với white list rules ⇒ an toàn.

- Kiểm tra với black list rules ⇒ cảnh báo & xử lý.

- Không match ⇒ gửi file sang Cuckoo.

### 3. Các chức năng hỗ trợ

- Giải nén file có mật khẩu.

- Giải nén nhiều lớp.

- Dọn dẹp thư mục tạm.

- Ghi log ra giao diện.

## Công nghệ & thư viện sử dụng

Python chuẩn:

- `os`, `sys`, `subprocess`, `threading`, `queue`, `shutil`, `gzip`, `tarfile`, `zipfile`

Giao diện: `tkinter`

Làm việc với định dạng nén:

- `rarfile`, `py7zr`

Tích hợp phân tích malware:

- `requests` (HTTP API với Cuckoo)

- `yara.exe` (dò quét mẫu malware)

Quản lý quyền file (Windows):

- `icacls`

## Yêu cầu

Python 3.x

YARA (`yara.exe`) đặt trong thư mục ứng dụng.

Cấu trúc thư mục:

    VirusScanner/
    │
    ├── main.py                  
    │
    ├── yara.exe                 
    ├── winrar.exe               
    ├── 7z.exe                   
    │
    └── yara_rules/              
        ├── white_list/          
        │   ├── rule1.yar
        │   ├── rule2.yara
        │   └── ...
        │
        └── black_list/          # Rule cho file độc hại
            ├── malware_rule.yar
            ├── trojan_rule.yara
            └── ...

## Đóng gói ứng dụng

    pyinstaller --onefile --add-data="yara_rules/white_list;./yara_rules/white_list" --add-data="yara_rules/black_list;./yara_rules/black_list" --add-data="yara.exe;." anti_virus.py
