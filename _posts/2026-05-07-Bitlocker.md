---
title: "Bitlocker CTF Challenge - picoCTF"
date: 2026-05-07 00:00:00 +07000
categories: [CTF]

---

**Description:**
Jacky is not very knowledgable about the best security passwords and used a simple password to encrypt their BitLocker drive. See if you can break through the encryption!

=======================================================================================



![pic1](/assets/img/posts/Bitlocker/pic1.png)

File được cung cấp: Một file image đĩa thô (bitlocker-1.dd)

**Bước 1: Xác định Image**

![pic2](/assets/img/posts/Bitlocker/pic2.png)

Kết quả cho thấy đây là phân vùng boot sector DOS/MBR chứa phân vùng BitLocker. Vì BitLocker là công nghệ mã hóa độc quyền của Windows, nên không thể mount bình thường bằng Linux nếu không có đúng key hoặc password.



**Bước 2: Trích xuất Hash Password**

Theo gợi ý “hash cracking”, mình đã sử dụng công cụ bitlocker2john trong bộ John the Ripper để trích xuất hash password (recovery/user password) từ metadata của file .dd.
 
![pic3](/assets/img/posts/Bitlocker/pic3.png)

Kết quả tạo ra một chuỗi hash bắt đầu bằng $bitlocker$1$...

![pic4](/assets/img/posts/Bitlocker/pic4.png)
 
**Bước 3: Crack Hash**

Với file hash đã trích xuất (bitlocker_hash.txt), mình sử dụng John the Ripper thực hiện tấn công từ điển bằng wordlist rockyou.txt tiêu chuẩn.

![pic5](/assets/img/posts/Bitlocker/pic5.png)

Kết quả: John đã crack thành công password: Jacqueline

**Bước 4: Giải mã Volume**

Để truy cập dữ liệu đã mã hóa trên Linux, mình sử dụng công cụ Dislocker. Quá trình mount cần thực hiện 2 bước riêng biệt: lớp giải mã và lớp filesystem.

![pic6](/assets/img/posts/Bitlocker/pic6.png)

Mở khóa lớp BitLocker:

Sử dụng password đã crack để tạo ra file ảo đã được giải mã.

![pic7](/assets/img/posts/Bitlocker/pic7.png)
 
Kết quả tạo ra file ảo: ~/mnt_bitlocker/dislocker-file

**Bước 5: Mount Filesystem**

File dislocker-file là một phân vùng NTFS thô. Mình mount nó vào thư mục thứ hai để xem được các file thực tế.
 
![pic8](/assets/img/posts/Bitlocker/pic8.png)
![pic9](/assets/img/posts/Bitlocker/pic9.png)


**Kết luận & Logic**

Challenge này kiểm tra khả năng kết hợp forensics đĩa (trích xuất hash ẩn) với cryptography (crack password-based encryption).

Bài học quan trọng là logic mount “hai thư mục”:

•	Thư mục thứ nhất chứa luồng dữ liệu đã giải mã (virtual file).

•	Thư mục thứ hai parse luồng đó thành filesystem có thể đọc được (các file thực tế).
