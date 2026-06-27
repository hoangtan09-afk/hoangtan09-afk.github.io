---
title: "Email Header Analysis - Tryhackme"
date: 2026-06-26 00:00:00 +07000
categories: [Email Analysis]

---

**Scenario**: A sales executive at Greenholt PLC has reported a suspicious email received from a known customer. The message raised several red flags: a generic greeting, an unexpected request for a money transfer, and an unsolicited attachment. According to the employee, this behavior does not align with the customer’s usual communication style. Concerned that the email may be malicious, the message has been escalated to the SOC (Security Operations Center) for further investigation. Your goal is to analyze the provided email sample and determine whether it is legitimate or part of a phishing attempt.

<br>

>Đây là một bài lab về **phân tích email** có dấu hiệu phishing cơ bản. Chúng ta sẽ nhận được email từ một khách hàng nhưng có rất nhiều điều đáng ngờ trong email này. Nhiệm vụ với vai trò là một SOC Analyst, mình và các bạn sẽ đi điều tra và **truy vết** các dấu hiệu bất thường này.
{: .prompt-info }  

<br>

![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-26-23-51-41.png)



<br>

## Q1: What is the Transfer Reference Number listed in the email's Subject line?

Đến với câu hỏi đầu tiên, chúng ta cần xác định được số tham chiếu giao dịch chuyển tiền chứa trong mail là gì.

Ở ngay hình trên thì hầu hết chúng ta sẽ thấy con số này

![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-26-23-53-25.png)

Vậy con số chúng ta cần tìm ở đây là: **09674321**

<br>

## Q2. What is the display name of the sender?

Ở câu hỏi này chúng ta cần xác định tên của người gửi. Và điều này rất dễ dàng để nhìn thấy ngay khi chúng ta xem những section đầu của mail
 
![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-26-23-53-55.png)

Tên của người gửi là: **Mr. James Jackson**

<br>

## Q3. What is the sender's email address?

Đã tìm tên người gửi thì đi kèm với thông tin này là email, vậy email của người gửi sẽ là:

**info@mutawamarine.com**

<br>

## Q4. What email address will receive a reply to this email?

Ở phần này chúng ta chú ý đọc kỹ câu hỏi. Câu này hiểu đúng sẽ là địa chỉ email nào sẽ nhận được phản hồi cho email này.

Hãy chú ý dòng “**Reply to**”

![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-26-23-55-02.png)
 
Điều này dấy lên một vài nghi vấn. Tại sao email từ sender và email nhận được reply cho email này lại có địa chỉ khác nhau? Mọi reply cho email này sẽ được gửi đến info.**mutawamarine@mail.com**

<br>

## Q5. What is the originating IP address of this email?

Địa chỉ IP gốc của email này là gì? Để xem được IP gốc, chúng ta tiến hành phân tích source của email

Để xem source email trong **Thunderbird**, các bạn có thể click **view source** ở góc phải như hình
 
![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-26-23-55-53.png)

Có rất nhiều công cụ phân tích **email header** ngoài kia chẳng hạn như **Message Header Analyzer, Extract URLs,…** Bài lab này mình sẽ sử dụng **mxtoolbox** là chủ yếu

Sau khi xem view source, chọn tất cả nội dung trong **email source** và quăng lên **mxtoolbox**
 
![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-26-23-56-49.png)

Lướt xuống một tí tới phần **Relay Information**, bạn sẽ cần để ý đến **dòng đầu tiên**, cột **From**

![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-26-23-57-18.png)
 
Dòng này chứa địa chỉ IP gốc chúng ta cần tìm: **192.119.71.157**

Ngoài ra chúng ta có thể thấy các thông tin như:

1. **192.119.71.157 (Hostwinds server)**

→ nơi email được tạo / gửi đi đầu tiên 

2. **Yahoo MTA (mta4212.mail.bf1.yahoo.com)**

→ server nhận của Yahoo 

3. **Yahoo internal relay (atlas125.free.mail.bf1.yahoo.com)**

→ chuyển nội bộ trong Yahoo

<br>

## Q6. Who is the owner of the originating IP?

Khi chúng ta đã biết được IP gốc của email, việc truy vết được chủ sở hữu của địa chỉ IP này sẽ giúp ích nhiều cho việc phân tích sau này

Để thực hiện tìm kiếm chủ sở hữu, mình đã sử dụng công cụ **whois** có sẵn trong **kali linux**, câu lệnh đầy đủ sẽ là: **whois 192.119.71.157**
 
![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-26-23-58-29.png)

Kết quả trên cho thấy mình đã tra được tên của chủ sở hữu: **HostPapa**

Ngoài ra, chúng ta còn thấy cả địa chỉ cụ thể: **325 Delaware Avenue, Buffalo city, NY state, US**

<br>

## Q7. Run an SPF record check on the Return-Path domain identified in the email headers. What is the full SPF record for this domain?

Khi phân tích email header, việc kiểm tra SPF record của domain trong **Return-Path** giúp xác minh xem máy chủ gửi email có được phép gửi thay mặt cho domain đó hay không.

SPF hoạt động bằng cách domain công bố danh sách các máy chủ/IP được quyền gửi email. Khi nhận email, hệ thống sẽ lấy domain trong Return-Path và đối chiếu với SPF record.

![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-27-00-01-14.png)
 
Ở đây chúng ta có domain trong Return-Path là **mutawamarine.com**

Mình sẽ sử dụng công cụ có sẵn là **SPF surveyvor** để xem SPF record cho domain này
 
![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-27-00-01-38.png)

Ví dụ với record này, nghĩa là **domain** chỉ cho phép **Microsoft 365/Outlook** gửi email hợp lệ, và mọi nguồn khác đều bị coi là không hợp lệ **(-all).**

Trong thực tế phân tích, SPF giúp phát hiện spoofing (giả mạo email), kiểm tra tính hợp lệ của hạ tầng gửi, và hỗ trợ đánh giá mức độ tin cậy của email. Tuy nhiên, SPF chỉ xác thực “máy chủ gửi có được phép không”, chứ không đảm bảo email là an toàn hay không bị chiếm tài khoản.

<br>

## Q8. Perform a DMARC lookup for the Return-Path domain found in the email headers. What is the complete DMARC record for this domain?

DMARC (Domain-based Message Authentication, Reporting & Conformance) là cơ chế giúp domain kiểm soát cách xử lý email giả mạo dựa trên kết quả **SPF** và **DKIM**.

Với **domain**:
 
![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-27-00-02-32.png)

**v=DMARC1; p=quarantine; fo=1**

có thể hiểu ngắn gọn như sau:
•	v=DMARC1: đây là bản ghi DMARC. 
•	p=quarantine: nếu email **fail DMARC**, hệ thống nhận nên **đưa vào spam/quarantine** thay vì inbox hoặc reject hoàn toàn. 
•	fo=1: tạo báo cáo khi **SPF hoặc DKIM fail** (ít nhất một trong hai thất bại).

<br>

## Q9. What is the file name of the attachment found in the email?

Email này có một attachment đi kèm, chúng ta có thể tải về và xem hash của nó
 
![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-27-00-03-17.png)

![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-27-00-03-24.png)
 
File này có tên là: **SWT_#09674321____PDF__.CAB**

<br>

## Q10. Using the sha256sum command, what is the SHA256 hash of the file?

Chỉ cần dùng câu lệnh sha256sum trong linux là chúng ta có thể biết được hash
 
Hash: **2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f**

<br>

## Q11. Investigate the file hash from the previous question using VirusTotal (opens in new tab). What is the attachment's file size in KB (e.g., 122.31 KB)?


Để biết được file này nặng bao nhiêu KB, chúng ta có thể sử dụng Threat Intelligence Platform như VirusTotal.

Không chỉ biết dung lượng của file, trang này cung cấp nhiều thông tin khác như họ malware, file dropped, behaviour,…

![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-27-00-05-01.png)
 
VirusTotal cho kết quả file .CAB được 50/63 **security vendor analysis** đánh dấu là **malware**. Được gán nhãn họ malware như **msil, loki, agensla**

Để biết được dung lượng file như yêu cầu của câu hỏi, hãy qua tab **Details**
 
![](/assets/img/posts/2026-06-26-Email-Analysis/2026-06-27-00-05-27.png)

Như vậy, file này có dung lượng là: **400.26 KB**

<br>

## Q12. Continue your research on the file. What is the actual file type of the attachment?

Dựa vào hình ảnh trên, để ý phần **File Type** có ghi là RAR.

Vậy thực chất file này là loại file **.RAR** chứ không phải .CAB như ban đầu.

<br>

## Tổng kết

Qua bài lab này, chúng ta đã thực hiện phân tích một email có dấu hiệu phishing từ nhiều góc độ như **header analysis, SPF, DKIM, DMARC, IP tracing** và kiểm tra file đính kèm. Kết quả cho thấy email có nhiều dấu hiệu bất thường như sai lệch **thông tin người gửi,** cấu hình xác thực **domain** và file đính kèm bị **nghi ngờ độc hại**. Từ đó có thể rút ra rằng việc kết hợp kiểm tra **authentication** **(SPF, DKIM, DMARC)** cùng với phân tích nội dung và file là rất quan trọng để phát hiện email phishing và giảm thiểu rủi ro tấn công vào người dùng trong thực tế.

