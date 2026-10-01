---
title: "Boss of the SOC Version 1 (2015) - Ransomware"
date: 2026-09-30 00:00:00 +07000
categories: [Forensics]
---

After the excitement of yesterday, Alice has started to settle into her new job. Sadly, she realizes her new colleagues may not be the crack cybersecurity team that she was led to believe before she joined. Looking through her incident ticketing queue she notices a “critical” ticket that was never addressed. Shaking her head, she begins to investigate. Apparently on August 24th Bob Smith (using a Windows 10 workstation named we8105desk) came back to his desk after working-out and found his speakers blaring (click below to listen), his desktop image changed (see below) and his files inaccessible.

Alice has seen this before... ransomware. After a quick conversation with Bob, Alice determines that Bob found a USB drive in the parking lot earlier in the day, plugged it into his desktop, and opened up a word document on the USB drive called "Miranda_Tate_unveiled.dotm". With a resigned sigh she begins to dig into the problem...

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-10-57.png)

<br>

Trong bài viết này, chúng ta sẽ cùng khám phá thử thách số 2 thuộc kịch bản "Boss of the SOC v1" và trải nghiệm vai trò của một chuyên viên phân tích tại Trung tâm Điều hành An ninh (SOC). Chúng ta sẽ điều tra một loạt các sự cố bảo mật, phân tích các mối đe dọa mới nổi, đồng thời tận dụng Splunk để phát hiện những dấu hiệu quan trọng cho thấy hệ thống đã bị xâm nhập (IoC). Thông qua quy trình này, mục tiêu của chúng ta là nhận diện và giảm thiểu rủi ro từ các hoạt động độc hại, qua đó thể hiện những kỹ năng thiết yếu trong lĩnh vực an ninh mạng.

<br>

## Q200: What was the most likely IPv4 address of we8105desk on 24AUG2016?

Đầu tiên filter rộng với từ khoá “we8105desk” để xem qua log liên quan có cấu trúc như thế nào

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-20-37-11.png)

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-20-43-33.png)


Nhìn sơ qua log sau khi đã filter thì đánh giá như sau:
-	Có sử dụng giao thức LDAP, thể hiện ở trong field elements, dest_port có giá trị 389 (port cho LDAP protocol)
-	Có Netlogon, một dịch vụ của Window Domain để xác thực giao tiếp giữa máy client với DC (domain controller)
-	IP nguồn 192.168.228.14 gửi yêu cầu tra cứu thông tin trong Active Directory (thể hiện qua message_type: Search Request) 

Hiểu đơn giản:
-	Client -> “Cho tôi tra cứu thông tin này trong directory”
-	DC/LDAP Server -> trả kết quả


Nhưng có một điểm là giá trị src_ip khi query “we8105desk” không nhất quán, mỗi log là mỗi giá trị src_ip khác nhau. Điều này có nghĩa hostname có thể xuất hiện trong log do máy khác truy vấn/nhắc đến nó nên src_ip sẽ lẫn. Phải tìm query khác theo event mà chính WE8105DESK tự khai báo identity của nó

Sử dụng query này:

```text
“WE8105DESK” “Netlogon” dest_port=389 message_type=”Search request”
|stats count by src_ip
|sort – count
```
Ý nghĩa:
- "WE8105DESK" → event có nhắc tới host cần tìm 
- dest_port=389 → LDAP 
- message_type="Search request" → LDAP search 
- "Netlogon" → tập trung vào request Netlogon, nơi máy tự khai báo Host/DnsHostName 
- stats count by src_ip → xem IP nào thực sự gửi các request này

nếu một src_ip lặp lại nhiều lần trong đúng loại event này thì đó là ứng viên mạnh nhất

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-20-52-45.png)

Lưu ý chỉnh thời gian đúng về với thời gian của câu hỏi

Answer: 192.168.250.100


<br>

## Q201: Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer.

Từ câu trước, máy nạn nhân được xác định có IP: **192.168.250.100**

Để tìm các Suricata alert liên quan đến Cerber và xác định signature nào xuất hiện ít nhất, sử dụng:

```text
sourcetype=suricata "192.168.250.100" event_type=alert
alert.signature="*Cerber*"
| stats count by alert.signature_id alert.signature
| sort count
```

Giải thích:
- `sourcetype=suricata`: chỉ lấy log từ Suricata IDS. 
- `"192.168.250.100"`: tập trung vào traffic liên quan đến máy bị nhiễm. 
- `event_type=alert`: chỉ lấy các event mà Suricata tạo cảnh báo. 
- `alert.signature="*Cerber*"`: chỉ giữ các signature liên quan đến Cerber ransomware. 
- `stats count by alert.signature_id alert.signature`: nhóm theo từng cặp signature ID + signature name và đếm số lần mỗi signature alert. 
- `sort count`: sắp xếp từ số lần xuất hiện thấp nhất lên cao nhất. 

Sau khi chạy query, dòng đầu tiên là Suricata signature đã phát hiện Cerber ít lần nhất.

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-20-55-05.png)

Answer: 2816763

<br>

## Q202: What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase?

Để tìm được FDQN, dựa vào sourcetype stream:dns, kết hợp địa chỉ IP victim đã bị nhiễm, và từ khoá mã độc Cerber, có được query như sau

```text
sourcetype=stream:dns "192.168.250.100" "*Cerber*"
```

Kết quả chỉ cho ra một log duy nhất, chú ý field query dưới đây

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-20-58-49.png)


Answer: cerberhhyed5frqa[.]xmfir0[.]win


## Q203: What was the first suspicious domain visited by we8105desk on 24AUG2016?

Từ câu trước, IP của máy we8105desk đã được xác định là: 192.168.250.100

Để tìm domain đáng ngờ đầu tiên mà máy này truy vấn trong ngày 24/08/2016, sử dụng DNS logs:

```text
index=botsv1 sourcetype="stream:dns" src_ip="192.168.250.100" query!="*.arpa"
| table _time src_ip dest_ip query
| sort _time
```


Giải thích:

- `sourcetype="stream:dns"`: chỉ lấy DNS traffic. 
- `src_ip="192.168.250.100"`: chỉ lấy DNS request phát sinh từ máy we8105desk. 
- `query!=\*.arpa`: loại các reverse-DNS query dạng in-addr.arpa để giảm noise. 
- `table`: hiển thị thời gian, source IP, DNS server và domain được query. 
- `sort _time`: sắp xếp theo thời gian tăng dần để tìm domain đáng ngờ xuất hiện đầu tiên. 

Sau khi đặt time range đúng ngày 24AUG2016 và xem kết quả theo timeline, domain đáng ngờ đầu tiên xuất hiện lúc khoảng 16:48:12 là:

solidaritedeproximite[.]org

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-21-03-50.png)


<br>


## Q204: During the initial Cerber infection a VB script is run. The entire script from this execution, pre-pended by the name of the launching .exe, can be found in a field in Splunk. What is the length of the value of this field?


Câu hỏi cho biết trong giai đoạn Cerber lây nhiễm ban đầu, một VBScript được chạy và toàn bộ nội dung script, kèm theo tên executable dùng để launch nó, nằm trong một field của Splunk.

Thay vì bắt đầu bằng query phức tạp, trước tiên search rộng:
```text
VBS
```

Sau đó quan sát các field bên trái, đặc biệt là field app. Trong các giá trị xuất hiện, có một event đáng chú ý với:

`C:\Windows\SysWOW64\wscript.exe`

Giá trị này chỉ xuất hiện 1 lần, nên đây là event hiếm và đáng kiểm tra kỹ hơn.

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-21-05-58.png)

Tiếp tục filter riêng event đó:
```text
VBS app="C:\\Windows\\SysWOW64\\wscript.exe"
```
Khi mở event, field ParentCommandLine chứa một command rất dài bắt đầu bằng cmd.exe và phía sau là toàn bộ nội dung VBScript được tạo/thực thi trong quá trình Cerber infection. Đây chính là field mà đề bài đang nói tới

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-21-07-17.png)


Cuối cùng tính độ dài của ParentCommandLine:
```text
VBS app="C:\\Windows\\SysWOW64\\wscript.exe"
| eval length=len(ParentCommandLine)
| table length
```

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-21-07-57.png)

Answer: 4490


<br>

## Q205: What is the name of the USB key inserted by Bob Smith?

Để tìm USB key, trước tiên search rất rộng bằng keyword:
```text
friendlyname
```
![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-21-15-55.png)

Search này chỉ trả về rất ít event, nên tiếp tục nhìn cột field bên trái và thấy source=WinRegistry là nguồn liên quan đến Windows Registry

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-21-27-49.png)

Sau đó thu hẹp:
```text
friendlyname source=WinRegistry
```


Trong event Registry, ta thấy:

**friendlyname**

**data="MIRANDA_PRI"**

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-09-30-21-29-05.png)

Ở đây friendlyname là tên của Registry value, còn data là giá trị thực tế được lưu trong value đó.

Có thể hiểu Registry entry này như:
```text
Value name : friendlyname
Data       : MIRANDA_PRI
```
Vì event nằm trong nhánh Registry liên quan đến thiết bị portable/USB, nên MIRANDA_PRI chính là friendly name của USB key

Answer: MIRANDA_PRI


<br>

## Q206: Bob Smith's workstation (we8105desk) was connected to a file server during the ransomware outbreak. What is the IPv4 address of the file server?

Đã biết IP của workstation we8105desk là: 192.168.250.100

Bắt đầu bằng query rộng:
```text
index="botsv1" src_ip=192.168.250.100
```

Sau đó nhìn field sourcetype ở cột bên trái. Trong các protocol xuất hiện có stream:smb.


![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-14-59-52.png)

Vì câu hỏi nói workstation kết nối tới file server, SMB là nguồn dữ liệu đáng quan tâm vì đây là protocol Windows thường dùng để truy cập shared folders/files qua mạng.

Tiếp tục filter:
```text
index="botsv1" src_ip=192.168.250.100 sourcetype="stream:smb"
| stats count by path
```

**stats count by path** gom các SMB event theo từng network path, giúp dễ nhìn workstation đang truy cập những share nào

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-01-46.png)

\\192.168.250.20\fileshare cho thấy we8105desk đã truy cập một file share được host trên 192.168.250.20.

Answer: 192.168.250.20

<br>

## Q207: How many distinct PDFs did the ransomware encrypt on the remote file server?

Đầu tiên, vì đã biết file server là we9041srv, ta search các event liên quan tới file PDF trên server này:

```text
index=botsv1 host=we9041srv *.pdf
```

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-03-23.png)

Sau khi xem event logs, có thể thấy field:

`Relative_Target_Name`

chứa tên/path của các file PDF trên file share.

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-04-15.png)

Tiếp theo sử dụng query chính:
```text
index=botsv1 host=we9041srv *.pdf
| stats dc(Relative_Target_Name) as TotalPDFCount
```
Query này tìm các event trong botsv1 liên quan tới file PDF trên server we9041srv.

Sau đó:

`dc(Relative_Target_Name)`

được dùng để đếm số giá trị Relative_Target_Name khác nhau, tức số file PDF unique thay vì đếm tổng số event.

Answer: 257

<br>

## Q208: The VBscript found in question 204 launches 121214.tmp. What is the ParentProcessId of this initial launch?

Câu này dựa vào log Sysmon để tìm cái process mà file mã độc VBS  khởi chạy file 121214.tmp đã được đề cập. Cứ query dựa theo field đơn giản như sau

```text
index=botsv1 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" "121214.tmp" EventID=1
```

Giải thích:

- `source="WinEventLog:Microsoft-Windows-Sysmon/Operational"`: chuyển sang log sysmon
- `EventID=1`: filter event id 1 là event khi lại tiến trình mới, command line, tiến trình cha,…
- `"121214.tmp"`: lọc file được khởi chạy

Sau khi query thu được log này, để ý 2 field được khoanh đỏ như hình dưới

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-08-01.png)


Log này nói rằng 20429.vbs là tiến trình cha, đã khởi chạy tiến trình con (tiến trình hiện tại) là 121214.tmp. Log này chứa ParentProcessId cần tìm

Answer: 3968


<br>


## Q209: The Cerber ransomware encrypts files located in Bob Smith's Windows profile. How many .txt files does it encrypt?

Theo dữ kiện câu hỏi, tiến hành lọc rộng trước
```text
index=botsv1 host=we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" *.txt
```

Sau đó quan sát các fields bên trái như `app`, `EventID`, `TargetFilename`


![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-13-09.png)

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-13-18.png)

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-13-29.png)

Có thể thấy:
- EventID=2  → 415 events
- EventID=1  → 13 events

Đồng thời TargetFilename của EventID 2 chứa rất nhiều .txt nằm trong profile Bob, ví dụ:
```text
C:\Users\bob.smith.WAYNECORPINC\Desktop\2010\Office 2010 Pro\Key.txt
C:\Users\bob.smith.WAYNECORPINC\Desktop\2010\Project 2010\Key.txt
```
Đồng thời process nổi bật là:
```text
C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{...}\osk.exe
```
Điều này cho thấy trong dataset này, dấu vết Cerber tác động lên file đang nằm chủ yếu ở Sysmon Event ID 2 — File Creation Time Changed 

Giờ hướng đơn giản là giữ đúng osk.exe, rồi chỉ lấy .txt trong profile Bob và đếm TargetFilename khác nhau:
```text
index=botsv1 host=we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" *.txt app="C:\\Users\\bob.smith.WAYNECORPINC\\AppData\\Roaming\\{35ACA89F-933F-6A5D-2776-A3589FB99832}\\osk.exe" TargetFilename="*bob.smith.WAYNECORPINC*"
| stats dc(TargetFilename)
```
- `index=botsv1` → tìm trong dataset BOTS v1.
- `host=we8105desk` → chỉ lấy log từ máy victim.
- `sourcetype=...Sysmon...` → chỉ lấy Sysmon logs.
- `*.txt + app="...\osk.exe"` → chỉ lấy các event .txt liên quan process Cerber osk.exe.
- `TargetFilename="*bob.smith.WAYNECORPINC*"` → chỉ giữ file nằm trong profile của Bob, loại mấy path như C:\Sysmon\....


![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-15-47.png)

Answer: 406

<br>

## Q210: The malware downloads a file that contains the Cerber ransomware cryptor code. What is the name of that file?

Để tìm dấu hiệu tải file, sử dụng source suricata làm source điều tra. Trước hết query rộng theo dữ kiện có được từ câu hỏi

```text
index=botsv1 sourcetype=suricata src_ip="192.168.250.100" "http.http_method"=GET 
| table _time http.hostname http.url
```

Query này chỉ cần tư duy như sau:
- Mã độc tải file ở bên ngoài ám chỉ script VBS đã khởi chạy trên máy victim 192.168.250.100
- Tải file thì HTTP method là GET
- Tạo thành table gồm các giá trị như hostname, url để tiện quan sát

![](/assets/img/posts/2026-09-30-boss-of-the-soc-ransomware/2026-10-01-15-17-13.png)

Di chuyển cho đến khi thấy domain solidaritedeproximite[.]org, đây là domain đã tìm được ở Q203. IP victim GET đến domain này để tải file mhtr.jpg. File mã độc không phải lúc nào cũng là file có thể thực thi

Answer: mhtr.jpg

<br>

## Q211: Now that you know the name of the ransomware's encryptor file, what obfuscation technique does it likely use?

Kỹ thuật giấu bất kỳ thông tin nào vào một file ảnh được gọi là steganography

Answer: steganography


<br>

## Kết luận

Qua kịch bản "Boss of the SOC v1 - Ransomware", chúng ta đã theo dấu toàn bộ quá trình lây nhiễm mã độc Cerber từ lúc khởi nguồn cho đến khi hoàn tất hành vi tàn phá. Bắt đầu từ một sự bất cẩn của người dùng (cắm USB lạ `MIRANDA_PRI` nhặt được ở bãi xe), mã độc đã thực thi một VBScript để tải xuống payload ẩn giấu tinh vi dưới vỏ bọc một file ảnh (`mhtr.jpg` - sử dụng kỹ thuật Steganography), từ đó tiến hành mã hóa hàng loạt tài liệu không chỉ trên máy trạm cá nhân mà còn lan rộng ra cả File Server của tổ chức.

Thông qua việc giải quyết các câu hỏi, chúng ta đã áp dụng và rèn luyện những kỹ năng quan trọng của một chuyên viên phân tích SOC trên nền tảng Splunk:
- **Khả năng truy vấn và tương quan log:** Kết hợp dữ liệu từ nhiều nguồn đa dạng như DNS, SMB, Windows Registry, Sysmon và Suricata IDS để bức tranh toàn cảnh về cuộc tấn công trở nên rõ ràng.
- **Truy vết quá trình thực thi:** Dựa vào ParentProcessId và Command Line trong log Sysmon để lần ra quy trình hoạt động của mã độc.
- **Nhận diện IoC (Indicators of Compromise):** Trích xuất thành công các địa chỉ IP, Domain độc hại và các kỹ thuật tấn công để làm cơ sở cho việc phòng ngự và ứng cứu sự cố.

Bài lab này một lần nữa khẳng định tầm quan trọng của hệ thống giám sát log tập trung (SIEM) trong việc phát hiện và phản ứng sớm với các mối đe dọa, đồng thời cũng là bài học đắt giá về việc nâng cao nhận thức an toàn thông tin (Security Awareness) cho người dùng cuối trong tổ chức.









