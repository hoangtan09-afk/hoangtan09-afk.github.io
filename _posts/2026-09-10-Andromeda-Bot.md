---
title: "Andromeda Bot (Vietnamese Write Up)"
date: 2026-09-10 00:00:00 +07000
categories: [Forensics]
---

Phân tích bản sao bộ nhớ và logs bằng **MemProcFS**, **EvtxECmd**, và **Timeline Explorer** để xác định các IOC của **Andromeda Bot**, dựng lại chuỗi thời gian bị nhiễm, và liên kết các thuộc tính đó đến nhóm APT.

<br>

## Scenario

As a member of the DFIR team at SecuTech, you're tasked with investigating a security breach affecting multiple endpoints across the organization. Alerts from different systems suggest the breach may have spread via removable devices. You’ve been provided with a memory image from one of the compromised machines. Your objective is to analyze the memory for signs of malware propagation, trace the infection’s source, and identify suspicious activity to assess the full extent of the breach and inform the response strategy.

<br>

Bối cảnh đã cho chúng ta thấy mã độc có vẻ đã được lây lan thông qua các thiết bị rời cụ thể ở đây là USB. Mục tiêu bây giờ là phân tích bộ nhớ để truy tìm các dấu hiệu lây lan của mã độc, truy ngược lại nguồn gốc của nó và xác định nhóm APT nào đã lợi dụng loại mã độc này cho chiến dịch tấn công.

<br>

## Nạp kết xuất bộ nhớ với MemProcFS

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-13-24-16.png)

Mình được cho một file memory image như thế này. Việc đầu tiên cần làm là phải nạp kết xuất bộ nhớ (memory dump) để bắt đầu quá trình phân tích. Để thực hiện việc này, mình sử dụng công cụ **MemProcFS** được đề cập ở đầu đề bài.

Để nạp file bộ nhớ với công cụ **MemProcFS** mình chạy câu lệnh sau:

```bash
memprocfs.exe -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\memory.dmp"
```

Giải thích câu lệnh:
- `memprocfs.exe` là tệp thực thi của MemprocFS, có nhiệm vụ tải tệp bộ nhớ
- `-f` xác định tệp bộ nhớ mà chúng ta cần nạp vào, chính là file tên `memory.dmp`

Lệnh này sẽ tốn một ít thời gian để chạy vì một phần mình đang thực hiện trong môi trường từ xa, đợi đến khi nào nó xuất hiện như này thì lệnh đã chạy xong

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-13-40-17.png)

Để rõ hơn, ta có thể thấy một ổ cứng ảo `M:\` xuất hiện trên **File Explorer**

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-13-41-19.png)

Làm xong bước này, mình đã có thể truy cập và thao tác với các file bên trong như một ổ cứng bình thường, điều này giúp việc điều tra dễ dàng hơn rất nhiều

## Theo dấu thiết bị USB (USB Tracking)

Căn bản thì bước base đã xong. Bối cảnh ở trên nhắc đến việc mã độc được lây nhiễm thông qua thiết bị USB, việc theo dõi số sê-ri của thiết bị USB là rất quan trọng để xác định các thiết bị có khả năng không được phép sử dụng trong sự cố, giúp truy xuất nguồn gốc và thu hẹp phạm vi điều tra. 

Số sê-ri của USB mặc định sẽ được lưu trong registry (đối với hệ điều hành **Windows**), cụ thể ở đường dẫn  `HKLM\SYSTEM\ControlSet001\Enum\USBStor`. Mình sẽ lần theo đường dẫn này trong ổ **M** được tạo ra bởi **MemprocFS**

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-13-48-28.png)

Bên trong folder `Disk&Ven...` chứa các folder số **sê-ri** của USB đã được cắm vào máy 

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-13-49-59.png)

Vậy ở đây số **sê-ri** của USB đã được cắm vào máy là: **7095411056659025437&0**

Tìm được số sê-ri của USB rồi thì nên tìm cái gì tiếp? Việc theo dõi hoạt động của thiết bị USB là rất cần thiết để xây dựng dòng thời gian của sự cố, qua đó cung cấp điểm khởi đầu cho quá trình phân tích. Vậy mình cần tìm thời gian gần nhất mà USB này được cắm vào thiết bị là khi nào. 

Từ registry key chứa serial number của USB, mình tiếp tục vào folder tên `Properties`. Tại đây có khá nhiều thư mục mang tên GUID, mỗi GUID đại diện cho mỗi thuộc tính và thông tin khác nhau liên quan đến USB

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-13-53-46.png)

Đối với timestamp liên quan đến thiết bị, được cắm vào hay tháo khỏi hệ thống thì GUID cần quan tâm là

```text
{83da6326-97a6-4088-9453-a1923f573b29}
```

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-13-58-32.png)

Bên trong GUID này có một số thư mục quan trọng:

```text
0064 → Install Date
0065 → First Install Date
0066 → Last Arrival Date
0067 → Last Removal Date
```

Với mục tiêu là xác định thời gian gần nhất mà USB này được cắm vào thiết bị, mình truy cập vào thư mục **0066**

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-02-36.png)

Tiếp tục vào file `(_Key_).txt` để xem thông tin thời gian bên trong

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-03-17.png)

Vậy mình đã xác định được lần gần nhất USB này được cắm vào thiết bị là: **2024-10-04 13:48:18 UTC**

<br>

## Thu thập và phân tích Event Logs

Việc xác định đường dẫn đầy đủ của tệp thực thi cung cấp bằng chứng quan trọng để truy xuất nguồn gốc cuộc tấn công và hiểu cách thức mã độc được triển khai. Tại thư mục `misc\eventlog` có chứa rất nhiều eventlog (evtx), đây chính là "mỏ vàng" cho các defenders

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-09-04.png)

Nhưng để như vậy thì việc phân tích sẽ trở nên vô cùng khó khăn bởi các event log không được xếp theo một trình tự khoa học mà chúng đang nằm rải rác. Thật may là ta có thể kết hợp hai công cụ đã đề cập là `EvtxECmd` và `Timeline Explorer`

Để tạo một cái nhìn tổng quan về các log này, mình thực hiện lệnh sau

```bash
EvtxECmd.exe.lnk -d M:\misc\eventlog --csv "C:\Users\Administrator\Desktop\Start Here\Artifacts"
```

Giải thích lệnh:
- `EvtxECmd.exe.lnk` là công cụ phân tích cú pháp log của **Eric Zimmerman**, được sử dụng để tạo ra một file event log mà chúng ta dùng để phân tích
- `-d` chỉ định thư mục mà các event logs được lưu, ở đây là `M:\misc\eventlog`. Bằng cách này, chúng ta sẽ gom tất cả các event logs thành một file, điều này sẽ làm việc phân tích dễ hơn nhiều
- `--csv` nói rằng kết quả đầu ra là file định dạng csv chứa các event logs

Sau khi chạy lệnh, nếu hiển thị như thế này thì lệnh đã chạy thành công

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-19-05.png)

File đầu ra của mình chính xác là như này

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-20-27.png)

Bây giờ mình mở `TimelineExplorer` để import file .csv đầu ra ở trên vào, điều này cung cấp cho ta một cái bảng trực quan về toàn bộ event log, giúp ta dễ dàng theo dõi và trích xuất hơn

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-24-46.png)

Tại đây mình quyết định kiểm tra Sysmon Event ID 1, đó là Process Creation. Điều này có thể tiết lộ **Windows Defender** bị tắt, cũng như là file mã độc được khởi tạo

Sau khi lọc được Event ID 1, mình để ý ở cột **Excutable Info** có một dòng thể hiện đặc trưng của hành động tắt **Windows Defender**

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-31-55.png)

Khi điều tra máy đầu cuối trong một doanh nghiệp, hành động tắt Windows Defender là hành động dấy lên nghi vấn cao và cần phải giám sát chặt chẽ cũng như điều tra kỹ toàn bộ hành vi sau đó. Và ngay ở trên thôi mình đã thấy ngay một dòng log thể hiện một file PE kỳ lạ được khởi chạy

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-33-18.png)

Tại đây mình xác định được đường dẫn đầy đủ của tệp thực thi được chạy sau khi các lệnh PowerShell vô hiệu hóa các tính năng bảo vệ của Windows Defender là: `E:\hidden\Trusted Installer.exe`

<br>

## Phân tích mã độc và trích xuất IOC (Indicators of Compromise)

Việc xác định cơ sở hạ tầng C&C của mã độc bot là yếu tố then chốt để phát hiện các IOC. Ở bước này, mình tập trung tìm các báo cáo threat intelligence về tệp kỳ lạ này, đồng nghĩa với việc chúng ta cần biết mã hash của tệp `Trusted Installer.exe`

Ở cùng dòng log chứa `Trusted Installer.exe`, kéo qua bên trái một chút ở cột **Payload Data3** ta có thể thấy mã hash của tệp này

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-45-14.png)

SHA256 HASH: **9535a9bb1ae8f620d7cbd7d9f5c20336b0fd2c78d1a7d892d76e4652dd8b2be7**

Mình tra cứu hash này trên nền tảng threat intelligence phổ biến như VirusTotal và được kết quả như hình

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-46-12.png)

Kết quả cho thấy tệp tin này bị 57 trong số 68 nhà cung cấp giải pháp bảo mật đánh dấu là mã độc, cho thấy khả năng cao đây là một mối đe dọa. Nó có liên quan đến nhiều dòng mã độc, bao gồm `Gamarue`, `NSIS` và `Andromeda` — tất cả đều được biết đến với vai trò hỗ trợ các Trojan truy cập từ xa (RAT) và mạng botnet. Các dòng mã độc này thường được sử dụng để thiết lập kênh liên lạc điều khiển và ra lệnh (C&C) nhằm phục vụ việc vận hành từ xa và đánh cắp dữ liệu

Mình tiếp tục xem ở mục **Network Communication** thì thấy mã độc đã giao tiếp với nhiều domain lạ, sau một lúc tra cứu thì mình kết luận được URL mà con bot đã sử dụng liên quan đến C&C

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-14-58-49.png)

URL: **hxxp[://]anam0rph[.]su/in[.]php**

## Phân tích hành vi Dropped File của mã độc

Việc hiểu rõ các chỉ số thỏa hiệp (IOC) đối với các tập tin do mã độc tạo ra là rất cần thiết để nắm bắt thông tin về các giai đoạn khác nhau của mã độc cũng như quy trình thực thi của nó. Ở bước này mình có để ý dòng log như hình dưới

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-15-09-23.png)

Ở đây minh chứng cho việc sau khi mã độc `Trusted Installer.exe` được khởi chạy, mã độc này đã tạo ra một file độc hại khác có tên `Sahofivizu.exe` hoặc nói cách khác đây là hành vi **Dropped file**

Mình cũng xác định được mã hash MD5 của file này ở cùng dòng: **7FE00CC4EA8429629AC0AC610DB51993**

Việc có được đường dẫn tệp đầy đủ cho phép thực hiện quy trình dọn dẹp triệt để hơn, đảm bảo rằng tất cả các thành phần độc hại đều được xác định và loại bỏ khỏi các vị trí bị ảnh hưởng. Mình muốn kiểm tra xem liệu có file DLL nào được drop bởi malware không, tiến hành filter event ID **11** (File Create)

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-15-20-30.png)

Sau khi filter event ID 11, mình thấy có xuất hiện không chỉ một mà là nhiều file DLL được drop bởi mẫu malware `Trusted Instsaller.exe` ban đầu. Và thời điểm bắt đầu có hành vi drop các file DLL này lúc **2024-10-04 13:49:53**. Điều này cùng cố rằng ngoài các file PE, chúng ta cần phải diệt và loại bỏ nốt toàn bộ các file khác có liên quan đến các mẫu PE mã độc ban đầu, chẳng hạn ở đây là toàn bộ file DLL như hình trên

<br>

## Xác định nguồn gốc cuộc tấn công (Attribution - APT Turla)

Trong lĩnh vực an ninh mạng, việc xác định nguồn gốc tấn công (attribution) là quá trình liên kết một cuộc tấn công mạng hoặc hoạt động mã độc cụ thể với một tác nhân đe dọa hoặc nhóm Tấn công Bền vững Nâng cao (APT) nhất định. Quá trình này bao gồm việc phân tích các chỉ số kỹ thuật—chẳng hạn như cơ sở hạ tầng, đặc điểm mã độc, cũng như các chiến thuật, kỹ thuật và quy trình (TTP)—và đối chiếu chúng với các tác nhân đe dọa đã được xác định. Việc xác định nguồn gốc giúp làm rõ động cơ, năng lực và mục tiêu đằng sau các cuộc tấn công, từ đó cho phép các tổ chức ứng phó hiệu quả và tăng cường khả năng phòng thủ trước những mối đe dọa trong tương lai.

![](/assets/img/posts/2026-09-10-Andromeda-Bot/2026-09-10-15-28-41.png)

Trong cuộc điều tra này, các báo cáo về tình báo mối đe dọa tiết lộ rằng nhóm `APT Turla` đã tái kích hoạt mã độc Andromeda để sử dụng trong các chiến dịch của mình. Turla – còn được biết đến với tên gọi Snake hoặc Venomous Bear – là một nhóm APT do nhà nước Nga hậu thuẫn, nổi tiếng với việc thực hiện các hoạt động gián điệp mạng nhắm vào các lĩnh vực chính phủ, quân sự và quốc phòng. Báo cáo nhấn mạnh rằng Turla đã tận dụng các tên miền điều khiển và ra lệnh (C2) của Andromeda vốn đã hết hạn; họ đăng ký lại các tên miền này để thu thập thông tin về nạn nhân và triển khai có chọn lọc các loại mã độc bổ sung – chẳng hạn như KOPILUWAK và QUIETCANARY – trong quá trình thực hiện chiến dịch.

Mã độc Andromeda, vốn lan rộng vào đầu những năm 2010, thường được sử dụng để phát tán lây nhiễm qua các ổ đĩa USB. Trong trường hợp này, nhóm Turla đã chiếm quyền kiểm soát cơ sở hạ tầng của Andromeda để chuyển đổi mục đích sử dụng sang hoạt động gián điệp, qua đó thể hiện khả năng tùy biến các công cụ cũ cho những chiến dịch mới. Điều này nhấn mạnh tầm quan trọng của việc giám sát các tên miền đã hết hạn và các hệ thống mã độc cũ, bởi tin tặc có thể lợi dụng chúng để tạo bàn đạp xâm nhập vào các mạng lưới mục tiêu.

<br>

## Kết luận

Qua bài lab này, quá trình điều tra số và phân tích mã độc đã được thực hiện bằng cách kết hợp nhiều công cụ và kỹ thuật khác nhau, cụ thể:

- **Khởi tạo và mount ảnh bộ nhớ:** Sử dụng công cụ **MemProcFS** để giả lập kết xuất bộ nhớ thành một ổ đĩa ảo, giúp dễ dàng phân tích và truy xuất thông tin hệ thống (files, registry, logs).
- **Phân tích thiết bị ngoại vi:** Lợi dụng **Registry** (`HKLM\SYSTEM\ControlSet001\Enum\USBStor`) để trích xuất số sê-ri và định vị mốc thời gian thiết bị USB (nguồn lây nhiễm nghi ngờ) được cắm vào máy.
- **Trích xuất và phân tích Event Logs:** Sử dụng **EvtxECmd** kết hợp với **Timeline Explorer** để parse các Event Logs nằm rải rác thành bảng phân tích trực quan. Từ đó, sử dụng tính năng lọc để phát hiện các hoạt động bất thường qua Sysmon (Event ID 1, Event ID 11).
- **Phân tích hành vi mã độc:** Nhận diện việc vô hiệu hóa Windows Defender, phát hiện tiến trình độc hại (`Trusted Installer.exe`), và các hành vi Dropped File đi kèm (như sinh ra các tệp `Sahofivizu.exe` và các tệp DLL).
- **Thu thập Threat Intelligence & Attribution:** Lấy mã hash của các tệp nghi ngờ để đối chiếu trên **VirusTotal**, định danh dòng mã độc (Andromeda Bot), tìm ra cơ sở hạ tầng điều khiển C&C và cuối cùng là liên kết các hành vi này với chiến dịch tái sử dụng mã độc Andromeda của nhóm **APT Turla**.










