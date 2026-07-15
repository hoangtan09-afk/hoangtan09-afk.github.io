---
title: "Squid Game"
date: 2026-07-14 00:00:00 +07000
categories: [Forensics]

---

## Bối cảnh & Mở đầu

**Will you survive the Squid Games?**

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-08-46.png)

<br>

Bài lab về bộ phim **Squid Game** nổi tiếng. Đề bài chỉ cho một file jpg đơn giản

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-09-40-41.png)

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-09-41-10.png)

<br>

## Q1: What is the phone number on the invitation card in Squid Game?

Những ai biết về bộ phim này thì đi kèm với tấm thẻ mời sẽ có số điện thoại liên quan đính kèm. Để trả lời câu hỏi này, chỉ cần dùng công cụ tìm kiếm online là sẽ ra

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-09-44-23.png)

**Answer: 8650 4006**

<br>

## Q2: Can you extract something from the invitation card file? What is the name of the file?

Ở câu hỏi này, đề bài cung cấp file Invitation Card.jpg và yêu cầu kiểm tra xem bên trong ảnh có giấu file nào khác hay không.

Đầu tiên, mình kiểm tra file bằng một số công cụ cơ bản:

```bash
file "Invitation Card.jpg" 
binwalk "Invitation Card.jpg" 
strings -a "Invitation Card.jpg" | less
```

Tuy nhiên, các lệnh trên không phát hiện được file nhúng nào đáng chú ý. Mình cũng thử **zsteg**, nhưng công cụ này chủ yếu hoạt động hiệu quả với ảnh PNG hoặc BMP, trong khi file cần phân tích lại là JPG.

Vì vậy, mình chuyển sang sử dụng **StegSeek** để kiểm tra xem ảnh có chứa dữ liệu được giấu bằng **steghide** hay không:

```bash
stegseek --seed "Invitation Card.jpg"
```

Kết quả nhận được:

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-05-19.png)


Kết quả này cho thấy bên trong file JPG có một **payload** dung lượng khoảng **1 MB**. **Payload** đã được nén và mã hóa bằng thuật toán **Rijndael-128** ở chế độ **CBC**.

Chuỗi **00a02111** chỉ là seed được sử dụng trong quá trình nhúng dữ liệu, không phải mật khẩu giải mã. Vì vậy, mình vẫn cần tìm **passphrase** để trích xuất file.

Ở câu hỏi số 1, mình đã tìm được dãy số:

**8650 4006**

Dãy số này chính là manh mối để mở file được giấu trong ảnh. Khi nhập **passphrase**, mình bỏ khoảng trắng và sử dụng:

**86504006**

Sau đó, mình dùng **steghide** để trích xuất payload:

```bash
steghide extract -sf "Invitation Card.jpg" -p "86504006"
```

Lệnh chạy thành công và trả về một file **PNG**:

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-11-31.png)

Tên file PNG được trích xuất chính là đáp án của câu hỏi.

**Answer: Dalgona.png**

<br>

## Q3: What hint text can be discovered in the final file?

Sau khi trích xuất thành công file **Dalgona.png** từ ảnh **Invitation Card.jpg**

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-17-48.png)

Mình tiếp tục kiểm tra xem trong ảnh PNG này có thông tin nào bị ẩn hay không.


Khi mở ảnh theo cách thông thường, mình không thấy nội dung đáng chú ý. Tuy nhiên, vì đây là một file PNG trong bài **steganography**, dữ liệu có thể được giấu trong các **bit plane** hoặc từng kênh màu của ảnh.

Để kiểm tra, mình sử dụng công cụ **StegSolve**:

```bash
java -jar stegsolve.jar
```

Sau khi **StegSolve** được mở, mình chọn: **File → Open → Dalgona.png**


Tiếp theo, mình sử dụng các nút mũi tên ở phía dưới để lần lượt xem ảnh qua nhiều chế độ khác nhau như:

- Red plane
- Green plane
- Blue plane
- Alpha plane
- Các bit plane từ 0 đến 7

Sau khi chuyển qua các lớp màu và bit plane, một đoạn văn bản ẩn bắt đầu xuất hiện rõ ràng trên ảnh. Đây chính là hint mà câu hỏi yêu cầu tìm.

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-18-29.png)

**Answer: red pixel**

Như vậy, StegSolve giúp tách các lớp dữ liệu màu của ảnh và làm hiện ra phần văn bản không thể quan sát được khi mở Dalgona.png theo cách thông thường.

<br>

## Q4: What is the final flag?

Từ câu hỏi số 3, mình tìm được hint:

**red pixel**

Gợi ý này cho thấy dữ liệu của flag có thể được giấu trong giá trị màu đỏ (**Red channel**) của các **pixel** trong ảnh **Dalgona.png.**

Để kiểm tra chi tiết từng pixel, mình sử dụng công cụ **PixSpy** và tải file **Dalgona.png** lên. Sau đó, mình phóng to ảnh cho đến khi nhìn thấy một **đường pixel** rất nhỏ được xếp theo chiều dọc ở cạnh bản đồ.

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-29-57.png)

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-30-15.png)

Mình lần lượt nhấp vào từng **pixel** từ trên xuống dưới. PixSpy hiển thị **giá trị màu** của mỗi pixel theo định dạng:

**(R, G, B)**

Ví dụ:

(123, 34, 45)

(102, 51, 70)

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-32-29.png)

> Lưu ý: mỗi lần click một pixel thì giá trị mới sẽ nhảy lên đầu. Sau khi click toàn bộ pixel cần thiết thì đọc theo chiều từ dưới lên trên
{: .prompt-info }


Vì hint là **red pixel**, mình chỉ lấy **giá trị đầu tiên**, tức là giá trị của kênh **Red**. Sau khi thực hiện với toàn bộ **đường pixel**, mình thu được dãy số:

```bash
123 102 124 173 123 64 166 63 137 115 171 64 156 155 64 162 137 107 165 171 65 175
```

Điểm đáng chú ý là tất cả các số trên chỉ chứa **chữ số từ 0 đến 7**. Đây là dấu hiệu cho thấy chúng có thể được biểu diễn dưới dạng hệ bát phân – **Octal**.

Mình đưa dãy số vào công cụ **Cipher Identifier** trên **dcode.fr**. Công cụ xác định đây là dữ liệu **Octal ASCII**.

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-36-12.png)

 Khi chuyển từng số từ hệ bát phân sang ký tự ASCII, ta có:

- 123 (Octal) = S
- 102 (Octal) = B
- 124 (Octal) = T
- 173 (Octal) = {

Hoặc dùng luôn công cụ **ASCII Code Converter** của **dcode.fr** cho khỏe

![](/assets/img/posts/2026-07-14-Squid-Game/2026-07-15-10-37-36.png)

Sau khi giải mã toàn bộ dãy số, mình thu được flag cuối cùng

**Answer: SBT{S4v3_My4nm4r_Guy5}**

<br>

## Tổng kết

Sau khi hoàn thành bài lab Squid Game, mình rút ra được một số kinh nghiệm quan trọng trong quá trình phân tích **steganography**:

- Biết cách kiểm tra một file ảnh có chứa dữ liệu ẩn hay không bằng các công cụ như **binwalk**, **zsteg**, **StegSeek**, **Steghide** và **StegSolve**.
- Hiểu rằng mỗi **định dạng ảnh** sẽ phù hợp với những công cụ khác nhau, ví dụ **StegSeek** và **Steghide** phù hợp với **JPG**, còn **zsteg** thường hiệu quả hơn với **PNG**.
- Biết cách phát hiện và trích xuất file được giấu bên trong một ảnh bằng **passphrase**.
- Biết tận dụng kết quả của câu hỏi trước làm **manh mối** cho câu hỏi sau, thay vì phân tích từng file một cách riêng lẻ.
- Biết sử dụng **StegSolve** để kiểm tra các **kênh màu** và **bit plane** nhằm tìm nội dung ẩn trong ảnh.
- Hiểu cách đọc giá trị **RGB** của từng pixel bằng **PixSpy** và lựa chọn đúng kênh màu dựa trên hint.
- Biết nhận diện một dãy số có thể thuộc **hệ bát phân** và chuyển đổi **Octal ASCII** để tìm ra nội dung cuối cùng.
- Quan trọng nhất, bài lab giúp mình rèn luyện **tư duy quan sát**, thử nghiệm nhiều hướng khác nhau và kết hợp nhiều công cụ để giải quyết một bài steganography **nhiều lớp**.

Qua bài lab này, mình nhận ra rằng dữ liệu ẩn không phải lúc nào cũng được phát hiện bằng **một lệnh duy nhất**. Việc lựa chọn **đúng công cụ**, chú ý đến từng **chi tiết nhỏ** và **liên kết các manh mối** là yếu tố quan trọng để đi đến **flag** cuối cùng.
