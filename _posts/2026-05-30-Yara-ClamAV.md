---
title: "Detecting Malware with YARA & ClamAV"
date: 2026-05-30 00:00:00 +07000
categories: [Malware Analysis]

---

Chào mọi người, hôm nay chúng ta sẽ làm quen với Phòng Lab Phân tích Mã độc. Cụ thể, chúng ta sẽ tập trung vào việc phát hiện mã độc bằng các quy tắc Yara và ClamAV. Hãy bắt đầu.

<br>

**1. Cài đặt và chuẩn bị mẫu**
 
![pic1](/assets/img/posts/Yara_ClamAV/pic1.png)

Vì mình đã cài đặt ClamAV trước đó, nên mình chỉ cần chạy lệnh `sudo freshclam` để cập nhật cơ sở dữ liệu virus cho ClamAV.

![pic2](/assets/img/posts/Yara_ClamAV/pic2.png)
 

Tiến hành tạo các tệp văn bản chứa các chuỗi mã độc mô phỏng.

![pic3](/assets/img/posts/Yara_ClamAV/pic3.png)
![pic4](/assets/img/posts/Yara_ClamAV/pic4.png)
 

Xem mã hex của tệp bằng `xxd`.

![pic5](/assets/img/posts/Yara_ClamAV/pic5.png)
 

`xxd` giúp xem **nội dung thực tế** của một tệp ở định dạng hex — rất hữu ích để phát hiện các ký tự ẩn, viết chữ ký diệt virus và phân tích pháp y.

**2. Phân tích cơ sở dữ liệu ClamAV**

Trích xuất & Vị trí & Giải nén
 
![pic6](/assets/img/posts/Yara_ClamAV/pic6.png)
![pic7](/assets/img/posts/Yara_ClamAV/pic7.png)
 

mình đã trích xuất nó trước đó. mình sẽ tiếp tục tìm quy tắc trong cơ sở dữ liệu như sau. Để làm việc đó, trước tiên mình sẽ **clamscan** một thư mục chứa **mã độc** để xem quy tắc nào được trả về trong kết quả:
 
![pic8](/assets/img/posts/Yara_ClamAV/pic8.png)

mình đã quét thành công và tìm thấy **Win.Packed.Malwarex-10059342-0**.

Tiến hành tìm quy tắc này trong cơ sở dữ liệu.

![pic9](/assets/img/posts/Yara_ClamAV/pic9.png)
 
mình thấy quy tắc này nằm bên trong tệp **daily.ldb**.

Giải mã Hex sang ASCII

![pic10](/assets/img/posts/Yara_ClamAV/pic10.png)
 
Có vẻ đây là mã byte (mã máy), tạo ra các ký tự mà chúng ta vẫn chưa thể đọc. mình sẽ dùng **ndisasm** để giải mã nó thành **Assembly**.

![pic11](/assets/img/posts/Yara_ClamAV/pic11.png)
 
Sau khi nghiên cứu trực tuyến một thời gian, mình hiểu được **chức năng** của các đoạn **Assembly** này. Cụ thể:

Những dòng **Assembly** này thuộc về **Packer/Stub** (mã khởi động) của mã độc. Mục đích chính là **tự giải mã** để giải nén phần thân độc hại vào bộ nhớ nhằm trốn tránh phát hiện bởi AV.

**Tóm tắt các lệnh:**
- **insd, pusha:** Dùng để lấy địa chỉ thực thi và giữ nguyên trạng thái các thanh ghi trước khi giải mã.
- **cs pop ecx:** Một kỹ thuật chuyển đổi ngữ cảnh bộ nhớ để truy cập dữ liệu nén.
- **sub ah, [eax+0x45], das:** Đây là thuật toán giải mã (thường là phép trừ hoặc XOR) để khôi phục mã máy gốc từ dữ liệu bị làm rối.

Nói cách khác: Đây là một "vỏ bảo vệ" giúp mã độc ẩn mình trên ổ cứng và chỉ lộ ra khi được thực thi trong bộ nhớ.


**3. Tạo chữ ký tùy chỉnh**

Tạo tệp `mywildcard.ndb` bằng cú pháp: `Malware_Name:Target:Offset:Hex_String`

![pic12](/assets/img/posts/Yara_ClamAV/pic12.png)
 

**Việc tạo tệp .ndb phục vụ 3 mục đích chính:**

**1. Phát hiện mã độc mới:** Cung cấp cho ClamAV "chữ ký" của một loại mã độc mới mà cơ sở dữ liệu mặc định của hệ thống vẫn chưa có.

**2. Kiểm soát chủ động:** Cho phép mình định nghĩa các quy tắc quét tùy chỉnh riêng để phát hiện các tệp đáng ngờ trong môi trường Lab mà không ảnh hưởng đến cơ sở dữ liệu hệ thống.

**3. Nghiên cứu cấu trúc:** Giúp mình hiểu cách ClamAV phân tích và khớp các mẫu mã độc dựa trên chuỗi Hex hoặc các quy tắc logic (Logical Signatures).

Tiến hành thực hiện một lần quét thử với cơ sở dữ liệu mới tạo bằng lệnh:

**clamscan -d mywildcard.ndb test1.txt test2.txt test3.txt test4.txt test5.txt**

![pic13](/assets/img/posts/Yara_ClamAV/pic13.png)

Dựa trên kết quả, cơ sở dữ liệu tùy chỉnh mình tạo đã quét thành công 5 tệp văn bản mô phỏng được tạo ở đầu buổi lab.

Điều này có nghĩa **ClamAV** đã thực hiện thành công:

- Đã tải thành công cơ sở dữ liệu `mywildcard.ndb`
- Đã biên dịch tất cả 6/6 chữ ký
- Đã quét các tệp kiểm tra
- Đã phát hiện các tệp khớp với các chữ ký tùy chỉnh mình viết
- Tiền tố `.UNOFFICIAL` là bình thường, vì đây là **chữ ký tùy chỉnh** mình tạo, không phải chữ ký chính thức từ ClamAV.

Bây giờ mình sẽ trích xuất 08 mẫu chữ ký từ cơ sở dữ liệu ClamAV để phân tích:

**- 4 mẫu đầu tiên:** mình sẽ dùng `xxd` để dịch Hex sang ASCII.

**- 4 mẫu cuối:** mình sẽ dùng `ndisasm` để giải mã Hex thành Bytecode (Assembly), sau đó dùng AI để phân tích hành vi.

<br>
<br>

<span style="font-size: 16px; color: #87CEEB">**Dịch sang ASCII**</span>
<br>

mình chạy lệnh sau để trích xuất **04 mẫu đầu tiên** từ **main.ndb** và **daily.ndb** trước:

**grep -E '^[^:]+:[0-9]+:[^:]+:[0-9A-Fa-f]+$' main.ndb daily.ndb \ | grep -iE '68747470|2e657865|2e646c6c|6d6163726f|736372697074|766273|706f7765727368656c6c|636d642e657865|4d6963726f736f6674|436f64654d6f64756c65' \ | head -n 4 > ascii_4.txt**

Lệnh mình chạy ưu tiên lọc các chữ ký có thể được dịch sang ASCII mà không hiển thị mã máy.

![pic14](/assets/img/posts/Yara_ClamAV/pic14.png)
 
Bây giờ mình tiến hành dịch sang ASCII cho từng loại:

<br>

**main.ndb:Doc.Trojan.Nori-1**

![pic15](/assets/img/posts/Yara_ClamAV/pic15.png)
 
**Ý nghĩa của chữ ký này:**

Thông qua quá trình điều tra, mình tin rằng đây có vẻ là **một đoạn mã macro VBA trong tài liệu Office độc hại**. Các chỉ dấu chính:

- **CodeModule.Lines(2, 1):** truy cập các dòng mã trong module VBA.

- **Components.Item(...):** thao tác các thành phần/macro bên trong dự án VBA.

- **<> "'Iron" Then:** câu lệnh điều kiện kiểm tra xem nội dung dòng mã có khác chuỗi `'Iron` hay không.

Có khả năng đây là một chữ ký dùng để phát hiện mã macro tự kiểm tra/tự sửa đổi, thường thấy trong mã độc macro dùng để **ẩn mã, tự sửa đổi macro hoặc kiểm tra dấu hiệu nhiễm.**

<br>

**main.ndb:Win.Trojan.Dialer-1**

![pic16](/assets/img/posts/Yara_ClamAV/pic16.png)
 
**Ý nghĩa của chữ ký này:**

mình nhận thấy chữ ký này có nhiều byte không đọc được, nhưng vẫn có một số IOC/chuỗi đáng chú ý có thể nhìn thấy:

- http://...
- .exe
- Software\Web...
- Passw...
- Exit

Sự hiện diện của các chuỗi `http://...` và `.exe`: có khả năng liên quan đến **tải xuống tệp thực thi từ URL** hoặc xác định các mẫu có hành vi **tải payload**.

`Software\Web...`: gợi ý liên quan đến **đường dẫn Registry hoặc cấu hình phần mềm trên Windows**.

`Passw...`: có thể liên quan đến chuỗi "Password", thường thấy trong **mã độc đánh cắp thông tin**, nhưng phần này khá nhiễu nên mình không thể kết luận chắc chắn.

Nhiều ký tự bị hỏng/không đọc được: đây không phải chuỗi ASCII thuần túy, mà là một mẫu byte được ClamAV dùng để xác định mã độc.

<br>

**main.ndb:Win.Trojan.GWGirl-1**

![pic17](/assets/img/posts/Yara_ClamAV/pic17.png)
 
**Ý nghĩa của chữ ký này:**

Chữ ký đã giải mã:

.com

DXInput.dll

G2h7o2st_Event

\SCANREGW.EXE

- **.com:** có thể liên quan đến các tệp thực thi cũ theo kiểu DOS hoặc một miền, nhưng vì nó đứng riêng lẻ nên mình chưa thể kết luận.
- **DXInput.dll:** Một DLL giả mạo giống như thư viện hệ thống hoặc thư viện nhập liệu trò chơi, có khả năng được dùng để ngụy trang.
- **G2h7o2st_Event:** Một chuỗi có cấu trúc giống tên sự kiện hoặc mutex, thường được dùng để xác định một phiên bản hoặc đồng bộ hóa tiến trình.
- **\SCANREGW.EXE:** Một tên tệp giống công cụ Windows cũ SCANREGW.EXE, có thể bị mã độc lợi dụng để ngụy trang.

Kết luận: Chữ ký này cho thấy dấu hiệu phát hiện mã độc dựa trên DLL đáng ngờ, tên sự kiện/mutex và các tệp EXE hệ thống bị giả mạo, nhưng chưa đủ để kết luận về hành vi cụ thể.

<br>

**main.ndb:Win.Trojan.DeltaV1-1**

![pic18](/assets/img/posts/Yara_ClamAV/pic18.png)
 
**Ý nghĩa của chữ ký này:**
Chữ ký này giải mã thành một chuỗi có thể đọc được một phần:

**.com**

**Delta v1.0 by Retro**

**http:/**

- **"*.com"**: có thể liên quan đến các tệp thực thi .com theo phong cách DOS, hoặc các mẫu mã độc nhiễm vào tệp .com.
- **"Delta v1.0 by Retro"**: giống như một chuỗi nhận dạng hoặc tên nội bộ của mã độc hoặc công cụ để lại bởi tác giả.
- **http:/**: gợi ý về một thành phần URL, nhưng chuỗi bị cắt ngắn nên chưa đủ để xác định C2 hoặc liên kết tải xuống.
- **Phần đầu tiên** chứa nhiều byte nhị phân và các đoạn giống như lệnh DOS/assembly, nên đây không phải là ASCII thuần túy mà là một mẫu byte để phát hiện mã độc.

**Kết luận:** Chữ ký này rất có khả năng được dùng để phát hiện một mẫu mã độc/virus cũ liên quan đến các tệp .com, chứa chuỗi nhận dạng "Delta v1.0 by Retro", nhưng chưa đủ dữ liệu để kết luận về hành vi cụ thể.

<br>

<span style="font-size: 16px; color: #87CEEB">**Dịch sang Bytecode (Assembly)**</span>

<br>
Ở bước tiếp theo, mình sẽ trích xuất **04 mẫu chữ ký còn lại** để dịch sang bytecode bằng lệnh:

**grep -h -E '^[^:]+:[0-9]+:[^:]+:[0-9A-Fa-f]+$' main.ndb daily.ndb \ | grep -viE 'trojan|nori|layla' \ | head -n 4 > asm_4.txt**

mình dùng lệnh này để lọc ra 04 mẫu khác **không chứa Trojan và không chứa Nori/Layla**.

![pic19](/assets/img/posts/Yara_ClamAV/pic19.png)


Tiến hành giải mã thành bytecode cho từng loại:

<br>
**Win.Worm.Gaobot-1**
 
![pic20](/assets/img/posts/Yara_ClamAV/pic20.png)

**Ý nghĩa của chữ ký này:**

Khi được giải mã thành assembly, chữ ký này cho thấy **nhiều lệnh thao tác trực tiếp** với **các thanh ghi** và **khu vực bộ nhớ**, chẳng hạn:

**xor al,0x67**

**and [edx+0x2ddc0d83],dl**

**mov cl,[eax+0x45907da4]**

**or [ebx+0x73254089],dl**

**jz 0x5a**

**jnc 0x93**

**jnz 0x77**

- `xor al,0x67`: thực hiện phép XOR trên thanh ghi AL, có thể liên quan đến xử lý/chuyển đổi dữ liệu. 
- Các lệnh như `and`, `or`, `sub`, `cmp`: các phép toán logic và so sánh dữ liệu trong bộ nhớ. 
- Các lệnh nhảy như `jz`, `jnc`, `jnz`: cho thấy việc rẽ nhánh điều kiện trong luồng thực thi. 
- Một số byte được nhận diện thành các chuỗi riêng như `.com`, `quit`, `cac`, cho thấy chữ ký có thể đang bắt một mẫu chứa cả byte mã máy lẫn chuỗi văn bản.

**Kết luận ngắn:**

Chữ ký này mô tả một mẫu byte chứa thao tác thanh ghi, truy cập bộ nhớ và các lệnh rẽ nhánh điều kiện. Nó có thể được ClamAV dùng để xác định một mẫu mã độc dựa trên **đặc điểm cấp byte**, bao gồm cả các dấu hiệu liên quan đến tệp `.com` và các chuỗi lệnh rời rạc như `quit`.

<br>

**Win.Worm.Bormex-1**

![pic21](/assets/img/posts/Yara_ClamAV/pic21.png)
 
**Ý nghĩa của chữ ký này:**

- **inc ebx, adc, add, xor, sub, and, or**: các lệnh thao tác dữ liệu ở mức **thanh ghi/bộ nhớ**.

- **push dword [esp+0x8]**: đẩy một tham số vào ngăn xếp, có thể liên quan đến gọi hàm hoặc xử lý dữ liệu.

- **test eax,eax + jz:** kiểm tra kết quả trong eax, rồi nhảy nếu bằng 0.

- **jmp word 0x8313:**dword 0xee05a19d: một lệnh nhảy xa, thường thấy trong các mẫu byte phức tạp hoặc mã bị làm rối.

- **int byte 0x78:** kích hoạt một ngắt, có thể là dấu hiệu của mã cấp thấp hoặc một chuỗi byte đặc biệt.

- **loopne:** vòng lặp điều kiện, cho thấy khả năng lặp qua dữ liệu.

**Kết luận ngắn:**
Chữ ký này mô tả một mẫu byte với nhiều thao tác trên thanh ghi, bộ nhớ, ngăn xếp và các nhánh điều kiện. Nó có thể được ClamAV dùng để xác định mã có xử lý dữ liệu phức tạp hoặc bị làm rối ở cấp byte. Tuy nhiên, chưa có API hoặc chuỗi rõ ràng nào hiện ra, nên chưa đủ để kết luận về hành vi cụ thể.

<br>

**Vbs.Tool.Svbsvc-1**

![pic22](/assets/img/posts/Yara_ClamAV/pic22.png)


**Ý nghĩa của chữ ký này:**

Khi được giải mã thành assembly, chữ ký này cho thấy nhiều lệnh thao tác thanh ghi, so sánh và nhảy điều kiện.

**Ý nghĩa chính:**

- **inc, dec, xor, and, sub, cmp:** các lệnh xử lý dữ liệu và so sánh giá trị.

- **jg, jz, jno, jnc, jng:** nhiều lệnh nhảy điều kiện, cho thấy mẫu có cấu trúc rẽ nhánh.

- **push, pop, popa:** thao tác ngăn xếp và thanh ghi.

- **outsb, insd, insb:** các lệnh I/O cấp thấp, thường xuất hiện trong mẫu byte hoặc mã máy chuyên dụng.

**Kết luận ngắn:**

Chữ ký này là một mẫu byte với nhiều phép logic, thao tác ngăn xếp và nhảy điều kiện. Nó có thể được ClamAV dùng để xác định mã có cấu trúc phức tạp hoặc bị chỉnh sửa ở cấp byte. Tuy nhiên, không thấy API, URL hay chuỗi rõ ràng nào, nên chưa đủ để suy ra hành vi mã độc cụ thể.

<br>

**Win.Ircbot.Netol-1**

![pic23](/assets/img/posts/Yara_ClamAV/pic23.png)
 
**Ý nghĩa của chữ ký này:**

Khi giải mã, chữ ký này thực chất là một **chuỗi Unicode UTF-16LE**, không phải mã máy thuần túy. Nếu đọc như văn bản, nó gần như là:

**elseif  ($exists(c:\netol.scr**

- **elseif:** cú pháp điều kiện, thường thấy trong script.
- **$exists(...):** kiểm tra sự tồn tại của tệp/đường dẫn. 
- **c:\netol.scr:** kiểm tra tệp **.scr** trên ổ C. Tệp **.scr** là screensaver, nhưng thực chất là tệp thực thi của Windows, thường bị mã độc lợi dụng để che giấu payload.

Khi đưa vào **ndisasm**, nó bị giải mã sai thành các lệnh như:

**add [gs:eax+eax+0x73],ch**

**imul eax,[eax],0x200066**

**cmp al,[eax]**

Những lệnh này không có ý nghĩa hành vi rõ ràng vì ndisasm đang hiểu sai chuỗi UTF-16LE thành assembly.

**Kết luận ngắn:**

Chữ ký này rất có khả năng được dùng để phát hiện một đoạn script/mã độc kiểm tra sự tồn tại của tệp **c:\netol.scr**, trong đó **.scr** là định dạng dễ bị khai thác để che giấu các tệp thực thi độc hại.

<br>

<span style="font-size: 20px; color: #87CEEB">**Phần 2: Viết quy tắc YARA**</span>


<br>
Để tiến hành viết quy tắc Yara, trước tiên mình cần cài Yara. mình đã chạy các lệnh sau để cài đặt:

**Sudo apt update**

**Sudo apt install git yara -y**
 
mình đã cài đặt thành công Yara, phiên bản 4.5.5


![pic25](/assets/img/posts/Yara_ClamAV/pic25.png)


Tiếp theo, mình sẽ clone kho lưu trữ The Zoo về máy:

**git clone https://github.com/ytisf/theZoo.git**
 
![pic26](/assets/img/posts/Yara_ClamAV/pic26.png)

Tiếp theo, chúng ta đến phần quan trọng: viết 10 quy tắc YARA.

<br>

**Quy tắc 1: Xác định các tệp PE**

![pic27](/assets/img/posts/Yara_ClamAV/pic27.png)
 
**Giải thích:**

- **Chức năng:** Xác định các tệp thực thi Windows ở định dạng PE.

- **Chữ ký:** Các tệp PE thường bắt đầu bằng MZ, với một header PE bên trong.
- **Điều kiện khớp:** $mz phải ở đầu tệp (offset 0) và $pe phải xuất hiện.
- **Ý nghĩa:** Dùng để lọc các tệp có cấu trúc như tệp thực thi Windows.

<br>

**Quy tắc 2: Xác định các API keylogger**

![pic28](/assets/img/posts/Yara_ClamAV/pic28.png)

**Giải thích:**

- **Chức năng:** Phát hiện các dấu hiệu keylogger.

- **Chữ ký:** Các API liên quan đến ghi nhận phím và theo dõi cửa sổ đang hoạt động.

- **Điều kiện khớp:** Ít nhất 2 trong 3 chuỗi API phải xuất hiện.
- **Ý nghĩa:** Nếu một tệp sử dụng nhiều API này, có khả năng nó đang theo dõi phím và hoạt động của người dùng.

<br>

**Quy tắc 3: Xác định các API tiêm tiến trình**

![pic29](/assets/img/posts/Yara_ClamAV/pic29.png)

 
**Giải thích:**

- **Chức năng:** Phát hiện các dấu hiệu tiêm tiến trình.

- **Chữ ký:** Các API thường dùng để mở tiến trình, cấp phát bộ nhớ, ghi mã độc vào tiến trình khác và tạo remote thread.

- **Điều kiện khớp:** Ít nhất 2 API phải xuất hiện.

- **Ý nghĩa:** Đây là hành vi phổ biến của mã độc để ẩn mã trong các tiến trình hợp pháp.

<br>

**Quy tắc 4: Xác định các API kết nối mạng**
 
![pic30](/assets/img/posts/Yara_ClamAV/pic30.png)

**Giải thích:**

- **Chức năng:** Phát hiện các tệp có dấu hiệu giao tiếp mạng.

- **Chữ ký:** Các API dùng để mở kết nối Internet, gửi yêu cầu HTTP hoặc tải tệp xuống.

- **Điều kiện khớp:** Ít nhất 2 chuỗi API phải xuất hiện.

- **Ý nghĩa:** Có thể liên quan đến việc tải payload, giao tiếp C2 hoặc rò rỉ dữ liệu.


<br>

**Quy tắc 5: Dấu hiệu thực thi lệnh hệ thống**
 
![pic31](/assets/img/posts/Yara_ClamAV/pic31.png)

**Giải thích:**

- **Chức năng:** Xác định hành vi thực thi lệnh hệ thống.

- **Chữ ký:** cmd.exe, powershell, /c, ShellExecute.

- **Điều kiện khớp:** Chỉ cần một trong các chuỗi xuất hiện.

- **Ý nghĩa:** Mã độc thường dùng dòng lệnh để chạy script, tải tệp, thiết lập tính bền vững hoặc thực thi payload.

<br>

**Quy tắc 6: Xác định tính bền vững qua Registry**

![pic32](/assets/img/posts/Yara_ClamAV/pic32.png)
 
**Giải thích:**

- **Chức năng:** Phát hiện các dấu hiệu bền vững thông qua Registry.

- **Chữ ký:** Các khóa Registry như Run, HKCU, HKLM, hoặc các API ghi Registry.

- **Điều kiện khớp:** Ít nhất một chuỗi phải xuất hiện.

- **Ý nghĩa:** Mã độc có thể dùng Registry để tự chạy sau khi hệ thống khởi động.


<br>

**Quy tắc 7: Xác định các tệp PE có entropy cao, bị nén**

![pic33](/assets/img/posts/Yara_ClamAV/pic33.png)

**Giải thích:**

- **Chức năng:** Xác định các tệp PE có khả năng bị nén hoặc mã hóa.

- **Chữ ký:** Entropy toàn tệp cao.

- **Điều kiện khớp:** Tệp phải là PE, kích thước > 50KB và entropy > 7.2.

- **Ý nghĩa:** Các tệp bị nén thường có entropy cao vì dữ liệu được nén/mã hóa để che giấu mã thật.


<br>

**Quy tắc 8: Xác định các phần mở rộng thường bị mã độc khai thác**

![pic34](/assets/img/posts/Yara_ClamAV/pic34.png)
 
**Giải thích:**

- **Chức năng:** Xác định các phần mở rộng tệp thường bị khai thác.

- **Chữ ký:** .scr, .vbs, .bat, .ps1, .dll.

- **Điều kiện khớp:** Ít nhất 2 phần mở rộng phải xuất hiện.

- **Ý nghĩa:** Mã độc có thể tạo hoặc gọi các script/tệp thực thi phụ trợ để thực thi hành vi độc hại.


<br>

**Quy tắc 9: Xác định chuỗi mutex hoặc event**

![pic35](/assets/img/posts/Yara_ClamAV/pic35.png)
 
**Giải thích:**

- **Chức năng:** Phát hiện các dấu hiệu mutex/event.

- **Chữ ký:** Global\, Local\, CreateMutex, _Event.

- **Điều kiện khớp:** Chỉ cần một chuỗi xuất hiện.

- **Ý nghĩa:** Mã độc thường dùng mutex để ngăn không cho nhiều phiên bản chạy đồng thời hoặc để đánh dấu máy đã bị nhiễm.



<br>

**Quy tắc 10: Xác định chữ ký PE khi MZ không ở đầu tệp**

![pic36](/assets/img/posts/Yara_ClamAV/pic36.png)

**Giải thích:**

- **Chức năng:** Xác định các tệp có PE được nhúng bên trong.

- **Chữ ký:** MZ và PE đều có mặt, nhưng MZ không ở đầu tệp.

- **Điều kiện khớp:** Cả $mz và $pe đều có mặt, và $mz không ở offset 0.

- **Ý nghĩa:** Tệp có thể chứa một payload PE được nhúng, thường thấy ở các dropper/loader.

<br>

**10 quy tắc mình viết được thiết kế theo nhiều nhóm hành vi khác nhau: nhận diện PE, API keylogger, tiêm tiến trình, API mạng, thực thi lệnh, bền vững qua Registry, tệp PE có entropy cao, phần mở rộng đáng ngờ, mutex/event và PE được nhúng. Mặc dù không một quy tắc nào có thể kết luận chắc chắn một tệp là độc hại, nhưng chúng giúp phát hiện các dấu hiệu đáng ngờ cho phân tích tĩnh.**

<br>

Tiếp theo, mình tiến hành quét thư mục The Zoo đã clone bằng lệnh:

**yara -r custom_rules.yar theZoo**

![pic37](/assets/img/posts/Yara_ClamAV/pic37.png) 
 
Như hình trên cho thấy, các quy tắc mình viết đã khớp với nhiều mẫu mã độc.

Cụ thể, đầu ra cho thấy các quy tắc như **Rule_05_Command_Execution, Rule_08_Suspicious_File_Extensions, Rule_10_Dropped_PE_Inside_File, Rule_01_PE_File, và Rule_06_Registry_Persistence** đã khớp với nhiều tệp .zip, .pyd, .db, cũng như các tệp trong thư mục .git của The Zoo.


<br>


**Rule_05_Command_Execution**

Quy tắc này khớp nhiều nhất. Nó phát hiện các chuỗi như:

- **cmd.exe**

- **powershell**

- **/c**

- **ShellExecute**

Nhiều tệp mã độc trong The Zoo chứa các dấu hiệu thực thi lệnh hệ thống, nên quy tắc này đã khớp với nhiều mẫu như **WannaCry_Plus, Petrwrap, Fareit, Zeus, QuasarRAT, PowerLoader**, v.v. Tuy nhiên, quy tắc này khá rộng và có thể gây dương tính giả, vì nó cũng khớp với `theZoo/conf/maldb.db`.


<br>


**Rule_08_Suspicious_File_Extensions**

Quy tắc này phát hiện các phần mở rộng tệp đáng ngờ như:

- **.scr**

- **.vbs**

- **.bat**

- **.ps1**

- **.dll**

Nó khớp với nhiều tệp nguồn mã độc như **njRAT, LokiRAT, AsyncRAT, QuasarRAT, Carberp**, v.v. 
Điều này hợp lý vì mã nguồn mã độc thường chứa các script, DLL hoặc phần mở rộng dùng để drop/thực thi payload.


<br>


**Rule_10_Dropped_PE_Inside_File**

Quy tắc này khớp với:

- **Android.CEREBRUS 2.zip.001**

- **Android.CEREBRUS 2.zip.002**

Quy tắc này tìm kiếm sự hiện diện của **MZ** và **PE** trong trường hợp **MZ** không ở đầu tệp. Điều này cho thấy tệp có thể chứa một PE được nhúng hoặc một mẫu byte có dạng PE. Đối với các tệp .zip.001/.002, rất có khả năng các archive này chứa payload PE hoặc một mẫu byte có dạng PE.

<br>

**Rule_01_PE_File**

Quy tắc này chỉ khớp với:

- **theZoo/imports/_rlsetup.pyd**

.pyd thực chất là một module extension của Python trên Windows, thường có cấu trúc PE tương tự như .dll. Vì vậy, việc quy tắc PE khớp là bình thường.

<br>

**Rule_06_Registry_Persistence**

Quy tắc này khớp trong:

- **theZoo/.git/objects/pack/...**

Đây không phải là mẫu mã độc trực tiếp mà là một tệp pack của Git. Sự khớp này có thể là do đối tượng Git chứa nội dung lịch sử/nội dung nguồn với các chuỗi Registry như HKCU, HKLM hoặc Software\Microsoft\Windows\CurrentVersion\Run. Vì vậy, phần này cần được ghi nhận là một dương tính giả tiềm năng do việc quét toàn bộ thư mục .git.


<br>

<span style="font-size: 20px; color: #87CEEB">**Phần 3: YARA thực hành - Phát hiện các kỹ thuật giả mạo**</span>

<br>

**Chọn kịch bản A (Extension Spoofing - dùng module magic) hoặc B (.NET Malware - dùng module dotnet).**

Ở đây, mình chọn kịch bản **A Extension Spoofing** để triển khai.

mình sẽ tạo một tệp giả mạo có phần mở rộng `.txt` nhưng lại chứa header EXE.

![pic38](/assets/img/posts/Yara_ClamAV/pic38.png) 

 
Đầu tệp có `4D 5A`, đây là số byte ma thuật của tệp PE.


Bây giờ mình sẽ viết một quy tắc Yara để phát hiện **extension spoofing**:

![pic39](/assets/img/posts/Yara_ClamAV/pic39.png) 
 
Quy tắc này dùng để phát hiện **extension spoofing**: tệp trông giống như `.txt` bên ngoài, nhưng bên trong chứa các dấu hiệu của một tệp thực thi Windows.

- **$mz = { 4D 5A }**: tìm các byte ma thuật MZ. Dấu hiệu này thường xuất hiện ở đầu các tệp .exe Windows.
- **$pe = "PE"**: tìm chuỗi "PE", thường xuất hiện trong header PE của các tệp thực thi Windows.
- **condition:** $mz at 0 and $pe: quy tắc chỉ khớp khi: 

- **MZ** nằm ở đầu tệp (offset 0); 

- và chuỗi **PE** có mặt trong tệp.


**Ý nghĩa:**

Nếu một tệp tên là `invoice.txt` có nội dung bắt đầu bằng MZ và chứa PE, thì nó không phải là tệp văn bản bình thường. Nó cho thấy dấu hiệu là một tệp thực thi Windows với phần mở rộng bị sửa đổi để đánh lừa người dùng.

Bây giờ mình sẽ dùng quy tắc này để quét tệp `.txt` được nhắc đến ở trên:

**yara spoofing_rule.yar invoice.txt**

![pic40](/assets/img/posts/Yara_ClamAV/pic40.png) 
 
**Kết quả quét cho thấy quy tắc đã khớp với điều kiện và kích hoạt thành công.**

<br>

<span style="font-size: 20px; color: #87CEEB">**Phần 4: Đánh giá và phân tích (Thảo luận)**</span>

<br>

Cả **ClamAV** lẫn **YARA** đều là các công cụ hỗ trợ phát hiện mã độc theo kiểu chữ ký, nhưng được dùng theo những cách khác nhau. ClamAV phù hợp hơn cho việc quét nhanh bằng các cơ sở dữ liệu sẵn có như **main.ndb, daily.ndb hoặc custom.ndb**. Điểm mạnh của ClamAV là dễ sử dụng, đi kèm với một cơ sở dữ liệu chữ ký rất lớn và chỉ cần chạy clamscan là có thể phát hiện các mẫu khớp. Tuy nhiên, ClamAV phụ thuộc rất nhiều vào các chữ ký tĩnh, nên rất dễ bị tránh nếu mã độc thay đổi mẫu byte, nén tệp, mã hóa chuỗi hoặc làm rối mã.

YARA linh hoạt hơn vì người phân tích có thể viết các quy tắc tùy chỉnh dựa trên nhiều tiêu chí: chuỗi, mẫu hex, API, header PE, entropy, section hoặc các điều kiện logic phức tạp. YARA phù hợp cho phân tích tĩnh, truy tìm các gia đình mã độc và phát hiện các kỹ thuật giả mạo như extension spoofing. Điểm yếu là nếu quy tắc viết quá rộng thì sẽ gây dương tính giả, còn nếu quá chặt thì dễ bỏ sót các biến thể mẫu.

Đối với các kỹ thuật đa hình, packer và obfuscation, cả hai công cụ đều có giới hạn. Vì vậy, kết quả từ ClamAV/YARA chỉ nên được xem là các chỉ báo ban đầu, cần kết hợp với phân tích tĩnh chuyên sâu và phân tích động để có kết luận chính xác.