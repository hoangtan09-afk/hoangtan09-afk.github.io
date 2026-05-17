---
title: "File Recovery"
date: 2026-05-17 00:00:00 +07000
categories: [Lab]

---

**Introduce: Đây là bài lab mô phỏng case thực tế cách các chuyên viên forensics khôi phục các file, evidence đã bị xóa bằng FTK Imager và Autopsy. Cùng mình nhập vai vào các chuyên gia pháp y số nhé.**


===============================================================================================

<br>
Mình có tạo một phân vùng ổ đĩa (Z:) chỉ 250MB để cho tiện nhằm phục vụ cho môi trường lab học tập. Trong thực tế thì các chuyên gia sẽ đọc toàn bộ dung lượng của các ổ quan trọng như C hoặc D….

![pic1](/assets/img/posts/FileRecovery/pic1.png)
 
Trong ổ Z mình sẽ tiến hành tạo hai file, hai file này đóng vai trò giả lập như các file bằng chứng quan trọng nào đó

![pic2](/assets/img/posts/FileRecovery/pic2.png)
 
Nội dung của các file lần lượt như hai hình dưới
 
 ![pic3](/assets/img/posts/FileRecovery/pic3.png)
 
 ![pic4](/assets/img/posts/FileRecovery/pic4.png)

Bây giờ, hãy tưởng tượng một hacker đã hack được vào máy này và xóa đi 2 file quan trọng này. Giả sử mình là hacker, mình sẽ xóa 2 file này theo 2 cách

Mình sẽ xóa file 1 bằng cách chỉ đơn thuần nhấn delete, tức là file này sẽ bay vào recycle bin
 
![pic5](/assets/img/posts/FileRecovery/pic5.png)

File 2 mình sẽ xóa vĩnh viễn bằng cách giữ phím shift sau đó nhấn delete
 
![pic6](/assets/img/posts/FileRecovery/pic6.png)

Lúc này ổ đĩa đã trống không
 
![pic7](/assets/img/posts/FileRecovery/pic7.png)

Đây là lúc chúng ta sẽ là chuyên viên phân tích pháp y số! Chúng ta phải bằng mọi cách khôi phục được các file đã bị xóa để phục vụ việc điều tra

Với các chuyên viên pháp y số, họ sẽ không thao tác/điều tra trực tiếp trên ổ đĩa máy đối tượng. Thay vào đó họ sẽ tạo một bản copy của ổ đĩa, đưa bản copy đó vào thiết bị di động (ổ cứng rời, usb,…) và đem về phòng Lab để tiến hành điều tra.

Chúng ta cũng sẽ follow procedures y như vậy. Đầu tiên hãy tạo một bản copy của ổ Z bằng **FTK Imager**

![pic8](/assets/img/posts/FileRecovery/pic8.png)

Chọn Logical Drive

![pic9](/assets/img/posts/FileRecovery/pic9.png)

Chọn ổ cần copy

![pic10](/assets/img/posts/FileRecovery/pic10.png)

Chọn định dạng .dd

![pic11](/assets/img/posts/FileRecovery/pic11.png)
 
Phần đặt tên, cho hồ sơ điều tra thì đặt tên gì cũng được. Sau đó click Next

![pic12](/assets/img/posts/FileRecovery/pic12.png)
 
Chọn thư mục đầu ra của file và đặt tên cho file

![pic13](/assets/img/posts/FileRecovery/pic13.png)
 
Về lại đây thì click Start

![pic14](/assets/img/posts/FileRecovery/pic14.png)
 
Sau khi xong thì chúng ta được các mã hash như hình. Theo mình đây là thông tin quan trọng cần lưu lại, vì mã hash được dùng để **kiểm tra tính toàn vẹn** của file. Các bạn nên lưu lại và cất ở nơi dễ tìm.

![pic15](/assets/img/posts/FileRecovery/pic15.png)
 
File copy của ổ đĩa sẽ như thế này nếu bạn follow các bước trên và thành công. File này thì không mở được bằng cách thông thường. 

Chúng ta sẽ dùng **Autopsy** để mở, một công cụ forensics phục vụ việc điều tra các file ổ đĩa và bằng chứng.

![pic16](/assets/img/posts/FileRecovery/pic16.png)

Chọn New Case sau đó đặt tên

![pic17](/assets/img/posts/FileRecovery/pic17.png) 

Tại đây, trỏ đến file copy của ổ đĩa ban đầu lúc nãy, click Next

Giao diện chính của **Autopsy**:

![pic18](/assets/img/posts/FileRecovery/pic18.png)
 
Trong này có khá nhiều mục hay ho mà mình muốn giới thiệu với các bạn, chẳng hạn khi click vào mục **Timeline**

![pic19](/assets/img/posts/FileRecovery/pic19.png)
 
Trong đây ghi lại các mốc thời gian có sự kiện thay đổi bên trong ổ đĩa

Khi qua tab List, ta sẽ thấy toàn bộ log thời gian về các event như tạo, truy cập, chỉnh sửa, xóa file. Tất nhiên sẽ có các file chúng ta đã tạo và xóa ở đầu bài lab.

![pic20](/assets/img/posts/FileRecovery/pic20.png)

File SECRET được tạo vào lúc 22:16, SUPER SECRET được tạo vào lúc 22:17:

![pic21](/assets/img/posts/FileRecovery/pic21.png)

Truy cập file vào lúc 22:18:

![pic22](/assets/img/posts/FileRecovery/pic22.png) 

Và tương tự như vậy cho các sự kiện khác như **modified**, **file changed**,… đều được ghi lại một cách đầy đủ. Cho nên bất cứ thao tác gì trên ổ đĩa cũng đều bị log lại và được theo dõi sát sao. Và **Autopsy** giúp chúng ta quan sát các log này một cách đầy đủ, trực quan nhất.

<br>
<br>

Mình sẽ chỉ điểm khác biệt giữa hai cách xóa file ở đầu bài, để ý hình sau đây giúp mình:

![pic23](/assets/img/posts/FileRecovery/pic23.png)
 
File SECRET lúc đầu chỉ xóa theo kiểu cho vào recycle bin, nên chúng ta vẫn còn thấy file SECRET còn xuất hiện ở dưới, được báo là đang ở trong **/$RECYCLE.BIN/**

![pic24](/assets/img/posts/FileRecovery/pic24.png)
 
Phần nội dung giống với nội dung chúng ta đã ghi vào file trước đó.

<br>

Khác với file SECRET, SUPER SECRET được xóa kiểu vĩnh viễn, cho nên sau sự kiện Modified của SUPER SECRET chúng ta sẽ không còn thấy nó nữa.
 
![pic25](/assets/img/posts/FileRecovery/pic25.png)

**Vậy làm sao để khôi phục 2 file này?**

Trở về giao diện chính Autopsy, bạn sẽ muốn xem trong mục Deleted Files
 
![pic27](/assets/img/posts/FileRecovery/pic27.png)
 
Vào file system

![pic28](/assets/img/posts/FileRecovery/pic28.png)


**Đây chính là các bằng chứng chúng ta cần khôi phục**

![pic29](/assets/img/posts/FileRecovery/pic29.png)
![pic30](/assets/img/posts/FileRecovery/pic30.png)
 
Nội dung đúng chính xác với những gì chúng ta làm ban đầu.

Để khôi phục thật sự, right-click và chọn extract files
 
![pic31](/assets/img/posts/FileRecovery/pic31.png)
![pic32](/assets/img/posts/FileRecovery/pic32.png)
 
Mình sẽ đưa về lại vị trí ban đầu

![pic33](/assets/img/posts/FileRecovery/pic33.png)
![pic34](/assets/img/posts/FileRecovery/pic34.png)
 
 
Như vậy chúng ta đã thành công khôi phục file bị xóa và hoàn thành trách nhiệm của một chuyên viên forensics (file còn lại cách làm cũng tương tự).

<br>

Nếu các bạn đã theo dõi đến đây, hy vọng bài lab này sẽ khơi dậy niềm đam mê và tinh thần tò mò của các bạn. Mình rất mong muốn được chia sẻ thêm nhiều kỹ thuật nữa trong giới Forensics đến các bạn! Cảm ơn các bạn đã dành thời gian đọc và làm theo, chúc các bạn một ngày tốt lành!




