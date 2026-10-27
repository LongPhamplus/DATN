# Hướng dẫn phân loại vai trò CVE (việc 2.3)

Mục đích: có một phân loại **độc lập với quy tắc suy từ vector** (`aapef/roles.py`) để đo tỉ lệ khớp. Người phân loại chỉ đọc **mô tả** của CVE; không xem vector CVSS, không xem quy tắc.

Câu hỏi cần trả lời cho mỗi CVE: *trong một attack graph, lỗ hổng này cho kẻ tấn công bước nào?*

| Nhãn | Khi nào chọn |
|---|---|
| `initial-access` | Kẻ tấn công từ xa, **không cần tài khoản**, khai thác một dịch vụ mạng hoặc ứng dụng lộ ra ngoài và giành được quyền truy cập hoặc thực thi mã trên máy đó (kể cả bỏ qua xác thực để vào được) |
| `lateral` | Khai thác qua mạng nhưng **cần đã có tài khoản hoặc quyền nào đó** (người dùng đã xác thực, quyền thấp), giành quyền truy cập trên máy hoặc ứng dụng đích; đây là bước đi từ máy này sang máy khác trong mạng |
| `privesc` | Kẻ tấn công **đã có quyền trên chính máy đó** (tài khoản cục bộ, chạy được mã) và lỗ hổng cho quyền cao hơn trên cùng máy (người dùng → admin/root/SYSTEM, thoát sandbox/container) |
| `client-side` | Cần **một người dùng làm gì đó**: mở tệp, bấm liên kết, vào trang web độc hại, xem email; kể cả XSS, CSRF |
| `other` | Lỗ hổng **không cho quyền truy cập** mới: chỉ từ chối dịch vụ, chỉ lộ thông tin, chỉ sửa dữ liệu nhỏ; hoặc mô tả không đủ để biết |

Quy tắc khi phân vân:
- Mô tả nêu nhiều hệ quả thì chọn theo hệ quả **cao nhất về quyền truy cập** mà kẻ tấn công đạt được.
- "Authenticated", "low-privileged user", "requires valid credentials" qua mạng → `lateral`; "local user", "local attacker" → `privesc`.
- Chỉ DoS hoặc chỉ lộ thông tin → `other`, kể cả khi khai thác từ xa không cần tài khoản.
- Không đoán theo tên sản phẩm; chỉ dựa vào mô tả.
