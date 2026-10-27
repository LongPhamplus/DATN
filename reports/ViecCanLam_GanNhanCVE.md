# Việc tác giả cần làm: gán nhãn vai trò CVE (việc 2.3, để sau)

*Ghi ngày 2026-10-27. Trạng thái: **chưa làm**, tác giả sẽ làm sau.*

## 1. Bối cảnh

Nhóm V gán CVE thật cho các máy theo **vai trò** của CVE trong attack graph. Vai trò được suy từ vector CVSS bằng quy tắc `aapef/roles.py` thay cho chọn tay. Cần biết quy tắc đúng đến đâu, nên phải đối chiếu với phân loại của người trên một mẫu.

Đã có (commit `fe27f4a`):
- `reports/role_sample.csv`: 80 CVE lấy mẫu có seed 1 từ snapshot `2026-10-27:2f4796fced2f`, gồm 40 thuộc KEV và 40 ngoài KEV. Các nhãn hiện có do một agent AI gán **mù**: chỉ đọc mô tả NVD, không thấy vector, không biết quy tắc. Cột `labeller` = `claude-subagent-blind`.
- `reports/role_sample_guide.md`: định nghĩa 5 nhãn và quy tắc khi phân vân.
- Kết quả đối chiếu (nhãn AI so với quy tắc):

| Đo | Tỉ lệ khớp |
|---|---|
| Quy tắc hiện tại, cả 80 CVE | 45% (36/80) |
| Bỏ 32 CVE nhãn `other` | 75% (36/48) |
| Quy tắc + bộ lọc "C:H và I:H mới là cho quyền truy cập" | 71% (57/80) |

**Vì sao cần tác giả làm:** nhãn AI chưa phải phân loại của người, và bộ lọc C:H/I:H được tìm ra trên chính mẫu này nên con số 71% có thể quá lạc quan. Hội đồng có thể hỏi "ai phân loại, có độc lập không".

## 2. Việc A: kiểm tra lại nhãn của mẫu 1 (`reports/role_sample.csv`)

**Mục tiêu:** có nhãn của người cho mẫu 1; đo mức đồng ý giữa người và AI.

**Các bước:**
1. Sao file: `reports/role_sample.csv` → `reports/role_sample_T.csv`. Trong bản sao, **xóa cột `manual_role`, `labeller` và `reason`** để không bị ảnh hưởng bởi nhãn AI, rồi thêm lại cột `manual_role` trống.
2. Với từng dòng: mở `nvd_url`, **chỉ đọc phần "Description"**; không nhìn khung CVSS bên phải. Điền `manual_role` theo `reports/role_sample_guide.md`.
3. Chấm khớp với quy tắc:
   `python scripts/role_sample.py score reports/role_sample_T.csv`
4. So nhãn của bạn với nhãn AI. Đếm số dòng giống nhau; nếu có thể, tính Cohen's kappa. Ghi kết quả vào mục 5 bên dưới.

**Thời gian ước tính:** khoảng 1–2 phút mỗi CVE, tức 1,5–2,5 giờ cho 80 dòng. Nếu không đủ thời gian, làm **tối thiểu 20 dòng mơ hồ** ở mục 4.

**Ví dụ cách gán (lấy từ mẫu):**

| CVE | Mô tả nói gì (rút gọn) | Nhãn | Vì sao |
|---|---|---|---|
| CVE-2026-6973 | "remotely authenticated user with administrative access achieves RCE" | `lateral` | qua mạng nhưng **cần tài khoản** |
| CVE-2024-8755 | "Authenticated User … OS Command Injection" | `lateral` | như trên |
| CVE-2025-24200 | "a physical attack may disable USB Restricted Mode" | `other` | tấn công vật lý, không cho quyền truy cập qua mạng |
| CVE-2024-5977 | "authenticated attackers … delete and update arbitrary posts" | `other` | chỉ sửa dữ liệu, không chiếm máy |
| CVE-2024-51503 | "execute low-privileged code first, then escalate privileges" | `privesc` | đã có quyền trên máy, leo thang |
| CVE-2022-30333 | "directory traversal during an extract (unpack) operation" | `client-side` | cần người dùng giải nén tệp |

## 3. Việc B: mẫu thứ hai để kiểm tra bộ lọc (khi có thời gian)

**Mục tiêu:** kiểm tra bộ lọc C:H/I:H trên dữ liệu chưa dùng để tìm ra nó (tránh "học thuộc" mẫu 1).

1. Sinh mẫu mới (seed khác, không trùng mẫu 1):
   `python scripts/role_sample.py draw --n 80 --seed 2 --out reports/role_sample_2.csv`
2. Gán nhãn như việc A (người gán; hoặc nhờ C chạy agent mù như mẫu 1 rồi bạn kiểm tra lại).
3. Chấm: `python scripts/role_sample.py score reports/role_sample_2.csv`. Tỉ lệ khớp của "quy tắc + bộ lọc" trên mẫu 2 mới là con số được báo cáo trong luận văn. (C cần thêm tùy chọn chấm có bộ lọc vào script khi bộ lọc được chốt.)

## 4. Các dòng AI đánh dấu là mơ hồ (ưu tiên kiểm tra)

Số thứ tự là số dòng dữ liệu (không tính dòng tiêu đề). Nhãn AI chọn ghi trước.

| # | CVE | Phân vân giữa | Lý do |
|---|---|---|---|
| 3 | CVE-2010-5330 | initial-access / lateral | không rõ có cần tài khoản |
| 6 | CVE-2023-26540 | privesc / lateral | chỉ ghi "Privilege Escalation" |
| 9 | CVE-2024-30866 | initial-access / other | SQL injection, không rõ hậu quả |
| 12 | CVE-2025-66644 | initial-access / lateral | không rõ có cần tài khoản |
| 15 | CVE-2024-5049 | initial-access / lateral | upload vào đường dẫn admin/ |
| 17 | CVE-2021-39935 | other / initial-access | SSRF không xác thực |
| 24 | CVE-2025-24200 | other / privesc | tấn công vật lý |
| 28 | CVE-2015-4902 | other / client-side | "unknown vectors" |
| 31 | CVE-2011-2462 | initial-access / client-side | thực thi mã từ xa, không nói cần người dùng |
| 40 | CVE-2024-34658 | other / privesc | vượt ASLR cục bộ |
| 46 | CVE-2022-30333 | client-side / initial-access | ghi tệp khi giải nén |
| 49 | CVE-2010-3765 | client-side / initial-access | JavaScript/frame; **AI gán không nhất quán với #31** |
| 57 | CVE-2024-5977 | other / lateral | sửa bài viết |
| 63 | CVE-2024-38796 | initial-access / other | lỗi bộ nhớ từ mạng kề |
| 67 | CVE-2024-21415 | initial-access / client-side | mô tả chỉ là tiêu đề "RCE" |
| 72 | CVE-2024-21723 | client-side / other | open redirect |
| 74 | CVE-2021-26411 | other / client-side | mô tả chỉ là tiêu đề "Memory Corruption" |
| 75 | CVE-2024-51503 | privesc / lateral | vừa cục bộ vừa có tấn công qua mạng |
| 78 | CVE-2024-44133 | privesc / other | vượt cài đặt quyền riêng tư |
| 79 | CVE-2024-5040 | other / initial-access | directory traversal, không rõ hậu quả |

## 5. Kết quả (điền khi làm xong)

| Mục | Giá trị |
|---|---|
| Số dòng tác giả đã gán | |
| Khớp tác giả với AI | / |
| Khớp tác giả với quy tắc | / |
| Khớp tác giả với quy tắc + bộ lọc | / |
| Quy tắc được chốt | |

## 6. Ảnh hưởng nếu chưa làm

Việc này **không chặn** phần mã: nhóm N không dùng CVE, và bộ chạy thí nghiệm vẫn chạy được. Nó chặn việc **chốt quy tắc gán CVE cho nhóm V**: quy tắc gán nên lấy CVE theo vai trò **và** loại các CVE không cho quyền truy cập (bộ lọc), nên cần biết bộ lọc có đáng tin không.
