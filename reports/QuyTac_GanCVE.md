# Quy tắc gán CVE cho nhóm V (công bố trước khi chạy)

*2026-10-28. Theo quyết định của tác giả, C viết quy tắc và script này thay T (ngoại lệ cho quy ước "T viết code sinh kịch bản", giống việc gán nhãn ở `ViecCanLam_GanNhanCVE.md`). Quy tắc và các kịch bản sinh ra được commit **trước** khi chạy thí nghiệm nhóm V. Mọi thay đổi sau đó phải ghi vào nhật ký ở cuối tài liệu này và ở `ThietKe_ThiNghiem.md`.*

## 1. Mục đích
Gắn CVE thật (dữ liệu snapshot) vào cấu trúc mạng NASim của nhóm N, để so được các chính sách dùng điểm CVSS/EPSS/KEV với chính sách theo ngữ cảnh. Tham số chính là **số CVE trên mỗi chỗ lỗ hổng** `m`, vì `ThietKe_ThiNghiem.md` §12–13 cho thấy số lỗ hổng trên mỗi máy mới làm bài toán bớt suy biến.

## 2. Đầu vào
- **Cấu trúc:** 4 kịch bản nhóm N đã chốt (`small`, `small-linear`, `medium-single-site`, `medium-multi-site`), giữ nguyên máy, topology, quét, `known`, mục tiêu.
- **Dữ liệu:** snapshot `2026-10-28:7453da5422a4`.

## 3. Chỗ lỗ hổng và nhóm CVE ứng viên
Mỗi `env_fact` `vuln_<máy>_<exploit>` của kịch bản NASim là một **chỗ lỗ hổng** (slot). Vai trò của slot suy từ cấu trúc, không chọn tay:

| Slot | Ý nghĩa trong NASim | Nhóm CVE ứng viên |
|---|---|---|
| `vuln_<máy>_e_*` | khai thác dịch vụ mạng, **không cần tài khoản** (NASim không mô hình hóa thông tin đăng nhập) | `role_with_filter` = `initial-access` (AV:N hoặc AV:A, PR:N, UI:N, C:H và I:H): 5.672 CVE, 11,3% thuộc KEV |
| `vuln_<máy>_pe_*` | leo thang tại chỗ | `role_with_filter` = `privesc` và AV:L (loại AV:P vì cần truy cập vật lý): 3.233 CVE, 7,5% thuộc KEV |

Điều kiện chung: CVE có vector CVSS v3, base score và điểm EPSS trong snapshot (để mọi mô hình và chính sách tính được). CVE lấy mẫu từ toàn bộ nhóm ứng viên, tức tập "mọi CVE thuộc KEV + mọi CVE công bố năm 2024" của snapshot; tỉ lệ KEV là tỉ lệ tự nhiên của tập này, không chỉnh.

Vai trò `lateral` (PR:L, cần tài khoản) và `client-side` (UI:R) **không dùng**, vì NASim không có tài khoản hay người dùng; dùng chúng sẽ thêm giả định mà mô hình không biểu diễn.

## 4. Cách gán
Với mỗi (kịch bản gốc, `m`, seed):
1. Duyệt các slot theo thứ tự tăng dần của tên; với mỗi slot, rút `m` CVE **khác nhau** từ nhóm ứng viên của slot, ngẫu nhiên đều, không hoàn lại trong slot, bằng `random.Random(f"{scenario_id}|m={m}|seed={seed}")`. Các slot rút độc lập: một CVE có thể xuất hiện ở hai máy khác nhau.
2. Mỗi hành động khai thác gốc dùng slot đó được thay bằng `m` bản sao, mỗi bản gắn một CVE: id `<id gốc>__<CVE>`, thêm trường `cve`, giữ nguyên điều kiện và hiệu ứng (kể cả mức truy cập user/admin của NASim). Bỏ trường `prob` và `cost` của NASim: xác suất nhóm V lấy từ CVE theo mô hình M-CVSS/M-EPSS/M-KEV.
3. Hành động quét và `capture_all` giữ nguyên.

Kết quả: đơn vị vá là `CVE@máy` (`aapef.defense.patch_units`). Một slot có `m` đơn vị; muốn đóng slot phải vá cả `m`.

## 5. Lưới kịch bản
- `m` ∈ {1, 2, 3, 5}; seed 0–9; 4 cấu trúc → 160 kịch bản, ghi ở `scenarios/V/<cấu trúc>-m<m>-s<seed>.json` kèm `scenarios/V/MANIFEST.json` (tham số, snapshot, SHA-256 từng file).
- **Đơn vị thống kê:** một kịch bản = một mạng; so sánh cặp chính sách trên cùng các mạng (`aapef.policy_stats`), báo cáo riêng theo từng `m` và từng cấu trúc.

## 6. Độ nhạy (sau thí nghiệm chính, đã công bố trước)
- **Tỉ lệ KEV:** rút CVE theo tầng, 50% từ KEV và 50% ngoài KEV.
- **Đội máy đồng nhất:** cùng một exploit NASim (ví dụ `e_ssh`) nhận **cùng** bộ CVE trên mọi máy (cùng phiên bản phần mềm).

## 7. Hạn chế (nêu trong luận văn)
- CVE gắn vào dịch vụ theo vai trò, không theo đúng sản phẩm (CVE của Apache không nhất thiết nằm trên dịch vụ `http`).
- Vai trò lấy từ quy tắc `role_with_filter`, độ khớp 72,5% với phân loại mù (`ViecCanLam_GanNhanCVE.md`).
- Các CVE trên một máy coi như độc lập; kẻ tấn công chọn CVE có xác suất cao nhất trong mô hình đang dùng.

## Nhật ký thay đổi
*(trống)*
