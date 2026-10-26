# Thiết kế thí nghiệm (công bố trước khi chạy)

*Bản nháp 2026-10-27, chờ tác giả duyệt. Mọi thay đổi sau khi đã chạy thí nghiệm chính phải ghi lại ở cuối tài liệu cùng lý do. Các mục đánh dấu **[CHỜ DUYỆT]** là đề xuất chưa được tác giả xác nhận.*

## 1. Mục tiêu
Đo xem, với ngân sách vá k, chính sách chọn lỗ hổng nào làm rủi ro đường tấn công tốt nhất còn lại thấp nhất, trên các mạng NASim. Mô phỏng thuần, không khai thác thật.

## 2. Câu hỏi và giả thuyết
- **RQ-P1.** Chính sách nào cho rủi ro còn lại thấp nhất ở mỗi ngân sách k?
- **RQ-P2.** Cấu trúc mạng ảnh hưởng thế nào đến chênh lệch giữa các chính sách?
- **RQ-P3.** Thứ hạng có bền khi đổi mô hình xác suất (nhóm V) và đổi snapshot dữ liệu?
- **H1.** Chính sách theo ngữ cảnh (tham lam) không kém chính sách dùng điểm đơn lẻ, và vượt rõ khi mạng có điểm nghẽn.
- **H2.** Chênh lệch thu hẹp ở mạng phẳng (nhiều đường song song).
- **H3.** Thứ hạng chính sách thay đổi ít khi đổi mô hình xác suất. Nếu đổi nhiều thì báo cáo như một kết quả.
- Kết quả "không khác biệt" hoặc ngược giả thuyết vẫn được báo cáo đầy đủ.

## 3. Hai nhóm thí nghiệm (hướng C)
| | Nhóm N | Nhóm V |
|---|---|---|
| Mạng | kịch bản NASim chuyển nguyên, không CVE | cùng cấu trúc, gán CVE theo quy tắc công bố trước, nhiều seed (quy tắc do T viết) |
| Xác suất | N1: `prob` thật của NASim. N2: CVSS dẫn xuất từ cấu trúc | M-CVSS, M-EPSS, M-KEV |
| Chính sách | theo ngữ cảnh, vét cạn, ngẫu nhiên, theo xác suất exploit | thêm CVSS-Base, CVSS-Exploit, EPSS, KEV-trước |
| Kết quả báo cáo | tách riêng | tách riêng |

Nhóm N không có CVE nên CVSS-Base, EPSS, KEV không áp dụng được; chính sách "theo xác suất exploit" (xếp theo xác suất thành công của exploit, N1 hoặc N2) là tương đương gần nhất và sẽ hòa nhiều ở N2 vì cùng loại exploit cùng điểm.

## 4. Mô hình và chỉ số
- **Rủi ro P\*(S):** xác suất thành công của đường tốt nhất tới mục tiêu trong kịch bản S, `P* = exp(−C*)`, C\* = tổng chi phí số thực nhỏ nhất (Dijkstra) với chi phí mỗi bước = −ln p. Không có đường: P\* = 0. Hành động quét và hành động ảo (`capture_all`) dùng xác suất cố định, không bị vá.
- **Đơn vị vá [CHỜ DUYỆT]:** một "ví dụ lỗ hổng" = (khai thác, máy đích), chính là mỗi `vuln_<máy>_<khai thác>` trong `env_facts` (nhóm N) hoặc (CVE, máy đích) (nhóm V). Vá = loại mọi hành động dựa trên `env_fact` đó khỏi bản sao kịch bản. Với `small` có 14 đơn vị.
- **R(k):** P\* sau khi vá k đơn vị đầu tiên của chính sách. R(0) là rủi ro ban đầu; R không tăng theo k.
- **Chỉ số phụ:** AUC của R(k) (chuẩn hóa theo R(0)), k\_block (k nhỏ nhất làm R = 0), tỉ lệ thắng theo cặp.
- **Ngân sách K [CHỜ DUYỆT]:** K = 6 với mạng ≤ 16 máy.
- Chi phí dùng số thực, không làm tròn.

## 5. Chính sách
| Chính sách | Quy tắc | Biết mạng? |
|---|---|---|
| Context-greedy | mỗi bước chọn đơn vị làm P\* giảm nhiều nhất; hòa thì theo mã đơn vị | có |
| Optimal | vét cạn mọi tập k đơn vị, chọn tập cho P\* nhỏ nhất (C(14,k) nhỏ) | có |
| Random | thứ tự ngẫu nhiên, 200 seed, lấy trung bình | không |
| Theo xác suất exploit | xác suất thành công giảm dần | không |
| CVSS-Base, CVSS-Exploit, EPSS, KEV-trước (chỉ nhóm V) | điểm tương ứng giảm dần | không |

Quy tắc hòa mọi chính sách: theo mã đơn vị tăng dần, để tất định.

## 6. Lưu ý công bằng
Context-greedy dùng mô hình xác suất để tìm đường nên có lợi thế khi chấm bằng đúng mô hình đó. Nhóm V chấm mỗi chính sách bằng cả ba mô hình. Nhóm N chỉ có một mô hình mỗi lần (N1 hoặc N2), nên báo cáo hai lần và nêu lợi thế này.

## 7. Thống kê [CHỜ DUYỆT]
- **Nhóm N:** mỗi kịch bản NASim là một mạng xác định; chỉ khoảng 4–6 kịch bản nên **không** đủ để kiểm định thống kê giữa các mạng. Báo cáo bảng R(k) và AUC từng kịch bản; riêng Random có khoảng tin cậy qua 200 seed.
- **Nhóm V:** biến thiên từ seed gán CVE; dùng bootstrap trên nhiều seed × kịch bản, kiểm định cặp (Wilcoxon) trên AUC, báo cáo cỡ hiệu ứng.
- Đối chiếu Context-greedy với Optimal: báo cáo độ lệch.

## 8. Kiểm tra tính hợp lý trước khi tin số liệu
1. Tính tay trên mạng rất nhỏ (ví dụ `tiny`): R(k) khớp.
2. R(0) = exp(−C\*) với C\* của Dijkstra trên chi phí số thực.
3. R(k) không tăng theo k, với mọi chính sách.
4. Optimal ≤ mọi chính sách khác tại cùng k.
5. Chính sách "tệ nhất có chủ đích" kém Random.

## 9. Mối đe dọa tính hợp lệ (nêu trong luận văn)
Mạng nhỏ và ít (NASim); xác suất NASim là số tác giả NASim đặt; CVSS dẫn xuất từ cấu trúc cho điểm bằng nhau trong cùng loại exploit; kẻ tấn công được giả định tối ưu và biết toàn mạng; vá hoàn hảo và tức thời; chưa mô hình hóa giá trị tài sản; hai mục tiêu nhạy được gộp qua máy ảo `GOAL`; chưa khảo sát đủ tài liệu để tuyên bố tính mới (xem `reports/KhaoSat_TaiLieu.md`: có công trình gần giống).

## 10. Quyết định đang chờ tác giả
1. Đơn vị vá = (khai thác/CVE, máy đích)?
2. K = 6 cho mạng ≤ 16 máy?
3. Có giữ chính sách "theo xác suất exploit" cho nhóm N?
4. Danh sách kịch bản NASim đưa vào nhóm N (đề xuất: `small`, `small-linear`, `medium-single-site`, `medium-multi-site`).

## Nhật ký thay đổi sau khi chạy
*(trống)*
