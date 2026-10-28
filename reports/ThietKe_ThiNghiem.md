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

## 10. Quyết định (tác giả đồng ý cả 4, 2026-10-27) [CHỐT]
1. Đơn vị vá = (khai thác hoặc CVE, máy đích).
2. K = 6 cho mạng ≤ 16 máy.
3. Giữ chính sách "theo xác suất exploit" cho nhóm N.
4. Kịch bản nhóm N: `small`, `small-linear`, `medium-single-site`, `medium-multi-site` (đã chuyển bằng `nasim2aapef.py`, nguồn `data/nasim/`).
5. (2026-10-28) `p_kev` = 0,9; độ nhạy kiểm tra sau.
6. (2026-10-28) Mô hình `native` (N1): xác suất `prob` gốc của NASim (bộ chuyển đổi mang theo, commit `5a4043b`); quét p = 1 như NASim. N2 giữ quét p = 0,9.
7. (2026-10-28) Mạng NASim sinh tự động: không bắt buộc (§13). Phần so sánh định lượng chính dựa vào nhóm V với nhiều CVE mỗi máy.

## 11. Số đo các kịch bản nhóm N (2026-10-27, chi phí hiện tại của bộ chuyển đổi)
| Kịch bản | Máy (gồm ATK, GOAL) | Hành động | Đơn vị vá | \|V\| | \|E\| | Đường tốt nhất (bước / chi phí) | Dijkstra |
|---|---|---|---|---|---|---|---|
| small | 10 | 62 | 14 | 657 | 5.823 | 10 / 15 | ~30–40 ms |
| small-linear | 10 | 37 | 12 | 283 | 984 | 13 / 22 | nhanh |
| medium-single-site | 18 | 224 | 25 | 69.121 | 3.234.050 | 6 / 12 | ~1,8 s |
| medium-multi-site | 18 | 135 | 27 | 180.583 | 3.998.300 | 9 / 16 | ~0,2 s |

**Hệ quả cho thiết kế:**
- **Optimal (vét cạn) chỉ khả thi ở `small` (C(14,6) = 3.003 tổ hợp) và `small-linear` (C(12,6) = 924).** Ở hai kịch bản medium, C(25,6) = 177.100 và C(27,6) = 296.010 tổ hợp, nhân với ~0,2–1,8 s mỗi lần tính rủi ro là hàng chục giờ. Ở đó chỉ so Context-greedy với các chính sách khác.
- **Rủi ro chi phí tính toán:** khi một bộ vá chặn hết đường, Dijkstra phải duyệt toàn bộ trạng thái còn tới được (tới 69 nghìn đến 180 nghìn trạng thái, hàng triệu cạnh), chậm hơn nhiều so với khi có đường. Cần đo trước khi chạy hàng loạt; nếu quá chậm, cân nhắc kiểm tra "còn tới được mục tiêu không" bằng cách rẻ hơn trước khi gọi Dijkstra.
- Bộ chuyển đổi hiện **gộp `prob` vào `cost`** (`round(cost/prob)`) nên nhóm N1 (xác suất NASim thật) chưa có dữ liệu xác suất gốc trong JSON; cần quyết định cách mang `prob` theo (việc của tác giả, phần bộ chuyển đổi).

## 12. Chạy thử kỹ thuật (2026-10-27, chưa phải thí nghiệm chính) — nhóm N2, K = 6

Mục đích: kiểm tra mã (`aapef/defense.py`, `aapef/policies.py`) và thời gian chạy, không dùng để kết luận. Rủi ro tính bằng A\* với heuristic h\_max (cho kết quả bằng Dijkstra, đã kiểm thử; trường hợp chặn hết đường trả lời ngay), nên rủi ro chi phí tính toán ở §11 đã được xử lý: mỗi lần tính ~0,01–0,4 s.

**Phát hiện: bài toán suy biến trên mạng NASim.** Với mục tiêu hiện tại (`capture_all` = chiếm **cả hai** máy nhạy cảm), cả 4 kịch bản đều có **k\_block = 1** cho Context-greedy: mỗi máy nhạy cảm chỉ có một lỗ hổng, vá một cái là đủ. Giả định kẻ tấn công đã ở trong mạng (bắt đầu từ từng máy nội bộ) không thay đổi điều này.

Đổi mục tiêu thành "chiếm **ít nhất một** máy nhạy cảm" (P\* = max theo từng máy, tính trong bộ nhớ, không sửa kịch bản):

| Kịch bản | Context-greedy k\_block / AUC | Theo xác suất exploit k\_block / AUC | Random AUC (20 seed, TB [min–max]) | Optimal |
|---|---|---|---|---|
| small | 1 / 0,08 | 1 / 0,08 | 0,59 [0,08–1,00] | = greedy |
| small-linear | 2 / 0,19 | 5 / 0,51 | 0,51 [0,19–0,92] | = greedy |
| medium-multi-site | 1 / 0,08 | 4 / 0,58 | 0,79 [0,10–1,00] | (không chạy) |
| medium-single-site | 2 / 0,25 | không chặn trong 6 / 1,00 | 0,88 [0,42–1,00] | (không chạy) |

Hệ quả: mạng NASim có điểm nghẽn rất hẹp (lát cắt nhỏ nhất 1–2 đơn vị), nên R(k) gần như hàm bậc thang và chính sách theo ngữ cảnh thắng gần như tuyệt đối. Đó là một kết quả (ủng hộ H1 ở mạng có điểm nghẽn) nhưng không đủ để so tinh các chính sách, và **không kiểm tra được H2** (NASim không có mạng phẳng).

**Quyết định (tác giả, 2026-10-27) [CHỐT]:**
1. Rủi ro = chiếm được **ít nhất một** máy nhạy cảm: P\* = max theo từng máy nhạy cảm (`RiskOracle(..., targets=sensitive_hosts(data))`), thay cho mục tiêu ảo `capture_all` (chiếm cả hai). Áp dụng cho cả nhóm N và V.
2. Giữ nhóm N với 4 kịch bản đã chốt, báo cáo như kết quả về mạng có điểm nghẽn hẹp.
3. Phần so sánh định lượng chính dùng mạng lớn hơn, nhiều lỗ hổng mỗi máy: kịch bản sinh bằng bộ sinh của NASim qua bộ chuyển đổi, kết hợp quy tắc gán nhiều CVE mỗi máy cho nhóm V (việc của T); H2 kiểm tra trên các mạng này.

## 13. Mạng NASim sinh tự động có giải quyết suy biến không? (2026-10-28, chạy thử)

Bộ sinh của NASim 0.12.0 (`ScenarioGenerator`, cấu hình công bố `small-gen`, `medium-gen`, `large-gen`, `huge-gen`; 8–38 máy), 10 seed mỗi cấu hình:
- **Mọi mạng sinh ra chỉ có một máy nối Internet** (subnet 1 có đúng 1 máy), với 1–2 cách khai thác từ Internet. Do đó, với kẻ tấn công từ Internet, k\_block ≤ 2 ở mọi kích thước.
- Biến thể "giả định đã bị xâm nhập" (bắt đầu từ từng máy nội bộ), thử trên `medium-multi-site` và `medium-single-site`, cả mô hình native và cvss: luôn có **2 đường không chung lỗ hổng và k\_block = 2**. Lát cắt nằm ở chính hai máy nhạy cảm, vì mỗi máy chỉ có một lỗ hổng.

**Kết luận:** mạng NASim lớn hơn tăng đa dạng về kích thước nhưng **không** làm bài toán bớt suy biến. Đại lượng quyết định là **số lỗ hổng trên mỗi máy**. Vì vậy phần so sánh định lượng chính phải dựa vào nhóm V với **nhiều CVE trên mỗi dịch vụ hoặc máy** (số CVE mỗi máy là một tham số, đã có trong danh sách độ nhạy của MasterPlan §8.4). Mạng sinh tự động vẫn hữu ích cho RQ-P2 (kích thước), nhưng không bắt buộc.

## Nhật ký thay đổi sau khi chạy
- 2026-10-27 (chạy thử kỹ thuật, trước thí nghiệm chính): đổi định nghĩa rủi ro sang "ít nhất một máy nhạy cảm" và thêm họ mạng lớn hơn; lý do: §12 (mục tiêu "cả hai máy" làm mọi kịch bản NASim có k\_block = 1).
- 2026-10-28: quét p = 1 dưới mô hình `native` (trước đó 0,9); lý do: NASim coi quét luôn thành công. R(0) của `small` dưới N1 đổi từ 0,729 thành 0,81. Kết quả N1 chạy trước thay đổi này (ví dụ `out/policies/N` lúc 00:40) phải chạy lại.
