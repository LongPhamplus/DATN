# Kế hoạch phát triển đồ án AAPEF (26/10 → 28/12/2026)

*Phiên bản 1 · 2026-10-26. Tài liệu này là kế hoạch; các mục "Sẽ làm" chưa được triển khai. Chi tiết thiết kế gốc: `AAPEF_Research_Plan.md`; chi phí CVSS: `reports/ThayDoi_ChiPhiCVSS.md`.*

## 1. Đề tài và câu hỏi nghiên cứu

**Đề tài:** Đánh giá các chính sách ưu tiên vá lỗ hổng (CVSS, EPSS, KEV, theo ngữ cảnh đường tấn công) bằng mô hình attack graph.

**Bài toán ATTT:** tổ chức chỉ vá được một phần lỗ hổng. Các thang điểm hiện có chấm từng lỗ hổng riêng lẻ, không xét vị trí của nó trên đường tới tài sản quan trọng. Cần cơ sở định lượng để chọn lỗ hổng vá trước và kết nối cần chặn.

**Câu hỏi nghiên cứu (RQ)**
- **RQ1.** Với ngân sách vá k lỗ hổng, chính sách nào giảm rủi ro đường tấn công nhiều nhất: theo CVSS, EPSS, KEV, hay theo ngữ cảnh đường tấn công?
- **RQ2.** Cấu trúc mạng (phẳng, có DMZ, phân đoạn, hình sao) ảnh hưởng thế nào đến chênh lệch giữa các chính sách?
- **RQ3.** Kết luận có bền vững khi đổi mô hình xác suất dùng để đánh giá (CVSS, EPSS, KEV) không?

**Giả thuyết kiểm chứng**
- H1: chính sách theo ngữ cảnh đường tấn công không kém các chính sách dùng điểm đơn lẻ, và vượt rõ khi mạng có điểm nghẽn.
- H2: chênh lệch thu hẹp ở mạng phẳng (mọi máy ngang hàng).
- H3: thứ hạng chính sách thay đổi ít khi đổi mô hình xác suất đánh giá; nếu đổi nhiều thì đó là kết quả cần báo cáo.

Kết quả "không khác biệt" vẫn là kết luận hợp lệ và sẽ được báo cáo trung thực.

## 2. Hiện trạng (đã có)
- Lõi mô phỏng attack graph (trạng thái quyền, hành động có tiền điều kiện/hậu điều kiện), 5 thuật toán tìm đường (BFS, DFS, Dijkstra, Greedy, A\*), phát lại và kiểm tra đường đi.
- Chi phí từ CVSS v3.1: `cost = round(10 × −ln(E/10))`, vector suy từ cấu trúc hoặc từ CVE thật trong `scenarios/cve_catalog.json` (10 CVE từ NVD, có kiểm chứng điểm Exploitability).
- Bộ kịch bản (27) và bộ sinh `scen_gen.py` (hai chế độ chi phí), benchmark, phân tích độ nhạy (thứ tự hành động, giả định mô hình chi phí).
- Công cụ: `demo`, `solve`, `benchmark --summary`, `recost`, `sensitivity`; 72 test; `scripts/reproduce.sh`.

## 3. Kỹ thuật sử dụng

| Nhóm | Kỹ thuật | Dùng để |
|---|---|---|
| Mô hình hóa | Attack graph theo trạng thái (quyền none/user/admin, tri thức đã học) | Biểu diễn chuỗi tấn công |
| Xác suất | CVSS v3.1 Exploitability, EPSS, KEV làm nguồn xác suất; chi phí = −ln p | Biến tích xác suất thành tổng chi phí |
| Tìm đường | Dijkstra/A\* (đường có xác suất thành công cao nhất), top-k đường | Đo rủi ro còn lại, liệt kê phương án |
| Phòng thủ (what-if) | Loại một CVE hoặc một cạnh topology rồi tính lại | Đo tác động của việc vá hoặc phân đoạn |
| Chính sách vá | Top-k theo CVSS Base, CVSS Exploitability, EPSS, KEV-trước; theo ngữ cảnh (tham lam theo mức giảm rủi ro biên); ngẫu nhiên; tối ưu bằng vét cạn ở mạng nhỏ | So sánh (RQ1) |
| Đánh giá | Đường cong rủi ro theo k, diện tích dưới đường cong, tỉ lệ thắng, kiểm định cặp, khoảng tin cậy bootstrap | Thống kê |
| Độ bền | Đánh giá chéo giữa các mô hình xác suất; phân tích độ nhạy giả định | Tránh lập luận vòng tròn (RQ3) |
| Trình bày | Ánh xạ MITRE ATT&CK (T1190 Initial Access, T1068 Privilege Escalation, T1210 Lateral Movement) | Kể đường tấn công theo ngôn ngữ ngành |

Bài toán chọn tập vá nhỏ nhất để chặn mọi đường được biết là khó (NP-khó) trong tài liệu về network hardening; vì vậy dùng tham lam ở mạng lớn và vét cạn ở mạng nhỏ để đối chiếu. *Cần dẫn nguồn khi viết luận.*

## 4. Dữ liệu

| Dữ liệu | Nguồn (công khai) | Trường dùng | Cách lưu |
|---|---|---|---|
| Lỗ hổng, vector CVSS | NVD CVE API 2.0 | id, vector v3.1, điểm Exploitability, mô tả | Snapshot JSON có ngày tải |
| Lỗ hổng bị khai thác thật | Danh mục CISA KEV (feed JSON/CSV công khai) | id, ngày thêm, vendor/product | Snapshot có ngày |
| Xác suất bị khai thác | EPSS của FIRST (API và file CSV hằng ngày) | epss, percentile, ngày | Snapshot có ngày |
| Kỹ thuật tấn công | MITRE ATT&CK | id, tên, chiến thuật | Bảng ánh xạ vai trò → kỹ thuật |
| Cấu trúc mạng | Mô hình tổng hợp: phẳng, DMZ + nội bộ, phân đoạn, hình sao; 10–50 máy | topology, máy mục tiêu | Kịch bản JSON |
| Case study (nếu kịp) | Một môi trường thực hành được tài liệu hóa công khai | cấu trúc và lỗ hổng theo mô tả | Mô hình hóa từ mô tả, không chạy môi trường |

**Nguyên tắc dữ liệu**
- Chỉ **tải một lần** rồi dùng snapshot cố định (kèm ngày và băm tệp) để tái lập; không gọi API trong lúc chạy thí nghiệm.
- Mọi snapshot nằm trong repo hoặc có script tải lại; ghi rõ ngày truy cập.
- NVD, EPSS giới hạn tần suất truy vấn: kiểm tra điều kiện sử dụng khi làm và ghi vào tài liệu. *Chưa xác nhận chi tiết; việc của tuần 2.*
- **Vai trò của CVE** (truy cập ban đầu, di chuyển ngang, leo thang cục bộ, chiếm miền) suy từ chính vector CVSS bằng quy tắc công bố (ví dụ AV:N + PR:N → truy cập ban đầu; AV:N + PR:L → di chuyển ngang; AV:L → leo thang cục bộ), thay cho chọn tay. *Quy tắc cần được kiểm tra trên mẫu trước khi dùng.*
- Gán CVE cho từng máy: lấy mẫu theo phân phối của KEV, tham số và seed cố định, công bố trước khi chạy.

## 5. Thiết kế thí nghiệm

1. **Mô hình xác suất đánh giá (sự thật nền của mô phỏng)**: M-CVSS (p = E/10), M-EPSS (p = epss), M-KEV (p cao nếu thuộc KEV, ngược lại theo EPSS). Mỗi chính sách vá được đánh giá dưới **cả ba**, không chỉ dưới mô hình trùng nguồn của chính sách đó.
2. **Chỉ số chính:** xác suất thành công của đường tốt nhất còn lại sau k lần vá, R(k), với k = 0…K. Chỉ số phụ: số đường còn lại (top-k), mục tiêu còn tới được hay không.
3. **So sánh:** đường cong R(k) trung bình ± khoảng tin cậy trên N mạng cho mỗi cấu trúc; diện tích dưới đường cong; tỉ lệ thắng theo cặp; kiểm định cặp.
4. **Độ nhạy:** hệ số chuẩn hóa xác suất, xác suất thu thập thông tin, kích thước mạng, số CVE trên mỗi máy.
5. **Lưu ý kỹ thuật:** chi phí hiện làm tròn về số nguyên; thí nghiệm dùng chi phí thực (số thực) để tránh méo thứ hạng.

## 6. Việc cần phát triển và phân công

| # | Hạng mục | Mô tả | Người làm |
|---|---|---|---|
| 1 | Lớp dữ liệu | Tải và lưu snapshot NVD/KEV/EPSS; quy tắc suy vai trò từ vector; kiểm tra tính toàn vẹn | Claude |
| 2 | Mô hình xác suất | Ba nguồn xác suất (CVSS/EPSS/KEV) cắm vào tính chi phí | Claude |
| 3 | What-if | Loại CVE hoặc cạnh topology, tính lại đường tốt nhất | Claude |
| 4 | Chính sách vá | Các chính sách ở Mục 3, hàm tính R(k) | Claude |
| 5 | Top-k đường | Liệt kê k đường khác nhau, quy ước độ đa dạng | Claude |
| 6 | Bộ chạy thí nghiệm và thống kê | Chạy lưới tham số, xuất CSV, đường cong, kiểm định | Claude |
| 7 | Ánh xạ ATT&CK và "lời kể" đường tấn công | Gắn kỹ thuật cho từng hành động, in ra | Claude |
| 8 | Dựng mạng từ dữ liệu | Các kịch bản mạng dạng nguồn có `cve` cho bốn cấu trúc; có thể mở rộng `scen_gen.py` | **Tác giả** (Claude kiểm tra đầu ra bằng validator, `recost`, benchmark `--strict`) |
| 9 | Case study | Mô hình hóa môi trường công khai từ mô tả | Tác giả, Claude hỗ trợ kiểm tra |
| 10 | Viết luận, slide, ôn hỏi đáp | Theo Mục 8 | Tác giả, Claude hỗ trợ |

## 7. Lịch 9 tuần

| Tuần | Ngày | Việc | Sản phẩm / tiêu chí xong |
|---|---|---|---|
| 1 | 26/10–1/11 | Khảo sát tài liệu, chốt giả thuyết và chỉ số, thiết kế thí nghiệm chi tiết | Bản thiết kế 2 trang được duyệt; danh sách tài liệu |
| 2 | 2/11–8/11 | Hạng mục 1, 2 | Snapshot có ngày và băm; quy tắc vai trò kiểm tra trên mẫu |
| 3 | 9/11–15/11 | Hạng mục 3, 4 | What-if và chính sách vá có test |
| 4 | 16/11–22/11 | Hạng mục 5, 6 (khung); hạng mục 8 bắt đầu | Chạy thử thí nghiệm nhỏ end to end |
| 5 | 23/11–29/11 | Chạy thí nghiệm chính | Bảng R(k) cho cả bốn cấu trúc mạng |
| 6 | 30/11–6/12 | Đánh giá chéo, độ nhạy, thống kê | Bảng so sánh và kiểm định |
| 7 | 7/12–13/12 | Hạng mục 7, 9 (case study nếu kịp) | Ví dụ cụ thể có số; lời kể ATT&CK |
| 8 | 14/12–20/12 | Viết luận | Bản nháp đầy đủ |
| 9 | 21/12–27/12 | Slide, ôn hỏi đáp, dự phòng | Sẵn sàng bảo vệ 28/12 |

**Mức tối thiểu vẫn bảo vệ được nếu trễ:** bỏ case study và ánh xạ ATT&CK; giữ tuần 1–6 và viết. Nêu rõ đó là giới hạn.

## 8. Sản phẩm cuối
Mã nguồn tái lập được bằng một lệnh; snapshot dữ liệu; báo cáo thực nghiệm; quyển đồ án (đề xuất bố cục: giới thiệu và RQ; kiến thức nền; mô hình và dữ liệu; thiết kế thí nghiệm; kết quả; thảo luận và hạn chế; kết luận); slide; tài liệu hỏi đáp (`reports/HoiDap_BaoVe.md`, soạn sau khi có số liệu).

## 9. Rủi ro và cách giảm

| Rủi ro | Giảm thiểu |
|---|---|
| Các chính sách không khác nhau nhiều | Báo cáo là kết quả hợp lệ; phân tích điều kiện nào tạo khác biệt |
| Mạng tổng hợp bị phản biện là không thực tế | Case study; nêu rõ giới hạn; dựa trên kiến trúc tham chiếu công khai |
| Lập luận vòng tròn (đánh giá bằng đúng thang đang so sánh) | Đánh giá chéo ba mô hình xác suất |
| Quy tắc suy vai trò từ vector kém chính xác | Kiểm tra trên mẫu; nêu là xấp xỉ |
| Tính mới chưa xác minh | Khảo sát tài liệu ở tuần 1 trước khi tuyên bố; chỉ nói "định lượng và tái lập" |
| Trễ tiến độ | Mức tối thiểu ở Mục 7; chốt phạm vi ở tuần 4 |
| Giới hạn truy vấn API | Tải một lần, dùng snapshot |

## 10. Phạm vi và đạo đức
Hoàn toàn là mô phỏng trên dữ liệu công khai: không mã khai thác, không quét hay tấn công hệ thống thật, không cần cyber range. Điểm CVSS/EPSS và danh sách CVE chỉ dùng như dữ liệu chấm điểm. Mô hình hiện đo khả năng bị tấn công thành công, **chưa đo tác động** (giá trị tài sản); đây là giới hạn đã biết và có thể mở rộng bằng trọng số tài sản nếu còn thời gian.
