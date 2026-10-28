# AAPEF: từ công cụ tìm đường tấn công đến khung đánh giá chính sách vá

*Báo cáo ngắn, 2026-10-28.*

## 1. AAPEF ban đầu (v1, 20–22/10/2026)

**Tên:** AAPEF — *Automated Attack Path Execution Framework*.

**Mục đích:** mô phỏng việc lập kế hoạch tấn công của Red Team như bài toán tìm đường trên không gian trạng thái. Trạng thái gồm quyền truy cập trên từng máy và thông tin đã biết; hành động có tiền điều kiện và hiệu ứng; mục tiêu là đạt một mức quyền trên máy đích. Chỉ mô phỏng trên dữ liệu JSON, không khai thác thật.

**Đã làm:**
- Lõi mô phỏng, phát lại và kiểm tra đường đi; 5 thuật toán BFS, DFS, Dijkstra, Greedy, A\* (heuristic chấp nhận được, có test).
- Chi phí mỗi bước tính từ CVSS v3.1: `cost = −ln(Exploitability/10)`, nên đường rẻ nhất là đường có xác suất thành công cao nhất. Vector lấy từ cấu trúc hành động hoặc từ CVE thật trên NVD.
- 27 kịch bản (viết tay và sinh tự động, tới 11.264 trạng thái), benchmark, `scripts/reproduce.sh`.

**Câu hỏi và kết quả:** so sánh 5 thuật toán về chi phí, độ dài, công sức tìm kiếm và độ bền (RQ1–RQ4). Dijkstra và A\* luôn cho chi phí tối ưu, BFS cho độ dài tối ưu, Greedy có thể rơi vào bẫy. Đánh đổi "đường ngắn nhất khác đường rẻ nhất" chỉ xuất hiện ở một kịch bản thiết kế tay.

**Hạn chế:** đây là câu hỏi về thuật toán. Kết quả phần lớn đã biết từ lý thuyết và ít giá trị an toàn thông tin: không trả lời được người phòng thủ nên làm gì.

## 2. Hướng phát triển: AAPEF v2

**Tên:** AAPEF v2 — *Attack-graph-based Patch-Prioritisation Evaluation* (xây trên lõi AAPEF).

**Đề tài:** Đánh giá các chính sách ưu tiên vá lỗ hổng (CVSS, EPSS, KEV, theo ngữ cảnh đường tấn công) bằng mô hình attack graph.

**Ý tưởng chuyển hướng:** đổi vai trò của lõi tìm đường từ *công cụ của kẻ tấn công* thành *thước đo cho người phòng thủ*.
- Rủi ro P\* là xác suất thành công của đường tấn công tốt nhất tới tài sản nhạy cảm.
- Vá k lỗ hổng theo một chính sách rồi đo lại để có đường R(k).
- So sánh các chính sách bằng diện tích dưới R(k) (AUC).

**Câu hỏi:** với ngân sách vá k lỗ hổng, chính sách nào làm rủi ro còn lại thấp nhất? Kết luận phụ thuộc thế nào vào cấu trúc mạng, mô hình xác suất và dữ liệu?

**Thêm so với v1:**

| Thành phần | Nội dung |
|---|---|
| Dữ liệu | Snapshot NVD, CISA KEV, EPSS (42.302 CVE) có SHA-256, khóa ngày 2026-10-28 |
| Mô hình xác suất | Ba mô hình M-CVSS, M-EPSS, M-KEV. Mỗi chính sách được chấm dưới cả ba (đánh giá chéo) |
| Phân tích phòng thủ | Vá giả định (what-if), tính rủi ro bằng A\*, đường cong R(k), đếm đường tấn công rời nhau |
| Chính sách vá | CVSS-Base, CVSS-Exploit, EPSS, KEV-trước, ngẫu nhiên, theo ngữ cảnh (tham lam trên đường tấn công), tối ưu (vét cạn) |
| Kịch bản | Mạng NASim (mã nguồn mở) gắn CVE thật theo quy tắc công bố trước: 160 mạng |
| Thống kê | Bootstrap CI, kiểm định Wilcoxon, kích thước hiệu ứng, phân tích độ nhạy (5 biến thể) |
| Trình bày | Đường tấn công theo MITRE ATT&CK, biểu đồ R(k) |

**Kết quả chính:**
- Chính sách theo ngữ cảnh thắng chính sách điểm cùng nguồn ở 30–40/40 mạng (p ≤ 2·10⁻⁶) và gần tối ưu khi mỗi lỗ hổng NASim chỉ được gắn 1 CVE. Ví dụ AUC 0,12 so với 0,49 của EPSS.
- Kết luận giữ nguyên ở mọi biến thể độ nhạy.
- Có điều kiện: xét đường tấn công nhưng dùng sai mô hình xác suất (CVSS) có thể thua chính sách EPSS đơn giản.

## 3. Hiện trạng

- **Phần kỹ thuật đã xong:** 116 test qua; mã nguồn đã đẩy lên GitHub.
- **Còn lại:**
  - snapshot dữ liệu thứ hai (khoảng 10/11) để kiểm tra độ ổn định theo thời gian;
  - viết quyển đồ án;
  - chuẩn bị slide bảo vệ.

Chi tiết: `reports/MasterPlan.md`, `reports/KetQua_NhomV.md`, `reports/HoiDap_BaoVe.md`.
