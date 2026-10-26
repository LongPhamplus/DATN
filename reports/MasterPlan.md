# Master plan đồ án AAPEF

*Cập nhật 2026-10-26. Tài liệu gốc về định vị đề tài, hiện trạng và việc cần làm. Lịch theo tuần và tiêu chí nghiệm thu từng việc: `reports/KeHoachPhatTrien.md`. Mọi mục "Sẽ làm" chưa triển khai; tên file/module là đề xuất.*

## 1. Đề tài (đã định vị lại)

**Tên:** Đánh giá các chính sách ưu tiên vá lỗ hổng (CVSS, EPSS, KEV, theo ngữ cảnh đường tấn công) bằng mô hình attack graph.

**Lĩnh vực:** quản trị rủi ro và phòng thủ (vulnerability management, network hardening). Lỗ hổng là **dữ liệu đầu vào**; đồ án không phân tích nguyên nhân lỗ hổng, không viết hay chạy mã khai thác, không tấn công hệ thống thật.

**Vấn đề:** tổ chức chỉ vá được một phần lỗ hổng. Các thang điểm chấm từng lỗ hổng riêng lẻ, không xét vị trí của nó trên đường tới tài sản quan trọng.

**Câu hỏi nghiên cứu**
- RQ1. Với ngân sách vá k lỗ hổng, chính sách nào (CVSS, EPSS, KEV, theo ngữ cảnh đường tấn công) giảm rủi ro đường tấn công nhiều nhất?
- RQ2. Cấu trúc mạng (phẳng, DMZ, phân đoạn, hình sao) ảnh hưởng thế nào đến chênh lệch giữa các chính sách?
- RQ3. Kết luận có bền khi đổi mô hình xác suất đánh giá và đổi snapshot dữ liệu không?

**Đóng góp (nói thận trọng)**
1. Khung định lượng, tái lập được, đo tác động của chính sách vá lên đường tấn công tốt nhất còn lại.
2. Kết quả thực nghiệm so sánh các chính sách trên nhiều cấu trúc mạng, có đánh giá chéo và độ nhạy.
3. Điều kiện cấu trúc mạng mà ngữ cảnh đường tấn công tạo khác biệt so với điểm đơn lẻ.

Không tuyên bố "chưa ai làm" trước khi khảo sát tài liệu (việc 1.1). Kết quả "không khác biệt" vẫn là kết luận hợp lệ.

## 2. Kiến thức ATTT áp dụng (để trả lời hội đồng)

| Kiến thức | Thể hiện trong đồ án |
|---|---|
| Quản lý lỗ hổng theo rủi ro: vì sao không vá hết, giới hạn của CVSS Base, vai trò EPSS và KEV | Các chính sách vá và thiết kế so sánh (RQ1) |
| Giải phẫu chuỗi tấn công: truy cập ban đầu → leo thang → di chuyển ngang → chiếm mục tiêu | Mô hình trạng thái quyền; ánh xạ ATT&CK T1190, T1068, T1210 (việc 7.1) |
| Đọc vector CVSS (AV, AC, PR, UI) để biết lỗ hổng đóng vai trò gì | Quy tắc suy vai trò từ vector (việc 2.3) |
| Kiến trúc mạng phòng thủ: DMZ, phân đoạn, điểm nghẽn, mạng phẳng | Bốn cấu trúc mạng và what-if chặn kết nối (RQ2) |
| Thang đo đo cái gì: độ khó khai thác ≠ xác suất thực tế ≠ giá trị tài sản | Ba mô hình xác suất, đánh giá chéo (RQ3), nêu rõ chưa đo impact |

**Giới hạn phải nêu thẳng:** mô phỏng trên dữ liệu công khai, không có môi trường thực; mạng tổng hợp nên kết luận chỉ đúng "trong mô hình"; CVSS/EPSS chỉ là xấp xỉ; chưa mô hình hóa giá trị tài sản.

## 3. Những gì đã có

| Hạng mục | Trạng thái |
|---|---|
| Lõi mô phỏng attack graph (trạng thái quyền, tiền/hậu điều kiện), phát lại và kiểm tra đường đi | Xong |
| 5 thuật toán tìm đường: BFS, DFS, Dijkstra, Greedy, A\* | Xong; Dijkstra tối ưu và A\*=C\* trên 21/21 kịch bản có đường, giữ qua 7 biến thể giả định |
| Chi phí CVSS v3.1 (`aapef/cvss.py`): cost = round(10·(−ln(E/10))), lệnh `recost` | Xong |
| `scenarios/cve_catalog.json`: 10 CVE thật từ NVD, có kiểm tra điểm Exploitability, vai trò, ngày KEV | Xong |
| Bộ kịch bản: 27 kịch bản `scenarios/benchmark_cvss.json`, `lab-01` (do tác giả công cụ thiết kế, phải nêu rõ khi báo cáo), 11 kịch bản nguồn CVE | Xong |
| Bộ sinh `scen_gen.py` (hai chế độ chi phí) | Do tác giả tự viết và sửa |
| Phân tích: `benchmark --summary`, độ nhạy thứ tự hành động và giả định chi phí, `scripts/cvss_sensitivity.py` | Xong |
| Kiểm thử và tái lập: 72 test, lint sạch, `scripts/reproduce.sh` (8 bước) | Xong |
| Tài liệu: README, `AAPEF_Research_Plan.md`, `reports/Chuong_KetQua.md`, `reports/ThayDoi_ChiPhiCVSS.md`, hai bản kế hoạch | Xong, riêng báo cáo LaTeX còn dở |
| Kết quả đã biết: DFS tốn tới ~8×C\*; bẫy Greedy 30 so với 14; đánh đổi L≠C chỉ có ở 6/10 kịch bản CVE có đường và phụ thuộc cách chuẩn hóa p | Đã ghi |

**Dở dang:** ba file LaTeX báo cáo sửa nửa chừng, chưa commit (tạm dừng theo yêu cầu); `out/cvss/*` đang ở trạng thái đã sửa chưa commit; `Student name.xlsx` chưa commit (chứa thông tin cá nhân, không đưa vào git).

**Chưa có (phần cốt lõi mới):** dữ liệu EPSS/KEV, what-if, chính sách vá, chỉ số R(k), bộ chạy thí nghiệm, thống kê, ánh xạ ATT&CK.

## 4. Những gì sẽ làm

Mã ID trùng `KeHoachPhatTrien.md` §6. **C** = Claude, **T** = tác giả.

| Giai đoạn | Việc | Sản phẩm | Ai |
|---|---|---|---|
| A. Định vị (tuần 1) | Khảo sát tài liệu; chốt giả thuyết, R(k), chính sách; xác nhận điều kiện dữ liệu | Bảng nguồn; bản thiết kế 2 trang | T, C |
| B. Dữ liệu (tuần 2) | Tải snapshot NVD/KEV/EPSS có hash; bộ nạp; quy tắc suy vai trò + kiểm tra mẫu; ba nguồn xác suất, chi phí số thực | `data/snapshots/*`, `MANIFEST.json`, `aapef/data.py` | C (T phân loại mẫu) |
| C. Phòng thủ (tuần 3–4) | What-if (vá CVE, chặn cạnh); các chính sách vá; hàm R(k); top-k đường; bộ chạy thí nghiệm | Mô-đun phân tích phòng thủ, runner | C |
| D. Mạng (tuần 4) | Dựng kịch bản bốn cấu trúc mạng nguồn CVE | Kịch bản qua validator và benchmark `--strict` | **T** (C chỉ kiểm tra đầu ra) |
| E. Thí nghiệm (tuần 5–6) | Chạy chính; đối chiếu tham lam với vét cạn ở mạng nhỏ; đánh giá chéo ba mô hình; bootstrap, kiểm định cặp; độ nhạy và snapshot thứ hai | Bảng, đường cong R(k) | C |
| F. Trình bày ATTT (tuần 7) | Ánh xạ ATT&CK, "lời kể" đường tấn công, khuyến nghị theo loại mạng, 3–5 ví dụ có số; case study nếu kịp | Đầu ra đọc được như báo cáo ATTT | C, T |
| G. Viết và bảo vệ (tuần 8–9) | Luận văn, slide, tài liệu hỏi đáp | Bản nộp, bảo vệ 28/12 | T (C hỗ trợ số liệu) |

**Mức tối thiểu vẫn bảo vệ được:** A–E và viết. Bỏ F (case study, ATT&CK) nếu trễ; nêu rõ là giới hạn.

**Hướng mở rộng (chọn tối đa một, nếu còn thời gian):** bài toán chọn tập vá tối ưu dưới ngân sách (so tham lam với tối ưu); thêm giá trị tài sản (impact); case study môi trường có tài liệu công khai.

## 5. Mốc kiểm soát

| Mốc | Ngày | Điều kiện đạt |
|---|---|---|
| M1 Thiết kế được duyệt | 1/11 | Bản 2 trang, giả thuyết và chỉ số công bố trước khi chạy |
| M2 Dữ liệu sẵn sàng | 8/11 | Snapshot + nạp có kiểm hash + ba nguồn xác suất có test |
| M3 Công cụ đủ chạy | 22/11 | What-if, chính sách, R(k), runner chạy end to end ra CSV |
| M4 Có kết quả chính | 6/12 | Bảng RQ1, RQ2, đánh giá chéo RQ3 |
| M5 Bản nháp luận văn | 20/12 | Đủ chương, số liệu khớp với `reproduce.sh` |
| Bảo vệ | 28/12 | — |

## 6. Rủi ro chính
Các chính sách không khác nhau (báo cáo trung thực); mạng tổng hợp bị phản biện (nêu giới hạn, case study); lập luận vòng tròn (đánh giá chéo); quy tắc suy vai trò kém chính xác (kiểm tra mẫu); dữ liệu đổi theo thời gian (snapshot có hash); tính mới chưa xác minh (khảo sát trước); trễ tiến độ (mức tối thiểu ở §4). Bảng đầy đủ: `KeHoachPhatTrien.md` §9.

## 7. Phiếu giao nhiệm vụ (`Student name.xlsx`, sheet `Cử nhân`)
Tên đề tài và các mục 3.1–3.5, Nội dung 1–5 đã điền theo đúng đề tài này nên không cần đổi nội dung. Còn lại hai việc của bạn: (1) ba ô "Lĩnh vực" đang là NLP/Big data/AI, không khớp; danh sách có "An toàn không gian số", nên hỏi thầy hướng dẫn trước khi đổi; (2) kiểm tra chiều cao dòng trong Excel vì chưa xem được bằng phần mềm.
