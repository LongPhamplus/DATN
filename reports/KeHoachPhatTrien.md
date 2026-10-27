# Kế hoạch phát triển đồ án AAPEF (26/10 → 28/12/2026)

*Phiên bản 2 · 2026-10-26. Tài liệu này là kế hoạch; các mục "Sẽ làm" chưa được triển khai và tên file/module là **đề xuất**. Chi tiết thiết kế gốc: `AAPEF_Research_Plan.md`; chi phí CVSS: `reports/ThayDoi_ChiPhiCVSS.md`.*

> **Cập nhật 2026-10-27:** đã chọn hướng C (hai nhóm thí nghiệm: N = NASim gốc không CVE, V = có CVE theo quy tắc công bố). Chi tiết ở `reports/MasterPlan.md` §8.0; nguồn cấu trúc NASim ở `reports/DuLieuMang_CoSan.md`. Việc 4.3 (dựng kịch bản) tách thành 4.3a (chuyển các kịch bản NASim, giữ `prob`) và 4.3b (biến thể có CVE, quy tắc công bố trước); cả hai do T làm.

## 1. Đề tài và câu hỏi nghiên cứu

**Đề tài:** Đánh giá các chính sách ưu tiên vá lỗ hổng (CVSS, EPSS, KEV, theo ngữ cảnh đường tấn công) bằng mô hình attack graph.

**Bài toán ATTT:** tổ chức chỉ vá được một phần lỗ hổng. Các thang điểm hiện có chấm từng lỗ hổng riêng lẻ, không xét vị trí của nó trên đường tới tài sản quan trọng. Cần cơ sở định lượng để chọn lỗ hổng vá trước và kết nối cần chặn.

**Câu hỏi nghiên cứu (RQ)**
- **RQ1.** Với ngân sách vá k lỗ hổng, chính sách nào giảm rủi ro đường tấn công nhiều nhất: theo CVSS, EPSS, KEV, hay theo ngữ cảnh đường tấn công?
- **RQ2.** Cấu trúc mạng (phẳng, có DMZ, phân đoạn, hình sao) ảnh hưởng thế nào đến chênh lệch giữa các chính sách?
- **RQ3.** Kết luận có bền vững khi đổi mô hình xác suất dùng để đánh giá (CVSS, EPSS, KEV) và khi đổi snapshot dữ liệu không?

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

**Cái giữ nguyên, cái thêm:** bộ máy mô phỏng và các thuật toán giữ nguyên. Thêm: nguồn xác suất EPSS/KEV bên cạnh CVSS, chức năng "vá rồi đo lại" (what-if), các chính sách vá, bộ chạy thí nghiệm. Các nguồn xác suất đóng **hai vai trò tách biệt**: làm *chính sách vá* (đối tượng so sánh) và làm *thước đo chấm điểm* (sự thật nền của mô phỏng).

## 3. Kỹ thuật sử dụng

| Nhóm | Kỹ thuật | Dùng để |
|---|---|---|
| Mô hình hóa | Attack graph theo trạng thái (quyền none/user/admin, tri thức đã học) | Biểu diễn chuỗi tấn công |
| Xác suất | CVSS v3.1 Exploitability, EPSS, KEV làm nguồn xác suất; chi phí = −ln p | Biến tích xác suất thành tổng chi phí |
| Tìm đường | Dijkstra/A\* (đường có xác suất thành công cao nhất), top-k đường | Đo rủi ro còn lại, liệt kê phương án |
| Phòng thủ (what-if) | Loại một CVE hoặc một cạnh topology rồi tính lại | Đo tác động của việc vá hoặc phân đoạn |
| Chính sách vá | Top-k theo CVSS Base, CVSS Exploitability, EPSS, KEV-trước; theo ngữ cảnh (tham lam theo mức giảm rủi ro biên); ngẫu nhiên; tối ưu bằng vét cạn ở mạng nhỏ | So sánh (RQ1) |
| Đánh giá | Đường cong rủi ro theo k, diện tích dưới đường cong, tỉ lệ thắng, kiểm định cặp, khoảng tin cậy bootstrap | Thống kê |
| Độ bền | Đánh giá chéo giữa các mô hình xác suất; phân tích độ nhạy giả định; chạy lại với snapshot thứ hai | Tránh lập luận vòng tròn (RQ3) |
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
- Vai trò của CVE (truy cập ban đầu, di chuyển ngang, leo thang cục bộ, chiếm miền) suy từ chính vector CVSS bằng quy tắc công bố (ví dụ AV:N + PR:N → truy cập ban đầu; AV:N + PR:L → di chuyển ngang; AV:L → leo thang cục bộ), thay cho chọn tay. *Quy tắc cần được kiểm tra trên mẫu trước khi dùng.*
- Gán CVE cho từng máy: lấy mẫu theo phân phối của KEV, tham số và seed cố định, công bố trước khi chạy.
- NVD, EPSS giới hạn tần suất truy vấn: kiểm tra điều kiện sử dụng và ghi vào tài liệu. *Chưa xác nhận chi tiết; việc của tuần 1–2.*

### 4.1. Snapshot: dùng như thế nào

**Snapshot** là bản sao cố định của dữ liệu công khai tại một ngày, lưu thành file. Dữ liệu nguồn đổi theo thời gian (EPSS cập nhật hằng ngày, KEV có mục mới, NVD có thể điều chỉnh điểm), nên nếu gọi mạng mỗi lần chạy thì kết quả hôm nay và tuần sau sẽ khác và không tái lập được.

**Luồng sử dụng**
1. **Tải một lần** bằng script (đề xuất `scripts/fetch_snapshots.py`): chỉ các CVE cần dùng (thuộc KEV và các CVE trong danh mục), kèm các trường ở bảng trên.
2. **Ghi file và bảng kê** (đề xuất `data/snapshots/<nguồn>_<YYYY-MM-DD>.json` và `data/snapshots/MANIFEST.json`): mỗi file có ngày tải, địa chỉ nguồn, số bản ghi và mã băm SHA-256.
3. **Nạp có kiểm tra** (đề xuất `aapef/data.py`): bộ nạp tính lại SHA-256 và so với bảng kê, từ chối nếu không khớp, rồi dựng bảng `CVE → {vector, epss, trong KEV, ngày vào KEV}`. Đường chạy thí nghiệm **không có mã gọi mạng**.
4. **Dùng trong thí nghiệm:** (a) lấy mẫu CVE gán cho các máy; (b) tính xác suất theo ba mô hình; (c) xếp hạng lỗ hổng cho các chính sách CVSS/EPSS/KEV.
5. **Ghi vết:** mọi file kết quả mang `snapshot_id` (tên và hash), để biết số liệu ứng với dữ liệu ngày nào.
6. **Cập nhật:** muốn dữ liệu mới thì tạo snapshot **mới**, không sửa snapshot cũ. Thí nghiệm chính dùng đúng một snapshot; chạy lại với snapshot thứ hai là một phép kiểm tra "kết luận có đổi theo thời gian không".

*Kích thước, việc có đưa file vào git hay chỉ lưu hash, và điều kiện sử dụng của từng nguồn cần xác nhận khi làm tuần 2.*

## 5. Thiết kế thí nghiệm

1. **Mô hình xác suất đánh giá (sự thật nền của mô phỏng):** M-CVSS (p = E/10), M-EPSS (p = epss), M-KEV (p cao nếu thuộc KEV, ngược lại theo EPSS). Mỗi chính sách vá được đánh giá dưới **cả ba**, không chỉ dưới mô hình trùng nguồn của chính sách đó.
2. **Chỉ số chính:** xác suất thành công của đường tốt nhất còn lại sau k lần vá, R(k), với k = 0…K. Chỉ số phụ: số đường còn lại (top-k), mục tiêu còn tới được hay không.
3. **So sánh:** đường cong R(k) trung bình ± khoảng tin cậy trên N mạng cho mỗi cấu trúc; diện tích dưới đường cong; tỉ lệ thắng theo cặp; kiểm định cặp.
4. **Độ nhạy:** hệ số chuẩn hóa xác suất, xác suất thu thập thông tin, kích thước mạng, số CVE trên mỗi máy, snapshot.
5. **Lưu ý kỹ thuật:** chi phí hiện làm tròn về số nguyên; thí nghiệm dùng chi phí thực (số thực) để tránh méo thứ hạng.

## 6. Công việc cụ thể và mục đích

*Người làm: **C** = Claude; **T** = tác giả. Cột "Xong khi" là tiêu chí nghiệm thu.*

**Tiến độ (cập nhật 2026-10-27, làm sớm hơn lịch):**

| Việc | Trạng thái | Ở đâu |
|---|---|---|
| 2.1 Snapshot | Xong: `2026-10-27:2f4796fced2f` (KEV 1.758, NVD 42.302 = KEV + công bố 2024, EPSS 41.551) | `data/snapshots/`, `scripts/fetch_snapshots.py` |
| 2.2 Bộ nạp kiểm hash | Xong | `aapef/data.py` |
| 2.3 Quy tắc vai trò | Mã xong; nhãn mù do AI gán: khớp 45%, 75% nếu bỏ CVE không cho quyền truy cập. **Phần kiểm tra của T để sau** | `aapef/roles.py`, `reports/ViecCanLam_GanNhanCVE.md` |
| 2.4 Mô hình xác suất | Xong (cvss, epss, kev, native; `p_kev` = 0,9 tạm, chờ T chốt) | `aapef/prob.py` |
| 3.1–3.3 What-if, chính sách, R(k) | Xong; rủi ro = chiếm ít nhất một máy nhạy cảm; A\* + h\_max | `aapef/defense.py`, `aapef/policies.py` |
| 4.1 Top-k đường | Xong theo quy ước "không dùng chung lỗ hổng" | `defense.disjoint_paths` |
| 4.2 Bộ chạy | Xong; chạy thử nhóm N2 và `lab-01` (nhóm V) đầu cuối | `python -m aapef.experiment` |
| 6.2 Thống kê | Mã xong (bootstrap, Wilcoxon chính xác, rank-biserial, tỉ lệ thắng) | `python -m aapef.policy_stats` |
| Chặn bởi T | `prob` trong bộ chuyển đổi (N1); mạng NASim lớn hơn; quy tắc gán CVE nhóm V; chốt `p_kev` | |

### Tuần 1 (26/10–1/11): định vị và thiết kế
| ID | Việc cụ thể | Mục đích | Xong khi | Ai |
|---|---|---|---|---|
| 1.1 | Khảo sát tài liệu: attack graph, lập kế hoạch tấn công, ưu tiên vá lỗ hổng, CVSS/EPSS/KEV | Định vị đóng góp, tránh tuyên bố tính mới sai | Bảng 10–15 nguồn, mỗi nguồn tóm tắt 2 dòng | T (C hỗ trợ tìm) |
| 1.2 | Chốt giả thuyết, chỉ số R(k), danh sách chính sách vá | Công bố trước khi chạy để không chọn theo kết quả | Bản thiết kế 2 trang được duyệt | C soạn, T duyệt |
| 1.3 | Xác nhận điều kiện sử dụng và giới hạn truy vấn của NVD, EPSS, KEV | Dùng dữ liệu đúng quy định, chọn cách tải phù hợp | Ghi chú nguồn và quyết định cách tải | C |

### Tuần 2 (2/11–8/11): lớp dữ liệu và mô hình xác suất
| ID | Việc cụ thể | Mục đích | Xong khi | Ai |
|---|---|---|---|---|
| 2.1 | Script tải snapshot NVD/KEV/EPSS và `MANIFEST.json` (ngày, nguồn, số bản ghi, SHA-256) | Dữ liệu cố định, tái lập được | Chạy script ra file; manifest đủ trường | C |
| 2.2 | Bộ nạp `aapef/data.py`: kiểm hash rồi nạp bảng CVE | Tách dữ liệu khỏi mã; không gọi mạng khi chạy thí nghiệm | Test: hash sai thì từ chối; dữ liệu mẫu nạp đúng | C |
| 2.3 | Quy tắc suy vai trò từ vector CVSS; kiểm tra trên mẫu 50–100 CVE đối chiếu phân loại thủ công | Tránh chọn tay; biết độ chính xác của quy tắc | Báo cáo tỉ lệ khớp; quy tắc được chốt | C làm, T phân loại mẫu |
| 2.4 | Ba nguồn xác suất (CVSS, EPSS, KEV) cắm vào tính chi phí; chi phí số thực | Có thể đánh giá chéo; bỏ méo do làm tròn | Test giá trị trên các CVE đã biết (ví dụ Log4Shell) | C |

### Tuần 3 (9/11–15/11): phân tích phòng thủ
| ID | Việc cụ thể | Mục đích | Xong khi | Ai |
|---|---|---|---|---|
| 3.1 | What-if: loại một CVE hoặc một cạnh topology trên bản sao kịch bản, tính lại đường tốt nhất | Đo tác động của việc vá hoặc phân đoạn | Test: vá CVE trên `lab-01` đổi kết quả đúng như tính tay | C |
| 3.2 | Các chính sách vá (CVSS Base, CVSS Exploitability, EPSS, KEV-trước, theo ngữ cảnh, ngẫu nhiên, vét cạn) | Đối tượng so sánh của RQ1 | Mỗi chính sách trả về thứ tự vá cho một kịch bản | C |
| 3.3 | Hàm R(k) và các chỉ số phụ | Thước đo kết quả | Test R(0) bằng rủi ro ban đầu; R đơn điệu không tăng theo k | C |

### Tuần 4 (16/11–22/11): top-k, bộ chạy, dựng mạng
| ID | Việc cụ thể | Mục đích | Xong khi | Ai |
|---|---|---|---|---|
| 4.1 | Top-k đường tấn công, quy ước độ đa dạng | Phương án thay thế và số đường còn lại | Test: k đường khác nhau theo quy ước | C |
| 4.2 | Bộ chạy thí nghiệm: lưới (cấu trúc mạng × kích thước × seed × chính sách × mô hình xác suất), ghi `snapshot_id` vào kết quả | Chạy hàng loạt và tái lập | Chạy thử nhỏ end to end ra CSV | C |
| 4.3 | Dựng kịch bản mạng cho bốn cấu trúc (phẳng, DMZ, phân đoạn, hình sao) dạng nguồn có `cve` | Dữ liệu mạng cho thí nghiệm | Qua validator, `recost`, benchmark `--strict` | **T** (C kiểm tra đầu ra) |
| 4.4 | Chốt phạm vi: giữ hay bỏ case study và ATT&CK | Quản lý rủi ro tiến độ | Quyết định ghi vào kế hoạch | T, C |

### Tuần 5–6 (23/11–6/12): thí nghiệm và thống kê
| ID | Việc cụ thể | Mục đích | Xong khi | Ai |
|---|---|---|---|---|
| 5.1 | Chạy thí nghiệm chính trên bốn cấu trúc mạng | Trả lời RQ1, RQ2 | Bảng và đường cong R(k) | C |
| 5.2 | Kiểm tra tính hợp lý: so chính sách tham lam với vét cạn ở mạng nhỏ | Phát hiện lỗi mô hình sớm | Báo cáo chênh lệch | C |
| 6.1 | Đánh giá chéo bằng ba mô hình xác suất | Tránh lập luận vòng tròn (RQ3) | Bảng thứ hạng chính sách theo mô hình | C |
| 6.2 | Thống kê: khoảng tin cậy bootstrap, kiểm định cặp, tỉ lệ thắng | Kết luận có độ tin cậy | Bảng thống kê | C |
| 6.3 | Độ nhạy: tham số mô hình và chạy lại với snapshot thứ hai | Kiểm tra kết luận có đổi theo thời gian | Bảng độ nhạy | C |

### Tuần 7 (7/12–13/12): trình bày và case study
| ID | Việc cụ thể | Mục đích | Xong khi | Ai |
|---|---|---|---|---|
| 7.1 | Ánh xạ ATT&CK và "lời kể" đường tấn công | Trình bày theo ngôn ngữ ngành | Mỗi đường in ra kèm kỹ thuật ATT&CK | C |
| 7.2 | Case study trên môi trường công khai (nếu kịp) | Trả lời "có thực tế không" | Một kịch bản mô hình hóa và so sánh | T (C hỗ trợ) |
| 7.3 | Chọn 3–5 ví dụ cụ thể có số (ví dụ "vá CVE X giảm rủi ro Y%") | Có ví dụ để trả lời hội đồng | Danh sách ví dụ có nguồn số liệu | C, T |

### Tuần 8–9 (14/12–27/12): viết và bảo vệ
| ID | Việc cụ thể | Mục đích | Xong khi | Ai |
|---|---|---|---|---|
| 8.1 | Viết luận theo bố cục ở Mục 8 | Hoàn thiện văn bản | Bản nháp đầy đủ | T (C hỗ trợ số liệu) |
| 9.1 | Slide, tài liệu hỏi đáp (`reports/HoiDap_BaoVe.md`), tập trả lời | Sẵn sàng bảo vệ 28/12 | Chạy thử một lần | T, C |
| 9.2 | Dự phòng và sửa lỗi | Đệm cho trễ tiến độ | — | cả hai |

**Mức tối thiểu vẫn bảo vệ được nếu trễ:** bỏ 7.1 và 7.2, giữ 1.x–6.x và viết. Nêu rõ đó là giới hạn.

## 7. Sản phẩm cuối
Mã nguồn tái lập được bằng một lệnh; snapshot dữ liệu cùng bảng kê; báo cáo thực nghiệm; quyển đồ án; slide; tài liệu hỏi đáp.

## 8. Bố cục đồ án đề xuất
Giới thiệu và RQ; kiến thức nền (attack graph, CVSS/EPSS/KEV, quản lý lỗ hổng); mô hình và dữ liệu (kể cả snapshot); thiết kế thí nghiệm; kết quả; thảo luận và hạn chế; kết luận.

## 9. Rủi ro và cách giảm

| Rủi ro | Giảm thiểu |
|---|---|
| Các chính sách không khác nhau nhiều | Báo cáo là kết quả hợp lệ; phân tích điều kiện nào tạo khác biệt |
| Mạng tổng hợp bị phản biện là không thực tế | Case study; nêu rõ giới hạn; dựa trên kiến trúc tham chiếu công khai |
| Lập luận vòng tròn (đánh giá bằng đúng thang đang so sánh) | Đánh giá chéo ba mô hình xác suất (6.1) |
| Quy tắc suy vai trò từ vector kém chính xác | Kiểm tra trên mẫu (2.3); nêu là xấp xỉ |
| Dữ liệu đổi theo thời gian làm kết quả không tái lập | Snapshot có hash (2.1, 2.2); snapshot thứ hai để kiểm tra (6.3) |
| Tính mới chưa xác minh | Khảo sát tài liệu ở 1.1 trước khi tuyên bố; chỉ nói "định lượng và tái lập" |
| Trễ tiến độ | Mức tối thiểu ở Mục 6; chốt phạm vi ở 4.4 |
| Giới hạn truy vấn API | Tải một lần, dùng snapshot |

## 10. Phạm vi và đạo đức
Hoàn toàn là mô phỏng trên dữ liệu công khai: không mã khai thác, không quét hay tấn công hệ thống thật, không cần cyber range. Điểm CVSS/EPSS và danh sách CVE chỉ dùng như dữ liệu chấm điểm. Mô hình hiện đo khả năng bị tấn công thành công, **chưa đo tác động** (giá trị tài sản); đây là giới hạn đã biết và có thể mở rộng bằng trọng số tài sản nếu còn thời gian.
