# AAPEF v2 — Master Plan (Đánh giá chính sách ưu tiên vá lỗ hổng)

**Attack-graph-based Patch-Prioritisation Evaluation trên nền AAPEF**
*Tài liệu lập kế hoạch — phiên bản 1.0 — 2026-10-26. Mọi hạng mục "Sẽ làm" **chưa triển khai**; tên file/module/tham số là **đề xuất**. Thiết kế lõi mô phỏng và thuật toán tìm đường (đã xong) nằm ở `AAPEF_Research_Plan.md`; lịch theo tuần: `reports/KeHoachPhatTrien.md`.*

> **Quy ước đánh dấu:** **[CHỐT]** = đã quyết (do tác giả hoặc đã có trong code) · **[ĐỀ XUẤT]** = đề xuất, chờ tác giả duyệt trước khi làm · **[TÙY CHỌN]** = chỉ làm nếu còn thời gian · **[HOÃN]** = ngoài phạm vi đồ án. **Người làm:** **T** = tác giả; **C** = Claude.
>
> **Phân công cố định [CHỐT]:** việc xây dựng kịch bản mạng và bộ sinh kịch bản (`scen_gen.py`, gán CVE cho máy, hình dạng topology) là việc **của tác giả**. Claude không viết hay sửa mã sinh kịch bản; chỉ viết mã đọc, kiểm tra, đánh giá kịch bản đã có.

---

## 1. Tóm tắt đề tài

**Tên đề tài:** Đánh giá các chính sách ưu tiên vá lỗ hổng (CVSS, EPSS, KEV, theo ngữ cảnh đường tấn công) bằng mô hình attack graph.

**Lĩnh vực:** quản trị rủi ro và phòng thủ (vulnerability management, network hardening). Lỗ hổng là **dữ liệu đầu vào** (CVE, vector CVSS, EPSS, KEV). Đồ án **không** phân tích nguyên nhân lỗ hổng, không viết hay chạy mã khai thác, không tấn công hệ thống thật.

**Vấn đề.** Tổ chức chỉ vá được một phần lỗ hổng. CVSS, EPSS, KEV chấm từng lỗ hổng riêng lẻ, không xét vị trí của lỗ hổng trên đường tới tài sản quan trọng. Chưa rõ trong điều kiện nào việc xét ngữ cảnh đường tấn công đem lại lợi thế so với chỉ xếp hạng theo điểm.

**Cách tiếp cận.** Dùng lõi AAPEF (attack graph dạng không gian trạng thái, chi phí = −ln xác suất thành công) làm *thước đo*: với mỗi kịch bản mạng, đo xác suất thành công của đường tấn công tốt nhất tới mục tiêu (**rủi ro**), rồi so sánh rủi ro còn lại sau khi vá k lỗ hổng theo từng chính sách.

**Câu hỏi nghiên cứu cốt lõi:** *Với ngân sách vá k lỗ hổng trên một mạng cho trước, chính sách chọn nào làm rủi ro đường tấn công tốt nhất còn lại thấp nhất, và kết luận đó phụ thuộc thế nào vào cấu trúc mạng, mô hình xác suất dùng để chấm điểm và thời điểm của dữ liệu?*

**Nguyên tắc:** vẫn theo *Simplicity First* của `AAPEF_Research_Plan.md` §2: thư viện chuẩn Python, hàm nhỏ, tất định, CLI + CSV/JSON; mỗi thành phần mới phải phục vụ trực tiếp một câu hỏi nghiên cứu.

---

## 2. Kiến thức ATTT áp dụng (để trả lời hội đồng)

| Kiến thức ATTT | Thể hiện cụ thể trong đồ án | Nơi trong kế hoạch |
|---|---|---|
| Quản lý lỗ hổng theo rủi ro: vì sao không vá hết được; giới hạn của CVSS Base; EPSS = xác suất bị khai thác; KEV = đã bị khai thác thật | Các chính sách vá và thiết kế so sánh | §6, §8 |
| Giải phẫu chuỗi tấn công: truy cập ban đầu → leo thang đặc quyền → di chuyển ngang → chiếm mục tiêu | Mô hình trạng thái quyền; ánh xạ MITRE ATT&CK (T1190, T1068, T1210) | §5.4, §9 (GĐ 14) |
| Đọc vector CVSS (AV, AC, PR, UI, S) để biết lỗ hổng đóng vai trò gì | Quy tắc suy vai trò từ vector | §5.2 |
| Kiến trúc mạng phòng thủ: DMZ, phân đoạn, điểm nghẽn, mạng phẳng | Bốn cấu trúc mạng; chặn kết nối là phép what-if [TÙY CHỌN] | §7 |
| Thang đo đo cái gì: độ khó khai thác ≠ xác suất thực tế bị khai thác ≠ giá trị tài sản | Ba mô hình xác suất, đánh giá chéo; nêu rõ chưa đo impact | §6.2, §10 |

**Điều không làm và không nhận là làm:** nghiên cứu lỗ hổng, khai thác, kiểm thử xâm nhập thật, môi trường thực nghiệm thật.

---

## 3. Phạm vi, giả định & ranh giới an toàn

### 3.1. Trong phạm vi
Mô phỏng hoàn toàn trên dữ liệu công khai đã lưu snapshot; kịch bản mạng tổng hợp (bốn cấu trúc); phép "vá" = loại bỏ hành động khai thác gắn với một CVE khỏi kịch bản; chỉ số rủi ro dựa trên đường tốt nhất; so sánh chính sách; đánh giá chéo; thống kê; ánh xạ ATT&CK để trình bày.

### 3.2. Ngoài phạm vi — ràng buộc an toàn [CHỐT, bắt buộc]
- Không mã khai thác, không quét hay tấn công hệ thống thật, không lệnh OS, không VM, không cyber range, không AI/ML.
- CVE/CVSS/EPSS/KEV chỉ là **dữ liệu chấm điểm**. Không tuyên bố "kẻ tấn công thật sẽ đi đường này".
- Kết quả chỉ có giá trị **trong mô hình** (mạng tổng hợp, xác suất là xấp xỉ).

### 3.3. Giả định (phải công bố trong luận văn)
1. Xác suất các bước độc lập (rủi ro đường = tích xác suất). Hạn chế đã biết.
2. Kẻ tấn công chọn đường có xác suất thành công cao nhất (tối ưu, biết toàn bộ mạng). Cận trên của rủi ro, không phải hành vi thực.
3. Vá là *hoàn hảo và tức thời*: sau khi vá, hành động khai thác CVE đó không còn.
4. Mỗi chính sách chỉ biết dữ liệu nó được phép dùng (điểm CVSS/EPSS/KEV; riêng chính sách theo ngữ cảnh còn biết topology và mục tiêu). Đây chính là thứ được đo: *giá trị của ngữ cảnh*.
5. Giá trị tài sản (impact) **không** mô hình hóa; mục tiêu là một máy cố định.
6. Hành động thu thập thông tin (không gắn CVE) không vá được và có xác suất cố định p = 0,9 ở mọi mô hình (kế thừa `AAPEF_Research_Plan.md` §9.3).

---

## 4. Hiện trạng: những gì đã có

### 4.1. Phần lõi (xong, đã kiểm thử)
| Hạng mục | Chi tiết | File chính |
|---|---|---|
| Mô hình trạng thái, `state_key`, `applicable`/`apply`/`successors` thuần | State = `{access, known}`, topology và env_facts tĩnh, loại no-op | `aapef/state.py` |
| Nạp + kiểm tra kịch bản JSON | Từ chối access mapping sai; lỗi rõ cho kịch bản nguồn CVE chưa có `cost` | `aapef/scenario.py` |
| 5 thuật toán tìm đường | BFS, DFS, Dijkstra, Greedy, A\* (heuristic admissible và consistent, có test) | `aapef/search.py` |
| Mô phỏng phát lại + kiểm tra goal | Ba cờ `path_found`/`path_valid`/`goal_reached` | `aapef/simulate.py` |
| Benchmark và phân tích | `benchmark --summary`, `|V|`/`|E|` đo riêng, độ nhạy thứ tự action | `aapef/benchmark.py`, `aapef/analyze.py` |
| Chi phí CVSS v3.1 | `cost = round(10·(−ln(E/10)))`, Scope, `recost`, độ nhạy giả định | `aapef/cvss.py`, `scripts/cvss_sensitivity.py` |
| Danh mục CVE thật | 10 CVE từ NVD, vector và ngày KEV, test điểm Exploitability khớp NVD 10/10 | `scenarios/cve_catalog.json` |
| Tái lập | `scripts/reproduce.sh` (8 bước, đã kiểm: cột không phải thời gian giống hệt), 72 test, lint sạch | `scripts/`, `tests/` |

### 4.2. Kịch bản (xong)
- 27 kịch bản chi phí CVSS (`scenarios/benchmark_cvss.json`, `scenarios/cvss/`), cộng bộ cấu hình cũ giữ làm hồi quy (`scenarios/*.json`).
- `lab-01` (4 máy, 9 CVE): **do tác giả công cụ thiết kế** — phải nêu rõ khi báo cáo.
- 11 kịch bản nguồn CVE do bộ sinh của tác giả tạo (`scenarios/gen_cve.sh`): chuỗi 5/6/7 máy, thang kích thước, không tới được, initial-goal, chu trình.
- Đã sửa lỗi `cycles-01` (|V|=198, |E|=621 đúng; bản cũ sai) và có test hồi quy.

### 4.3. Kết quả đã có (của phần AAPEF gốc, dùng làm nền)
- Dijkstra tối ưu và A\*=C\* trên 21/21 kịch bản có đường, giữ qua 7 biến thể giả định chi phí.
- DFS tốn tới ~8×C\*; bẫy Greedy 30 so với 14.
- Đánh đổi L≠C chỉ xuất hiện ở 6/10 kịch bản CVE có đường (đều 4 máy), không xuất hiện ở 11 kịch bản dẫn xuất từ cấu trúc; phụ thuộc cách chuẩn hóa p (6/21 với p=E/10, 10/21 với p=E/3,9).

### 4.4. Tài liệu (xong / dở)
Xong: README, `AAPEF_Research_Plan.md`, `reports/Chuong_KetQua.md`, `reports/ThayDoi_ChiPhiCVSS.md`, `KeHoachPhatTrien.md`. **Dở:** ba báo cáo LaTeX (`BaoCao_TomTat`, `BaoCao_ChiPhi_SinhKichBan`, `BaoCao_LuongHoatDong_ChiPhi`) sửa nửa chừng, chưa commit (tạm dừng theo yêu cầu).

### 4.5. Khoảng trống so với đề tài mới
| Còn thiếu | Cần cho |
|---|---|
| Dữ liệu EPSS và KEV (hiện chỉ có 10 CVE thủ công) | Mọi chính sách, mô hình xác suất |
| Phép "vá" / what-if và đo rủi ro còn lại | Trung tâm của RQ-P1 |
| Chính sách vá và chỉ số R(k) | RQ-P1, RQ-P2 |
| Mô hình xác suất EPSS/KEV, chi phí số thực | RQ-P3 (đánh giá chéo) |
| Bộ chạy thí nghiệm, thống kê | Mọi RQ-P |
| Kịch bản bốn cấu trúc mạng với nhiều CVE thật | RQ-P2 |
| Ánh xạ ATT&CK, khuyến nghị | Phần ATTT trình bày |

---

## 5. Dữ liệu và mô hình xác suất

### 5.1. Nguồn dữ liệu và snapshot
| Dữ liệu | Nguồn | Trường dùng | Ghi chú |
|---|---|---|---|
| CVE, vector CVSS v3.1, điểm | NVD CVE API 2.0 | id, vector, base score, mô tả | đã dùng cho 10 CVE |
| Lỗ hổng bị khai thác thật | CISA KEV | id, ngày thêm | **URL feed cần xác nhận** khi làm GĐ 9 |
| Xác suất bị khai thác | EPSS (FIRST) | epss, percentile, ngày | API đã kiểm tra hoạt động ngày 2026-10-25 (Log4Shell 0,99999; PwnKit 0,949; Dirty COW 0,835) |
| Kỹ thuật tấn công | MITRE ATT&CK | id, tên, chiến thuật | đã xác nhận T1190 Initial Access, T1068 Privilege Escalation, T1210 Lateral Movement |

**Snapshot [ĐỀ XUẤT].** Dữ liệu nguồn đổi theo ngày, nên mọi thí nghiệm đọc từ **bản sao cố định**:
1. `scripts/fetch_snapshots.py` tải một lần, chỉ các CVE cần dùng.
2. Ghi `data/snapshots/<nguồn>_<YYYY-MM-DD>.json` và `data/snapshots/MANIFEST.json` (ngày tải, nguồn, số bản ghi, SHA-256).
3. `aapef/data.py` kiểm hash khi nạp, từ chối nếu không khớp. Đường chạy thí nghiệm **không có mã gọi mạng**.
4. Mọi file kết quả mang `snapshot_id`. Muốn dữ liệu mới thì tạo snapshot mới, không sửa cũ.
5. Cần xác nhận trước khi làm: điều kiện sử dụng và giới hạn truy vấn của từng nguồn; có đưa file snapshot vào git hay chỉ lưu hash.

### 5.2. Vai trò của CVE suy từ vector [ĐỀ XUẤT]
Quy tắc công bố, tất định, để thay việc chọn tay (và để kịch bản không phụ thuộc phán đoán một người):

| Điều kiện trên vector | Vai trò |
|---|---|
| AV:N và PR:N | truy cập ban đầu |
| AV:N và PR:L hoặc PR:H | di chuyển ngang |
| AV:L hoặc AV:P | leo thang cục bộ |
| UI:R | phía máy khách |

*Cần kiểm tra:* đối chiếu với phân loại thủ công trên mẫu 50–100 CVE, báo cáo tỉ lệ khớp, nêu rõ đây là xấp xỉ. Danh mục 10 CVE hiện có dùng `attack_role` gán tay (chuẩn); quy tắc này phải khớp được với chúng như một phép thử đầu tiên.

### 5.3. Ba mô hình xác suất (sự thật nền của mô phỏng) [ĐỀ XUẤT]
Mọi hành động có CVE nhận xác suất `p` từ mô hình đang dùng; chi phí = −ln p (số thực, **không làm tròn**, để không méo thứ hạng). Hành động thu thập: p = 0,9.

| Mô hình | p của hành động gắn CVE | Ý nghĩa |
|---|---|---|
| **M-CVSS** | E/10 (E = Exploitability CVSS v3.1, Scope tính theo vector) | độ dễ khai thác theo đặc tả (đã có) |
| **M-EPSS** | epss của CVE tại ngày snapshot | xác suất bị khai thác thực tế theo dữ liệu |
| **M-KEV** | `p_kev` nếu CVE thuộc KEV, ngược lại epss | ưu tiên bằng chứng khai thác thật; `p_kev` là tham số công bố trước, kiểm tra độ nhạy |

Chi phí số thực được tính trong bộ nhớ từ `cve` + snapshot; **không** ghi đè trường `cost` nguyên của JSON (giữ validator và bộ hồi quy nguyên vẹn).

### 5.4. Ánh xạ ATT&CK [ĐỀ XUẤT, trình bày]
Bảng `vai trò → kỹ thuật`: truy cập ban đầu → T1190; leo thang cục bộ → T1068; di chuyển ngang → T1210. Chỉ để in đường tấn công theo ngôn ngữ ngành, không ảnh hưởng số liệu.

---

## 6. Câu hỏi nghiên cứu, giả thuyết, đại lượng đo

### 6.1. Hai tầng câu hỏi
- **Tầng A (đã xong, nền):** RQ-A1…A4 = RQ1…RQ4 của `AAPEF_Research_Plan.md` §4 (tính tối ưu chi phí/độ dài, search effort, robustness của 5 thuật toán).
- **Tầng P (mới, trọng tâm):** RQ-P1…P3 dưới đây. *Trong `KeHoachPhatTrien.md` và `MasterPlan` bản trước, RQ-P1…P3 được ghi là RQ1…RQ3.*

| RQ | Câu hỏi | Giả thuyết |
|---|---|---|
| **RQ-P1** | Với ngân sách vá k, chính sách nào (CVSS Base, CVSS Exploitability, EPSS, KEV-trước, theo ngữ cảnh, ngẫu nhiên) cho rủi ro còn lại thấp nhất? | **H1:** chính sách theo ngữ cảnh không kém các chính sách dùng điểm đơn lẻ và vượt rõ khi mạng có điểm nghẽn. |
| **RQ-P2** | Cấu trúc mạng (phẳng, DMZ + nội bộ, phân đoạn, hình sao) và kích thước ảnh hưởng thế nào đến chênh lệch? | **H2:** chênh lệch thu hẹp ở mạng phẳng (mọi máy ngang hàng, nhiều đường song song). |
| **RQ-P3** | Thứ hạng chính sách có bền khi đổi mô hình xác suất đánh giá và đổi snapshot? | **H3:** thứ hạng thay đổi ít; nếu đổi nhiều thì đó là kết quả cần báo cáo. |

Giả thuyết được công bố **trước khi chạy**. Kết quả "không khác biệt" hoặc ngược giả thuyết vẫn là kết luận hợp lệ và sẽ được báo cáo trung thực.

### 6.2. Đại lượng đo [ĐỀ XUẤT] (phân biệt, không trộn lẫn)
| Ký hiệu | Định nghĩa |
|---|---|
| **P\*(S)** | Xác suất thành công của đường tốt nhất trong kịch bản S dưới mô hình M: `P* = exp(−C*)`, với C\* = tổng chi phí số thực nhỏ nhất (Dijkstra). Không có đường → P\* = 0. |
| **R(k)** | P\* của kịch bản sau khi áp bộ vá gồm k đơn vị đầu tiên của chính sách. R(0) = rủi ro ban đầu; R không tăng theo k. |
| **AUC** | Diện tích dưới R(k), k = 0…K (càng nhỏ càng tốt). Chuẩn hóa theo R(0) khi so các mạng khác nhau. |
| **k\_block** | k nhỏ nhất làm R(k) = 0 (mục tiêu không còn tới được); "∞" nếu chưa đạt trong K. |
| **Tỉ lệ thắng** | Với mỗi cặp chính sách, tỉ lệ mạng mà chính sách này có AUC nhỏ hơn. |

Dùng `log R` khi trình bày (xác suất nhỏ cỡ 10⁻⁶ trở xuống là bình thường).

---

## 7. Mô hình phòng thủ (what-if) và chính sách vá

### 7.1. Đơn vị vá [ĐỀ XUẤT]
- **Đơn vị chính:** cặp (CVE, máy đích), tức mọi hành động có `cve` = CVE đó và có `set_access` lên máy đích đó. Một lần vá loại các hành động này khỏi bản sao kịch bản. Lý do: thực tế vá theo từng máy.
- **Biến thể [TÙY CHỌN]:** vá theo CVE trên toàn mạng (cập nhật cả đội máy); **chặn kết nối** (bỏ một cạnh topology) cho phân tích phân đoạn.
- Hành động không gắn CVE không vá được.

### 7.2. What-if (hàm thuần) [ĐỀ XUẤT]
```
patch(scenario, units)  -> scenario'      # bản sao, bỏ các hành động thuộc units; không sửa bản gốc
risk(scenario, model)   -> P*             # Dijkstra với chi phí số thực của model; 0 nếu không có đường
```
Tái dùng `successors`/Dijkstra hiện có; không thêm logic transition thứ hai.

### 7.3. Các chính sách [ĐỀ XUẤT]
Mỗi chính sách nhận (kịch bản, snapshot, K) và trả danh sách thứ tự các đơn vị vá. Chỉ **chính sách theo ngữ cảnh** và **vét cạn** được xem topology/mục tiêu; các chính sách còn lại chỉ thấy điểm của CVE (đây là thứ được đo: giá trị của ngữ cảnh).

| Chính sách | Quy tắc xếp hạng | Biết ngữ cảnh? |
|---|---|---|
| CVSS-Base | điểm Base giảm dần | không |
| CVSS-Exploit | điểm Exploitability giảm dần | không |
| EPSS | epss giảm dần | không |
| KEV-first | thuộc KEV trước, trong nhóm theo epss | không |
| Context-greedy(M) | mỗi bước chọn đơn vị làm P\* (dưới M) giảm nhiều nhất; hòa thì theo thứ tự cố định | có |
| Random | thứ tự ngẫu nhiên, seed cố định, lấy trung bình nhiều seed | không |
| Optimal (vét cạn) | tập k đơn vị làm P\* nhỏ nhất | có; chỉ với mạng nhỏ |

Quy tắc hòa của mọi chính sách: theo mã CVE rồi tên máy, để tất định.

**Ghi chú về công bằng.** Context-greedy(M) tự dùng mô hình M để đánh giá, nên khi chấm bằng đúng M nó có lợi thế "tự chấm". Vì vậy mỗi chính sách được chấm dưới **cả ba** mô hình (đánh giá chéo, §8), và Context-greedy được chạy ở cả ba biến thể.

Bài toán chọn tập vá tối thiểu để chặn mọi đường được biết là khó (NP-khó) trong tài liệu về network hardening; vì vậy dùng tham lam cho mạng lớn và vét cạn cho mạng nhỏ để đối chiếu. *Cần dẫn nguồn khi viết luận; chưa kiểm chứng.*

---

## 8. Thiết kế thí nghiệm [ĐỀ XUẤT]

### 8.1. Họ kịch bản
| Cấu trúc | Đặc điểm | Dự kiến kiểm tra |
|---|---|---|
| Phẳng | mọi máy ngang hàng, nhiều đường song song | H2: chính sách khó phân biệt |
| DMZ + nội bộ | một cửa vào, nội bộ phía sau | ngữ cảnh đáng giá nếu mọi đường qua cùng điểm |
| Phân đoạn | nhiều vùng nối qua cổng | vị trí điểm nghẽn |
| Hình sao | một máy trung tâm | điểm nghẽn cực đoan |

Kích thước 10–50 máy, nhiều seed mỗi cấu trúc. **Việc dựng các kịch bản này (kể cả gán CVE cho máy) là của T** (§9, GĐ 12). Quy tắc gán công bố trước khi chạy để không chọn theo kết quả. Đi kèm `lab-01` như một ví dụ minh họa (do tác giả công cụ thiết kế), không đưa vào thống kê chính.

### 8.2. Lưới thí nghiệm
`cấu trúc × kích thước × seed × chính sách × mô hình đánh giá`. Với mỗi bộ: ghi R(k) với k = 0…K, AUC, k\_block, `snapshot_id`, seed. K cố định trước (ví dụ K = 10; chốt ở GĐ 9).

### 8.3. Thống kê
- Đường cong R(k) trung bình (theo log) kèm khoảng tin cậy bootstrap qua các mạng.
- So sánh cặp: tỉ lệ thắng, kiểm định cặp (Wilcoxon signed-rank) trên AUC; báo cáo cỡ hiệu ứng, không chỉ p-value.
- Đối chiếu Context-greedy với Optimal trên mạng nhỏ: báo cáo độ lệch.

### 8.4. Đánh giá chéo và độ nhạy (RQ-P3)
- Bảng thứ hạng chính sách theo từng mô hình đánh giá. H3 đúng nếu thứ hạng ổn định.
- Độ nhạy: `p_kev`, hệ số chuẩn hóa, p thu thập, kích thước mạng, số CVE mỗi máy, **snapshot thứ hai** (cách ít nhất vài ngày để dữ liệu đổi).

### 8.5. Phép kiểm tra tính hợp lý trước khi tin số liệu
1. Mạng nhỏ tính tay: R(k) khớp phép tính thủ công.
2. R(0) trùng P\* tính từ `exp(−C*)` của Dijkstra hiện có (làm tròn chi phí nguyên cho sai khác nhỏ, có kiểm tra).
3. R(k) không tăng theo k với mọi chính sách.
4. Optimal ≤ mọi chính sách khác tại cùng k.
5. Random trung bình nằm giữa; chính sách "tệ nhất có chủ đích" kém hơn Random (kiểm tra thước đo nhạy).

---

## 9. Kiến trúc mở rộng, module và lộ trình

### 9.1. Workflow mới
```
Snapshot (NVD/KEV/EPSS, có hash)  ──┐
Kịch bản mạng (T dựng, có cve)  ────┼→ prob model → risk P* → [policy → patch → risk]×k → R(k)/AUC → thống kê → bảng/đồ thị
                                     └→ ánh xạ ATT&CK cho đường tốt nhất (trình bày)
```

### 9.2. Module mới [ĐỀ XUẤT; được gộp nếu đơn giản hơn]
| Module | Trách nhiệm duy nhất | Ngoài phạm vi |
|---|---|---|
| `aapef/data.py` | nạp snapshot, kiểm hash, bảng `CVE → {vector, epss, kev, ngày}` | gọi mạng khi chạy thí nghiệm |
| `scripts/fetch_snapshots.py` | tải và ghi snapshot + manifest | chạy trong đường thí nghiệm |
| `aapef/prob.py` | ba mô hình xác suất, chi phí số thực, quy tắc vai trò | sửa `cost` nguyên của JSON |
| `aapef/defense.py` | `patch`, `risk`, liệt kê đơn vị vá | logic transition mới |
| `aapef/policies.py` | các chính sách §7.3 | huấn luyện, học máy |
| `aapef/experiment.py` | lưới chạy, R(k), AUC, thống kê, xuất CSV | cơ sở dữ liệu, dashboard |
| `aapef/attck.py` | vai trò → kỹ thuật, in đường tấn công | số liệu |

Lệnh CLI [ĐỀ XUẤT]: `python -m aapef patch-eval --policy P --model M --k K scenario.json`, `python -m aapef experiment --config experiments/main.json`.

### 9.3. Lộ trình (26/10 → bảo vệ 28/12/2026)
Số GĐ tiếp nối GĐ 0–8 đã xong. Tiêu chí nghiệm thu chi tiết từng việc: `KeHoachPhatTrien.md` §6.

| GĐ | Tuần | Nội dung | Sản phẩm | Nghiệm thu | Ai |
|---|---|---|---|---|---|
| **9** | 1 (26/10–1/11) | Định vị: khảo sát 10–15 nguồn; chốt giả thuyết, R(k), danh sách chính sách, K; xác nhận điều kiện dữ liệu | Bản thiết kế 2 trang; bảng nguồn | T duyệt (mốc M1) | C soạn, T duyệt, T/C khảo sát |
| **10** | 2 (2/11–8/11) | Dữ liệu: `fetch_snapshots.py`, manifest, `data.py`, quy tắc vai trò + kiểm mẫu, `prob.py` ba mô hình | Snapshot có hash; nạp có kiểm hash | Test hash sai thì từ chối; giá trị mẫu khớp (mốc M2) | C (T phân loại mẫu) |
| **11** | 3 (9/11–15/11) | Phòng thủ: `patch`, `risk`, chính sách §7.3, R(k), AUC, k\_block | Mô-đun `defense`, `policies` | Phép kiểm §8.5 mục 1–4 pass | C |
| **12** | 3–4 (9/11–22/11) | **Dựng kịch bản bốn cấu trúc mạng nguồn CVE; quy tắc gán CVE** | Kịch bản qua validator, `recost`, `benchmark --strict` | Mốc M3 | **T** (C chỉ kiểm tra đầu ra) |
| **13** | 4 (16/11–22/11) | Bộ chạy thí nghiệm, top-k đường, chạy thử nhỏ end to end | `experiment.py`, CSV | Chạy thử ra CSV có `snapshot_id` (mốc M3) | C |
| **14** | 5–6 (23/11–6/12) | Thí nghiệm chính; đối chiếu Optimal; đánh giá chéo; thống kê; độ nhạy + snapshot thứ hai | Bảng RQ-P1…P3 | Mốc M4 | C |
| **15** | 7 (7/12–13/12) | Ánh xạ ATT&CK; khuyến nghị theo loại mạng; 3–5 ví dụ có số; case study môi trường công khai nếu kịp | Đầu ra đọc như báo cáo ATTT | — | C, T |
| **16** | 8–9 (14/12–27/12) | Viết luận, slide, tài liệu hỏi đáp; dự phòng | Bản nộp, bảo vệ 28/12 | Mốc M5 (20/12: nháp đủ chương) | T (C hỗ trợ số liệu) |

**Mức tối thiểu vẫn bảo vệ được nếu trễ:** GĐ 9–14 và viết; bỏ GĐ 15 (ATT&CK, case study). Quyết định giữ/bỏ chốt ở cuối GĐ 13.

**Hướng mở rộng (chọn tối đa một, nếu còn thời gian):** chọn tập vá tối ưu dưới ngân sách ở quy mô lớn hơn; thêm giá trị tài sản (impact) vào rủi ro; case study một môi trường có tài liệu công khai (mô hình hóa từ mô tả, không chạy).

**Việc song song, không thuộc critical path:** hoàn thiện ba báo cáo LaTeX (đang tạm dừng theo yêu cầu T); viết lại chương kết quả cho đề tài mới; biểu đồ từ `out/scaling/analysis.csv`.

---

## 10. Chiến lược test & tiêu chí nghiệm thu

### 10.1. Test mới (pytest) [ĐỀ XUẤT]
- **Snapshot:** hash sai → từ chối; thiếu trường → lỗi rõ; nạp không gọi mạng.
- **Mô hình xác suất:** M-CVSS cho p = E/10 khớp `cvss.py`; M-EPSS/M-KEV trả giá trị đúng trên dữ liệu mẫu; hành động thu thập luôn p = 0,9.
- **Vai trò:** quy tắc §5.2 phân loại đúng 10 CVE của danh mục (hoặc ghi rõ ngoại lệ).
- **`patch`:** không sửa kịch bản gốc; vá một đơn vị trên `lab-01` làm P\* đổi đúng như tính tay.
- **`risk`:** R(0) khớp `exp(−C*)`; không có đường → 0.
- **Chính sách:** thứ tự tất định; Optimal ≤ các chính sách khác; R(k) không tăng theo k.
- **Runner:** chạy lại cho CSV giống hệt (cùng seed, cùng snapshot).
- Toàn bộ 72 test hiện có vẫn pass.

### 10.2. Tiêu chí nghiệm thu đồ án
1. `reproduce.sh` (mở rộng) tái tạo toàn bộ bảng RQ-A và RQ-P từ snapshot đã lưu; cột không phải thời gian giống hệt.
2. Mọi file kết quả mang `snapshot_id`, seed, tham số.
3. Có đủ sáu chính sách, ba mô hình đánh giá, bốn cấu trúc mạng.
4. Báo cáo nêu đúng các giả định §3.3 và giới hạn §11.
5. Thiết kế (giả thuyết, chỉ số, K) có ngày thấp hơn ngày chạy thí nghiệm chính (công bố trước).

---

## 11. Rủi ro & giảm thiểu

| Rủi ro | Giảm thiểu |
|---|---|
| Các chính sách không khác nhau | Báo cáo là kết quả hợp lệ; phân tích điều kiện nào tạo khác biệt (H2) |
| Mạng tổng hợp bị phản biện là không thực tế | Nêu rõ giới hạn; dựa trên kiến trúc tham chiếu công khai; case study nếu kịp; không tuyên bố ngoài mô hình |
| Lập luận vòng tròn (chấm bằng đúng thang đang so sánh) | Đánh giá chéo ba mô hình; Context-greedy chạy ở cả ba biến thể |
| Mô hình thiên về chính sách theo ngữ cảnh vì nó biết mạng | Nêu là phần được đo (giá trị ngữ cảnh); so với Optimal để biết còn dư địa |
| Quy tắc suy vai trò kém chính xác | Kiểm mẫu (GĐ 10); nêu là xấp xỉ |
| Quy tắc gán CVE cho máy làm lệch kết quả | Công bố trước; chạy nhiều quy tắc/seed; do T phụ trách và ghi rõ |
| Dữ liệu đổi theo thời gian | Snapshot có hash; snapshot thứ hai để kiểm tra |
| Xác suất cực nhỏ (EPSS) gây lỗi số | Làm việc ở không gian log (chi phí −ln p), báo cáo log R |
| Tính mới chưa xác minh | Khảo sát ở GĐ 9 trước khi tuyên bố; chỉ nói "định lượng và tái lập" nếu chưa có bằng chứng khác |
| Điều kiện sử dụng/giới hạn truy vấn dữ liệu chưa rõ | Xác nhận ở GĐ 9; tải một lần |
| Trễ tiến độ (còn ~9 tuần) | Mức tối thiểu §9.3; mốc M1…M5; dựng mạng (T) song song với mã (C) |
| Phụ thuộc vào việc dựng mạng của T | GĐ 12 chồng lên GĐ 11/13; có `lab-01` và 11 kịch bản CVE làm dữ liệu thử cho mã |

**Giới hạn phải nêu trong luận văn:** mô phỏng trên dữ liệu công khai; mạng tổng hợp; CVSS/EPSS chỉ là xấp xỉ khả năng khai thác; giả định độc lập giữa các bước; kẻ tấn công tối ưu; vá hoàn hảo; chưa có impact; `lab-01` do tác giả công cụ thiết kế; tính mới chưa được xác minh bằng khảo sát đầy đủ.

---

## 12. Bảng quyết định

| Hạng mục | Trạng thái |
|---|---|
| Đề tài: đánh giá chính sách ưu tiên vá bằng attack graph (hướng quản trị rủi ro) | **[CHỐT]** |
| Mô phỏng thuần, dữ liệu công khai, không cyber range | **[CHỐT]** |
| Lõi AAPEF (state, 5 thuật toán, chi phí CVSS) giữ nguyên | **[CHỐT]** |
| Kịch bản mạng và bộ sinh do T làm | **[CHỐT]** |
| Snapshot có hash, chạy không gọi mạng | **[ĐỀ XUẤT]** |
| Ba mô hình xác suất M-CVSS/M-EPSS/M-KEV, chi phí số thực | **[ĐỀ XUẤT]** |
| Đơn vị vá = (CVE, máy đích) | **[ĐỀ XUẤT]** |
| Chỉ số R(k), AUC, k\_block | **[ĐỀ XUẤT]** |
| Bảy chính sách §7.3 | **[ĐỀ XUẤT]** |
| Quy tắc suy vai trò từ vector | **[ĐỀ XUẤT]** (cần kiểm mẫu) |
| Wilcoxon + bootstrap cho thống kê | **[ĐỀ XUẤT]** |
| Vá theo CVE toàn mạng; chặn cạnh topology | **[TÙY CHỌN]** |
| Ánh xạ ATT&CK, case study | **[TÙY CHỌN]** (chốt giữ/bỏ cuối GĐ 13) |
| Giá trị tài sản (impact) | **[HOÃN]** |
| Học máy, khai thác thật, cyber range | **[HOÃN]/ngoài phạm vi** |

---

## 13. Quyết định cần tác giả phê duyệt

1. **Đơn vị vá** = (CVE, máy đích), chứ không phải CVE toàn mạng? *(khuyến nghị: Có)*
2. **Bảy chính sách** ở §7.3 và **ba mô hình đánh giá** ở §5.3: đủ chưa, bớt gì? *(khuyến nghị: giữ nguyên; bớt Optimal nếu quá tốn thời gian)*
3. **`p_kev`** và **K** (ngân sách vá tối đa): giá trị nào? *(đề xuất K = 10; `p_kev` chốt ở GĐ 9 cùng độ nhạy)*
4. **Snapshot vào git** hay chỉ lưu hash và script tải? *(phụ thuộc điều kiện sử dụng và kích thước; xác nhận ở GĐ 9)*
5. **Phân công GĐ 12:** T dựng bốn cấu trúc mạng và quy tắc gán CVE; C chỉ kiểm tra đầu ra. *(đã thống nhất; xác nhận lịch 9/11–22/11)*
6. **Ưu tiên khi trễ:** bỏ ATT&CK/case study trước, giữ nguyên thí nghiệm chính? *(khuyến nghị: Có)*
7. **Phiếu giao nhiệm vụ (`Student name.xlsx`, sheet `Cử nhân`):** nội dung tên đề tài và mục 3.1–3.5, Nội dung 1–5 đã khớp đề tài này nên không cần đổi; ô "Lĩnh vực" **bỏ qua** theo quyết định của T.

---

### Điều kiện hoàn thành (self-check của kế hoạch)
- ✅ Phân biệt rõ đã có (§4) và sẽ làm (§5–9), đánh dấu trạng thái từng hạng mục (§12).
- ✅ RQ-P đo lường được, có giả thuyết công bố trước và đại lượng đo xác định (§6).
- ✅ Hai vai trò của nguồn xác suất tách biệt (chính sách so với thước đo), có đánh giá chéo (§7.3, §8.4).
- ✅ Kiểm tra tính hợp lý trước khi tin số liệu (§8.5), test và tiêu chí nghiệm thu (§10).
- ✅ Phân công rõ: việc dựng kịch bản mạng là của T (§9.3 GĐ 12).
- ✅ Giới hạn, giả định và điều chưa xác minh được nêu thẳng (§3.3, §5.1, §7.3, §11).
- ✅ Không exploit/VM/cyber range/AI-ML (§3.2); không thêm thành phần không phục vụ RQ (mỗi module ở §9.2 gắn với một RQ).
- ✅ Phù hợp ~9 tuần còn lại, có mức tối thiểu và mốc kiểm soát (§9.3).
