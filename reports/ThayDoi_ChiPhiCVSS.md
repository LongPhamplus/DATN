# Thay đổi: chuyển sang chi phí dẫn xuất từ CVSS v3.1

*Ngày 2026-10-22 · Bước 1 (chi phí dẫn xuất từ cấu trúc): `c72c346` (Plan), `22b121b` (mã), `85a5b31` (kịch bản + benchmark), `3b15125` (reproduce.sh). Bước 2 (vector CVE thật từ NVD): `d0d7480` (mã + danh mục), `5b3f17b` (lab-01 + kết quả), `fc24ea3`, `efc4a75` (tài liệu).*

> **Cập nhật:** Mục 1–8 mô tả bước 1 (thời điểm chưa dùng vector CVE thật). Bước 2 đã được thực hiện sau khi bạn chọn hướng "chấp nhận kết quả + vector CVE thật"; xem **Mục 9** cho những gì thay đổi thêm và kết quả mới. Các câu "đánh đổi biến mất ở mọi kịch bản" ở Mục 4–5 đúng cho 11 kịch bản dẫn xuất từ cấu trúc và có ngoại lệ `lab-01` (Mục 9).

## 1. Vì sao thay đổi

Chi phí hành động trước đây do người thiết kế gõ tay (kịch bản viết tay) hoặc rút ngẫu nhiên theo seed trong các khoảng tự chọn (`scen_gen.py`). Đó là phán đoán cá nhân, không có căn cứ trích dẫn, và hội đồng có thể hỏi "con số lấy từ đâu". Chi phí nay được **tính bằng một công thức công khai** từ vector CVSS v3.1 (FIRST). Mọi con số truy ngược được về một bảng hệ số cố định trong đặc tả.

## 2. Mô hình chi phí mới

```
E    = 8,22 × AV × AC × PR × UI         (Exploitability, CVSS v3.1, Scope Unchanged)
p    = E / 10                           (xác suất thành công; E tối đa ≈ 3,887 nên p ≤ 0,389)
cost = round(10 × (−ln p))              (số nguyên ≥ 0)
```

−ln biến tích xác suất thành tổng, nên tổng chi phí của một đường đi ≈ −10·ln(xác suất thành công cả đường) nếu các bước độc lập. Dijkstra và A\* vì vậy tìm *đường có xác suất thành công cao nhất*.

**Vector được dẫn xuất từ cấu trúc của chính action** (không ai gõ số):

| Thành phần | Quy tắc |
|---|---|
| AV | `N` nếu action có precondition `reachable`, ngược lại `L` |
| PR | mức cao nhất trong các `access_at_least` (`none`→`N`, `user`→`L`, `admin`→`H`); không có → `N` |
| AC, UI | mặc định công bố `L`, `N` (đổi được bằng tham số) |
| Ghi đè | trường tùy chọn `cvss_override` cho từng action (một phần của vector) |
| Action thu thập thông tin (chỉ có `learn`) | CVSS chấm lỗ hổng nên không áp dụng; dùng p = 0,9 → chi phí 1 |

Các chi phí kết quả chỉ có bốn giá trị: **1** (thu thập), **13** (chiếm quyền từ xa, cần quyền `user`: N/L/L/N), **14** (chiếm quyền không cần quyền và không qua mạng: L/L/N/N), **17** (leo thang cục bộ: L/L/L/N).

**Giả định phải công bố trong luận văn:** Scope Unchanged; AC=L, UI=N mặc định; p = E/10; hệ số 10; p thu thập = 0,9; các bước độc lập; vector dẫn xuất từ cấu trúc chỉ là *xấp xỉ* (quyền ở máy nguồn không hoàn toàn là "quyền cần có" theo nghĩa CVSS).

## 3. Những gì đã thay đổi

### 3.1. Tài liệu
- `AAPEF_Research_Plan.md`: định nghĩa C (§4.1); §9.2 viết lại (CVSS là mô hình chính, chi phí cấu hình cũ giữ làm bộ hồi quy); **§9.3 mới** (công thức, quy tắc, giả định, hệ quả, hạn chế); bảng rủi ro, bảng quyết định, §17 và bảng trạng thái (dòng 6b).

### 3.2. Mã nguồn
| File | Thay đổi |
|---|---|
| `aapef/cvss.py` (mới) | công thức, bảng hệ số, dẫn xuất vector, `recost_scenario` (idempotent), kiểm tra tham số mô hình |
| `aapef/scenario.py` | validator kiểm tra `cvss` (vector đầy đủ) và `cvss_override` (một phần) |
| `aapef/cli.py` | lệnh mới `recost` (tham số: `--scale`, `--p-norm`, `--discovery-p`, `--default-ac`, `--default-ui`) |
| `scripts/recost_all.sh`, `scripts/cvss_sensitivity.py` (mới) | tính lại toàn bộ kịch bản; phân tích độ nhạy theo giả định |
| `scripts/reproduce.sh` | thêm bước 7 và 8 (CVSS); chạy lại toàn bộ, mọi cột không phải thời gian giống hệt |
| `tests/test_aapef.py` | +12 test (tổng **54**): giá trị theo đặc tả, đơn điệu theo độ khó, dẫn xuất, ghi đè, tham số, idempotent, validator, CLI, biên chi phí 9–44 |

### 3.3. Dữ liệu
- `scenarios/cvss/` (15 kịch bản đã tính lại; **bản gốc không đổi**), `scenarios/benchmark_cvss.json`.
- `out/cvss/`: `results.csv`, `analysis.csv`, `statespace.csv`, `order_sensitivity.csv`, `assumption_sensitivity.csv`.
- `scen_gen.py` **không bị sửa**: bộ sinh vẫn tạo cấu trúc; chi phí nó ghi ra chỉ còn là giá trị tạm, bị `recost` ghi đè ở bước sau. Các giá trị tham chiếu trong `scenarios/meta/` (C\*, L\*...) thuộc mô hình cũ.

## 4. Kết quả sau khi tính lại (chưa dùng `cvss_override`)

### 4.1. Chi phí đường đi: trước và sau

| Kịch bản | C\* cũ → mới | BFS cũ → mới | Greedy cũ → mới | DFS cũ → mới |
|---|---|---|---|---|
| `demo-small-01` | 9 → 28 | 9 → 28 | 9 → 28 | 9 → 28 |
| `medium-01` | 6 → 13 | 10 → **13** | 10 → **13** | 6 → 28 |
| `large-01` | 7 → 13 | 9 → **13** | 9 → **13** | 10 → 43 |
| `size-v132` | 15 → 14 | 40 → **14** | 40 → **14** | 15 → 55 |
| `size-v11264` | 18 → 14 | 43 → **14** | 43 → **14** | 18 → 55 |
| `trap-01` | 15 → 14 | 40 → **14** | 44 → **30** | 15 → 55 |
| `trap-02` | 32 → 14 | 71 → **14** | 79 → **30** | 32 → 83 |
| `cycles-01` | 30 → 14 | 65 → **14** | 65 → **14** | 30 → 83 |

(DFS lấy theo thứ tự khai báo gốc.)

### 4.2. Công sức tìm kiếm ($E_n$), thang kích thước

| Kịch bản | \|V\| | Dijkstra cũ → mới | A\* cũ → mới |
|---|---:|---|---|
| `size-v132` | 132 | 72 → 17 | 58 → 5 |
| `size-v1026` | 1 026 | 329 → 17 | 154 → 5 |
| `size-v3024` | 3 024 | 1 058 → 129 | 526 → 8 |
| `size-v11264` | 11 264 | 3 694 → 2 049 | 2 291 → **12** |

### 4.3. Độ nhạy theo giả định (`out/cvss/assumption_sensitivity.csv`)

Bảy biến thể: mặc định, hệ số ×100, p chuẩn hóa 3,9 (thay vì 10), p thu thập 0,5 và 0,99, AC mặc định `H`, UI mặc định `R`. Trên 11 kịch bản có đường đi, ở **cả bảy biến thể**: đánh đổi L ≠ C xuất hiện **0/11**, A\* đạt C\* **11/11**, Dijkstra tối ưu chi phí **11/11**. Thứ tự hành động: BFS/Dijkstra/A\* giữ nguyên giá trị tối ưu, DFS dao động (ví dụ `trap-02`: chi phí 14–111, tức tới 7,9 lần C\*).

## 5. Tác động lên các kết luận

**Vẫn đứng vững** (không phụ thuộc mô hình chi phí):
- Dijkstra và A\* đạt chi phí tối ưu; BFS đạt số bước tối thiểu; mọi đường đi đều hợp lệ.
- DFS nhạy mạnh với thứ tự hành động (chi phí tới khoảng 8 lần C\* qua 51 thứ tự), trong khi BFS, Dijkstra và A\* giữ nguyên giá trị tối ưu.
- Greedy vẫn có thể bị dẫn vào tuyến tệ hơn tối ưu ở `trap-01/02` (30 so với 14), dù khoảng cách nhỏ hơn trước.
- Các trường hợp biên (vô nghiệm, đã thỏa mục tiêu, trạng thái trùng, no-op).

**Không còn đúng và cần viết lại:**
1. **Đánh đổi L ≠ C biến mất ở mọi kịch bản.** Trước đây tính chất này được *dựng sẵn* (tuyến trực tiếp luôn đắt hơn); nay, vì mọi hành động chiếm quyền gần như cùng chi phí (13), tuyến ít bước đồng thời là tuyến rẻ nhất và BFS, Dijkstra, A\* cho cùng chi phí. Câu "BFS/Greedy tốn gấp 2,2–2,9 lần chi phí tối ưu" **không còn đúng**.
2. **Đường cong RQ3 phụ thuộc mô hình chi phí.** Dijkstra không còn tăng gần tuyến tính theo \|V\|: công sức của nó nay chủ yếu do số *mồi nhử rẻ* (chi phí 1) quyết định (17 trạng thái ở `size-v1026` không có mồi nhử, 2 049 ở `size-v11264` có 9 mồi nhử), không phải do \|V\|. A\* tiết kiệm mạnh hơn nhiều (A\*/Dijkstra là 0,29 ở \|V\|=132 và 0,006 ở \|V\|=11 264, trước đây 0,47–0,81) vì heuristic (chi phí rẻ nhất của hành động nâng quyền = 13) nay gần như sát chi phí thật.
3. Mọi con số C, C\*, các bảng RQ1–RQ3 trong `Chuong_KetQua.md`, `BaoCao_PhanTich.md`, `BaoCao_TomTat.tex`, `BaoCao_ChiPhi_SinhKichBan.tex` **đang là số liệu của mô hình cũ và chưa được cập nhật**. Plan đã đánh dấu điều này.

**Vì sao đánh đổi gần như không thể xuất hiện** (hệ quả của mô hình, không phải lỗi): vector khó nhất của CVSS (AV:P/AC:H/PR:H/UI:R) cho chi phí tối đa **44**, trong khi một bước chiếm quyền thông thường là 13. Tuyến một bước chỉ có thể đắt hơn tuyến nhiều bước khi tuyến kia có tối đa khoảng 3 bước thông thường. Nghĩa là trong mô hình xác suất, *thêm bước gần như luôn làm giảm xác suất thành công*, nên đường ngắn thường tốt hơn. Đây là một nhận xét có ý nghĩa của riêng nó.

## 6. Hạn chế

- CVSS chấm *lỗ hổng*, không chấm hành động; điểm khai thác đo mức dễ khai thác, không phải rủi ro; giả định độc lập giữa các bước; chi phí không phản ánh độ khó thực của một cuộc tấn công cụ thể.
- Vector dẫn xuất từ cấu trúc là xấp xỉ; AC và UI chưa được phân biệt giữa các hành động (đều `L`, `N`), nên chi phí chỉ có bốn giá trị và khá phẳng.
- Chưa có kịch bản nào dùng `cvss_override`, nên chưa có kịch bản có đánh đổi L ≠ C.

## 7. Cần bạn quyết định *(đã giải quyết: chọn hướng 1 + 3b, xem Mục 9)*

1. **Chấp nhận kết quả "đánh đổi biến mất" và viết lại luận văn theo hướng đó** (khuyến nghị: trung thực, và tránh bị phản biện "tính chất được dựng sẵn"): kết luận RQ1/RQ2 chuyển thành "trong mô hình xác suất CVSS, BFS, Dijkstra, A\* trùng nhau về chi phí; điểm khác biệt nằm ở DFS (phụ thuộc thứ tự) và Greedy (có thể bị bẫy); đánh đổi L ≠ C chỉ xuất hiện khi một bước có xác suất thấp bất thường".
2. **Thêm một số kịch bản có `cvss_override` được giải thích theo định nghĩa CVSS** (ví dụ tuyến trực tiếp đòi `UI:R` và `AC:H`) để khảo sát khi nào L ≠ C xuất hiện. Mỗi ghi đè phải kèm lý do; không chỉnh số để ép ra kết quả.
3. **Nâng độ chi tiết của vector** (phân biệt AC, UI giữa các hành động) hoặc dùng vector CVE thật từ NVD cho dịch vụ trong kịch bản, để chi phí đa dạng và có cơ sở hơn.

Sau khi bạn chọn, tôi sẽ cập nhật chương kết quả và hai báo cáo LaTeX theo số liệu mới, rồi commit.

## 8. Tái lập

```bash
bash scripts/reproduce.sh        # 8 bước; bước 7-8 là phần CVSS
# hoặc riêng phần CVSS:
bash scripts/recost_all.sh
python -m aapef benchmark --config scenarios/benchmark_cvss.json --scenarios-dir scenarios/cvss --out out/cvss --strict
python scripts/cvss_sensitivity.py
```

## 9. Bước 2: vector CVE thật từ NVD (đã thực hiện)

### 9.1. Vì sao và hướng đã chọn

Sau khi xem xét hướng nghiên cứu "attack graph áp dụng vào Red Team", hướng được chọn là **chấp nhận kết quả của bước 1 (không dựng lại đánh đổi bằng ghi đè tùy ý) và đưa dữ liệu CVE thật vào**, vì gán trọng số bằng CVSS là thông lệ của lĩnh vực và mỗi con số truy ngược được về một bản ghi công khai. Hướng "ghi đè vài vector để ép ra đánh đổi" bị loại vì dễ bị phản biện là chỉnh số.

### 9.2. Thay đổi

| Nhóm | Nội dung |
|---|---|
| `aapef/cvss.py` | hỗ trợ **Scope Changed** (hệ số PR riêng: L 0,68, H 0,5); `parse_vector_string`; `load_catalog`; `recost_scenario(data, model, catalog)` nhận trường `cve` (từ chối: `cve` cùng `cvss_override`, `cve` trên hành động thu thập, CVE ngoài danh mục, thiếu danh mục) |
| `aapef/scenario.py`, `aapef/cli.py` | validator kiểm tra định dạng `cve`; `recost --catalog` (mặc định `scenarios/cve_catalog.json`) |
| `scenarios/cve_catalog.json` (mới) | 10 CVE: vector CVSS v3.1 do `nvd@nist.gov` công bố, điểm Exploitability NVD, ngày vào danh mục CISA KEV, nguồn, ngày truy cập 2026-10-22, quy tắc chọn, ghi chú về hai bản ghi chỉ có loại Secondary (Zerologon, PrintNightmare) |
| `scenarios/lab-01.json` (mới) | kịch bản thí điểm 4 máy, 14 hành động, 9 CVE; file nguồn **không có trường chi phí** nên không thể benchmark nhầm khi chưa tính lại |
| `scenarios/cvss/lab-01.json`, `scenarios/benchmark_cvss.json`, `out/cvss/` | bản đã tính lại, thêm vào bộ benchmark CVSS; các dòng của 15 kịch bản cũ **không đổi** ngoài cột thời gian (đã đối chiếu) |
| `tests/test_aapef.py` | +8 test (tổng **62**): hệ số Scope; phân tích vector; **mọi vector trong danh mục tái tạo đúng điểm Exploitability NVD công bố (10/10)**; hành động `cve`; các trường hợp dùng sai; `lab-01` khớp file đã commit và có đánh đổi |
| `scripts/cvss_sensitivity.py` | nạp danh mục, chạy trên 12 kịch bản có đường đi |

**Cách chọn CVE** (công bố trong danh mục): theo vai trò tấn công; ứng viên phải thuộc CISA KEV và có vector CVSS v3.1 của `nvd@nist.gov`; liệt kê mọi ứng viên đã xét; trong một vai trò các hành động sắp theo mã CVE tăng dần (không chọn thứ tự để lợi cho thuật toán nào). Lưu ý nguồn dữ liệu: bản ghi lấy qua API của NVD bằng công cụ trung gian, nên tính đúng của mỗi vector được kiểm lại độc lập bằng điểm Exploitability mà NVD công bố.

### 9.3. Kết quả trên `lab-01`

Chi phí: 9 (Struts, Log4Shell, Remote Desktop, Netlogon), 13 (SMBv1, Print Spooler), 17 (sudo, PwnKit), 23 (Dirty COW), 1 (thu thập). |V| = 16, |E| = 44.

| Thuật toán | *L* | *C* | *E_n* | *E_e* |
|---|---:|---:|---:|---:|
| BFS | 5 | 43 | 10 | 31 |
| DFS | 7 | 57 | 7 | 17 |
| Dijkstra | 6 | **30** | 10 | 33 |
| Greedy | 5 | 43 | 7 | 21 |
| A\* | 6 | **30** | 6 | 21 |

- **Đánh đổi L ≠ C xuất hiện từ dữ liệu chi phí:** đường ít bước nhất (5 bước, leo thang cục bộ trên máy web rồi chiếm miền) tốn 43, đường tối ưu (6 bước, qua máy ứng dụng bằng Remote Desktop) tốn 30. Bước leo thang cục bộ (17–23) đắt hơn bước di chuyển ngang từ xa (9–13) đủ để bù một bước phụ.
- **Độ nhạy thứ tự (51 thứ tự):** BFS và Greedy luôn 5 bước nhưng chi phí 37–43 (6 đường đi khác nhau mỗi thuật toán); Dijkstra và A\* giữ nguyên 30; DFS 33 đường đi, chi phí 30–57. Đây là kịch bản đầu tiên cho thấy **Greedy nhạy với thứ tự hành động**, một hạn chế đã nêu ở bước 1.
- **Bền vững trước giả định:** trong cả 7 biến thể (hệ số nhân, chuẩn hóa, xác suất thu thập, AC, UI) đánh đổi vẫn xuất hiện ở `lab-01` (1/12 kịch bản), A\* = C\* ở 12/12 và Dijkstra tối ưu ở 12/12.

### 9.4. Cần nói thẳng khi bảo vệ

- **Cấu trúc của `lab-01` do tôi thiết kế, và hệ quả về chi phí đã được suy tính khi thiết kế.** Chi phí lấy từ NVD, nhưng việc kịch bản có đường "leo thang cục bộ rồi chiếm miền từ máy web" là lựa chọn thiết kế. Vì vậy `lab-01` là *minh họa* cách chi phí lấy từ dữ liệu ảnh hưởng tới lựa chọn đường đi, **không phải** bằng chứng độc lập rằng đánh đổi L ≠ C tồn tại trong mạng thực. Điều này đã được ghi trong mô tả của kịch bản, chương kết quả và hai báo cáo.
- Việc gắn một hành động trừu tượng với một CVE cụ thể vẫn là phán đoán của người dựng kịch bản; CVE chỉ cho chi phí của *lỗ hổng đó*, không cho thấy kẻ tấn công thực sự sẽ chọn lỗ hổng nào.
- Danh mục chỉ có 10 CVE và một kịch bản thí điểm; chưa đủ để khái quát.
- Phần "rủi ro bị phát hiện / tàng hình" vẫn là hướng phát triển (bài toán nhiều mục tiêu), chưa làm.

### 9.5. Tài liệu đã cập nhật

`AAPEF_Research_Plan.md` (§9.3, bảng trạng thái), `reports/Chuong_KetQua.md` (Mục 4.1.2, 4.2b, 4.3, 4.6, 4.8, 4.9, tài liệu tham khảo), `reports/BaoCao_TomTat.tex`, `reports/BaoCao_ChiPhi_SinhKichBan.tex`, `README.md`. `reports/BaoCao_PhanTich.md` giữ nguyên làm báo cáo của mô hình cũ (đã có chú thích phạm vi).

### 9.6. Việc còn lại

1. Thêm nhiều kịch bản dựng quanh CVE thật, tốt nhất không do một người thiết kế (ví dụ lấy từ một môi trường thực hành công khai đã được mô tả), với quy tắc chọn chặt hơn, để kết luận về đánh đổi không dựa vào một kịch bản.
2. Bài toán nhiều mục tiêu (xác suất thành công và rủi ro bị phát hiện): hướng phát triển.
3. Biểu đồ cho luận văn, chỉnh chương theo mẫu của khoa, slide bảo vệ.
