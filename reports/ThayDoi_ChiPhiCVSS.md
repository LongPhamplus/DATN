# Thay đổi: chuyển sang chi phí dẫn xuất từ CVSS v3.1

*Ngày 2026-10-22 · Các commit: `c72c346` (Plan), `22b121b` (mã), `85a5b31` (kịch bản + benchmark), `3b15125` (reproduce.sh)*

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

## 7. Cần bạn quyết định

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
