# AAPEF — Báo cáo phân tích kết quả (tóm tắt)

*Ngày 2026-10-20 · Dữ liệu: `out/results.csv`, `out/analysis.csv`, `out/statespace.csv`*
*Tái tạo: `python -m aapef benchmark --config scenarios/benchmark_config.json --out out`*

## 1. Thiết lập

- 4 thuật toán chính: BFS, DFS, Dijkstra, Greedy Best-First (heuristic = số bậc access còn thiếu ở host goal), cộng A* [TÙY CHỌN] với heuristic admissible (h = chi phí rẻ nhất của một action nâng quyền host goal lên mức goal; chứng minh trong `make_admissible_heuristic`, kiểm bằng test).
- 4 scenario trong `benchmark_config.json`. Kích thước state-space đo bằng bước duyệt tham chiếu (§12.5):

| Scenario | \|V\| | \|E\| | Đặc điểm |
|---|---:|---:|---|
| demo-small-01 | 4 | 3 | 1 đường thẳng |
| medium-01 | 6 | 8 | đường ngắn-đắt vs dài-rẻ |
| large-01 | 18 | 36 | nhánh, dead-end (D), diamond, 2 đường tới goal |
| unreachable-01 | 3 | 2 | goal không đạt được |

- Mọi chỉ số L, C, E_n, E_e đều tất định (đo 1 lần). Runtime T = trung vị của 30 lần đo, sau 2 lần warm-up, kèm IQR.
- Tham chiếu theo §12.4: **C\* = chi phí của Dijkstra**, **L\* = độ dài của BFS**.

## 2. Kết quả chính

| Scenario | Thuật toán | L | C | C − C\* | L − L\* | E_n | E_e | E_n / \|V\| | T (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| demo-small-01 | cả 4 | 3 | 9 | 0 | 0 | 3 | 3 | 0.75 | 0.029–0.033 |
| medium-01 | BFS | 1 | 10 | **+4** | 0 | 2 | 4 | 0.33 | 0.026 |
| medium-01 | DFS | 3 | 6 | 0 | +2 | 3 | 6 | 0.50 | 0.039 |
| medium-01 | Dijkstra | 3 | **6** | 0 | +2 | 3 | 6 | 0.50 | 0.046 |
| medium-01 | Greedy | 1 | 10 | +4 | 0 | **1** | 2 | 0.17 | 0.014 |
| large-01 | BFS | 1 | 9 | +2 | 0 | 3 | 9 | 0.17 | 0.056 |
| large-01 | DFS | 5 | 10 | **+3** | **+4** | 5 | 14 | 0.28 | 0.094 |
| large-01 | Dijkstra | 3 | **7** | 0 | +2 | **9** | 24 | 0.50 | 0.199 |
| large-01 | Greedy | 1 | 9 | +2 | 0 | **1** | 3 | 0.06 | 0.016 |
| unreachable-01 | cả 4 | — | — | — | — | 3 | 2 | 1.00 | 0.016–0.018 |

Tất cả path tìm được đều có `path_valid = true` và `goal_reached = true` sau khi replay.

## 3. Trả lời các câu hỏi nghiên cứu

### RQ1 — Tính tối ưu chi phí
- Dijkstra đạt C\* trên mọi scenario có lời giải, đúng như lý thuyết khi cạnh không âm.
- BFS và Greedy lệch +4 (×1.67) ở medium-01 và +2 (×1.29) ở large-01: cả hai đều chọn đường 1 bước nhưng đắt.
- DFS lệch +3 (×1.43) ở large-01. Ở medium-01 DFS trùng C\* chỉ vì thứ tự action trong JSON tình cờ đặt đường rẻ trước — **không phải bảo đảm**.

### RQ2 — Tối ưu độ dài
- BFS đạt L\* trên mọi scenario. Greedy cũng đạt L\* ở cả hai scenario có nhiều đường, nhưng đó là do heuristic tình cờ khớp với đường 1 bước, không phải tính chất chung.
- Dijkstra dài hơn L\* 2 bước (đổi độ dài lấy chi phí) → minh họa trực tiếp **L ≠ C**.
- DFS cho path dài nhất (L = 5 ở large-01, +4 bước): nó đi vào nhánh dead-end/diamond trước khi tới goal.

### RQ3 — Search effort & runtime *(kết quả sơ bộ)*
- **Greedy tiết kiệm effort nhất**: E_n = 1 ở medium/large, bằng 0.5× và 0.33× của BFS, và chỉ chạm 6–17% state-space. Cái giá phải trả là C lệch +2…+4.
- **Dijkstra tốn effort nhất** khi đồ thị lớn hơn: ở large-01, E_n = 9 (3× BFS, 50% của \|V\|), T = 0.199 ms (≈3.6× BFS). Lý do: nó phải settle mọi state rẻ hơn C\* = 7 trước khi được phép dừng.
- T đi cùng chiều với E_n/E_e (thứ tự xếp hạng giống nhau ở large-01), nhưng tuyệt đối chỉ ở mức micro-giây. IQR lớn nhất ≈ 0.015 ms, nên chênh lệch T giữa các thuật toán ở scenario nhỏ hầu như là nhiễu.
- **Hạn chế quan trọng:** chỉ có 3 kích thước giải được (\|V\| = 4, 6, 18). Chưa đủ để kết luận E_n/T **tăng thế nào theo kích thước state-space**. Xem §5.

### RQ4 — Robustness
- unreachable-01: cả 4 thuật toán dừng, trả no-path với `path_valid = null` sau khi duyệt hết 3 state (coverage 100%), không lặp vô hạn.
- large-01 có diamond (cùng một state đến từ hai đường): mọi thuật toán khử trùng đúng theo `state_key`. Do effect chỉ đơn điệu tăng nên state-space là DAG, không tồn tại cycle thật (xem README).
- Trường hợp initial state đã thỏa goal được kiểm bằng test (`initial-goal-01`): path rỗng, E_n = E_e = 0.

### Thí nghiệm phụ — Độ nhạy theo thứ tự action
*Dữ liệu: `out/order_sensitivity.csv`. Tái tạo: `python -m aapef sensitivity --config scenarios/benchmark_config.json --permutations 50 --out out`.*

Thí nghiệm chạy lại mỗi thuật toán trên 51 thứ tự action: thứ tự gốc trong file và 50 hoán vị sinh theo seed 42.

| Scenario | Thuật toán | Số path khác nhau | L (min–max) | C (min–max) | E_n (min–max) |
|---|---|---:|---|---|---|
| medium-01 | BFS | 1 | 1 | 10 | 1–2 |
| medium-01 | DFS | **4** | 1–3 | **6–13** | 1–3 |
| medium-01 | Dijkstra | 1 | 3 | **6** | 3 |
| medium-01 | Greedy | 1 | 1 | 10 | 1 |
| large-01 | BFS | 1 | 1 | 9 | 1–3 |
| large-01 | DFS | **15** | **1–5** | **7–15** | 1–5 |
| large-01 | Dijkstra | 1 | 3 | **7** | 9 |
| large-01 | Greedy | 1 | 1 | 9 | 1 |

- **BFS và Dijkstra:** L\* của BFS và C\* của Dijkstra **không đổi** qua mọi thứ tự, đúng với lý thuyết rằng tính tối ưu không phụ thuộc cách phá hòa. Effort của BFS vẫn dao động (E_n từ 1 đến 3), vì thứ tự quyết định goal được gặp sớm hay muộn trong cùng một tầng.
- **DFS:** phụ thuộc mạnh vào thứ tự. Ở large-01, DFS cho 15 path khác nhau, C dao động từ 7 đến 15 (có lúc đạt C\*, có lúc gấp 2,1 lần), L từ 1 đến 5. Kết quả "DFS trùng C\* ở medium-01" trong bảng §2 vì thế chỉ là trường hợp cá biệt của thứ tự gốc. Đây là bằng chứng định lượng cho §4.3.
- **Greedy:** ổn định trên hai scenario này, nhưng chỉ vì heuristic phân biệt rõ đường 1 bước. Chưa kiểm tra trên scenario mà heuristic hòa nhau nhiều.

## 4. Kết luận tạm thời

1. Không có thuật toán nào tốt nhất trên mọi tiêu chí. Dijkstra tốt nhất cho **C**, BFS cho **L**, Greedy cho **effort**.
2. Trong mô hình này, đường "ít bước" thường là đường "đắt", nên BFS/Greedy và Dijkstra cho ra lời giải khác hẳn nhau.
3. DFS không có ưu thế ở tiêu chí nào và phụ thuộc mạnh vào thứ tự khai báo action (15 path khác nhau qua 51 thứ tự ở large-01). BFS và Dijkstra giữ nguyên giá trị tối ưu của mình qua mọi thứ tự.

## 5. Hạn chế & việc tiếp theo

- **RQ3 cần scenario lớn hơn** (ví dụ \|V\| hàng trăm đến hàng nghìn, nhiều mức kích thước) để vẽ đường cong E_n, T theo \|V\|. Pipeline đã sẵn sàng: bỏ thêm file scenario vào `scenarios/` rồi thêm id vào config là `analysis.csv` có ngay các cột `node_coverage`, `nodes_vs_bfs`.
- Kết quả RQ1/RQ2 hiện dựa trên 2 scenario có nhiều đường (medium, large). Cần thêm scenario để tránh kết luận từ trường hợp cá biệt (ví dụ việc Greedy trùng L\* hay DFS trùng C\*).
- Runtime ở thang micro-giây chịu nhiễu của hệ điều hành; nên ưu tiên E_n/E_e làm chỉ số effort chính, đúng như §4.1.

## 6. Phụ lục — A\* (tùy chọn)

*Dữ liệu: các dòng `astar` trong `out/results.csv` và `out/analysis.csv`.*

| Scenario | Dijkstra: C / E_n / E_e | A\*: C / E_n / E_e |
|---|---|---|
| demo-small-01 | 9 / 3 / 3 | 9 / 3 / 3 |
| medium-01 | 6 / 3 / 6 | 6 / 3 / 6 |
| large-01 | 7 / 9 / 24 | 7 / **6 / 17** |

- A\* đạt cùng chi phí tối ưu C\* với Dijkstra ở mọi scenario có lời giải (test xác nhận trên 11 thứ tự action mỗi scenario).
- Ở large-01, heuristic cắt bớt 1/3 số state phải expand (9 → 6). Hai scenario nhỏ hơn không đủ lớn để thấy khác biệt.
- Heuristic được test là admissible và consistent trên mọi state reachable của large-01. Đây là điều kiện để kết luận tối ưu của A\* hợp lệ (§10).

## 7. Mối đe dọa tính hợp lệ — bộ sinh scenario (`scen_gen.py`)

*Kiểm chứng ngày 2026-10-21: 11 cấu hình sinh thử (|V| từ 42 đến 11.264) chạy trên cả 5 thuật toán, `--strict`.*

**Điều đã được kiểm chứng (không bị ảnh hưởng bởi các hạn chế):**
- |V|, |E| do generator (oracle độc lập) và AAPEF đo **khớp 11/11**; mọi path tìm được đều `path_valid = true`, `goal_reached = true`; scenario `unreachable`/`initial-goal` cho đúng schema §12.3.
- Tính tối ưu: BFS đạt L\*, Dijkstra và A\* đạt C\* trên mọi scenario và mọi thứ tự action thử (21 thứ tự).
- Bẫy Greedy hoạt động trên engine thật: C(Greedy) = 44 và 79, cao hơn cả BFS (40 và 71) và C\* (15 và 32).

**Điều bị hạn chế (ảnh hưởng đến cách diễn giải, không ảnh hưởng đến tính đúng của app):**

| # | Hạn chế | Ảnh hưởng | Cách xử lý khi viết luận |
|---|---|---|---|
| 1 | Đường cong effort của Dijkstra gần tuyến tính theo \|V\| vì decoy rẻ hơn C\* nên phải bị expand gần hết; BFS/DFS/Greedy gần như phẳng vì goal ở nông | RQ3: kết luận chỉ đúng cho họ scenario này | Nêu rõ "trong họ scenario chuỗi + decoy"; không khái quát hóa |
| 2 | `--target-v` lệch tới ~30% (bước nhân ×2/×3) | Không ảnh hưởng kết quả | Báo cáo \|V\| thực đo, không dùng giá trị mục tiêu |
| 3 | Greedy cho đúng 1 path qua mọi thứ tự action | RQ1/RQ4: chưa thử Greedy khi heuristic hòa nhiều | Ghi là giới hạn; chỉ khẳng định Greedy không tối ưu, không khẳng định mức độ nhạy |
| 4 | `--cycles` chỉ tạo action no-op (state-space là DAG) | RQ4: chưa thử cycle thật | Ghi là giới hạn của mô hình (effect đơn điệu), không phải lỗi |
| 5 | Mọi scenario cùng một họ cấu trúc | Khả năng tổng quát hóa | Nêu trong phần hạn chế của luận văn |

**Kết luận:** các giả thuyết RQ1 (Dijkstra tối ưu C), RQ2 (BFS tối ưu L), RQ4 (dừng đúng khi no-path/cycle/trùng state) được hỗ trợ độc lập với các hạn chế trên. RQ3 chỉ kết luận được **trong phạm vi họ scenario đã sinh**.

## 8. Kết quả RQ3 — effort theo kích thước state-space

*Dữ liệu: `out/scaling/` (`python -m aapef benchmark --config scenarios/benchmark_scaling.json --out out/scaling`); scenario sinh bằng `scenarios/gen_rq3.sh`. Runtime: trung vị 5 lần sau 2 lần warm-up. Phạm vi kết luận: họ scenario chuỗi + dead-end + decoy (xem §7).*

| Scenario | \|V\| | \|E\| | BFS E_n | DFS E_n | Dijkstra E_n | Greedy E_n | A\* E_n | A\*/Dijkstra | Dijkstra T (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| demo-small-01 | 4 | 3 | 3 | 3 | 3 | 3 | 3 | 1,00 | 0,03 |
| medium-01 | 6 | 8 | 2 | 3 | 3 | 1 | 3 | 1,00 | 0,05 |
| large-01 | 18 | 36 | 3 | 5 | 9 | 1 | 6 | 0,67 | 0,20 |
| size-v132 | 132 | 364 | 9 | 7 | 72 | 3 | 58 | 0,81 | 3,2 |
| size-v352 | 352 | 1.264 | 13 | 7 | 169 | 3 | 127 | 0,75 | 8,4 |
| size-v1026 | 1.026 | 4.131 | 9 | 7 | 329 | 3 | 154 | 0,47 | 25,0 |
| size-v3024 | 3.024 | 14.688 | 15 | 7 | 1.058 | 3 | 526 | 0,50 | 100,0 |
| size-v11264 | 11.264 | 68.608 | 23 | 7 | 3.694 | 3 | 2.291 | 0,62 | 329,0 |

Hệ số mũ ước lượng của E_n theo \|V\| (từ size-v132 đến size-v11264, log–log hai đầu mút): Dijkstra ≈ 0,89 · A\* ≈ 0,83 · BFS ≈ 0,21 · DFS = 0 · Greedy = 0.

- **Dijkstra** tăng gần tuyến tính theo \|V\| (E_n từ 72 đến 3.694 khi \|V\| tăng 85 lần). Nó expand khoảng 33–55% state-space, vì phải settle mọi state rẻ hơn C\* trước khi dừng. Runtime tăng cùng chiều (3,2 → 329 ms).
- **A\*** đạt cùng C\* với Dijkstra nhưng expand ít hơn: bằng 0,47–0,81 lần Dijkstra. Mức tiết kiệm không đơn điệu theo kích thước (tốt nhất ở \|V\| ≈ 1.000–3.000), nên chưa kết luận được xu hướng; cần thêm họ scenario khác.
- **BFS, DFS, Greedy** gần như phẳng: goal nằm nông (2 bước ở tuyến trực tiếp), nên chúng dừng sớm bất kể \|V\|. Đây là hệ quả của cấu trúc scenario chứ không phải tính chất chung của các thuật toán (hạn chế 1, §7).
- **Cái giá của việc ít effort:** BFS và Greedy tốn chi phí gấp 2,2–3 lần C\* (ví dụ size-v11264: C = 43 so với C\* = 18; L = 2 so với 7). Đây là đánh đổi L≠C đã nêu ở RQ1/RQ2, giờ được thấy lại ở mọi kích thước.

## 9. Kết quả robustness và độ nhạy (scenario sinh)

*Dữ liệu: `out/generated/` (`benchmark_generated.json`, 50 hoán vị thứ tự action, seed 42).*

| Scenario | BFS (L, C) | Greedy (L, C) | Dijkstra = A\* (L, C\*) | DFS: số path / C |
|---|---|---|---|---|
| trap-01 | 2, 40–44 | 2, **44** | 7, 15 | 38 path / 15–59 |
| trap-02 | 2, 71–79 | 2, **79** | 11, 32 | 34 path / 32–121 |
| cycles-01 | 2, 65 | 2, 65 | 11, 30 | 35 path / 30–93 |

- **Bẫy Greedy hiệu lực:** trên trap-01/02, Greedy bị heuristic dẫn vào tuyến lure có chi phí cao hơn cả tuyến trực tiếp mà BFS tìm được (44 > 40, 79 > 71). Đây là bằng chứng Greedy không chỉ "không đảm bảo tối ưu" mà có thể tệ hơn cả tìm kiếm mù về chi phí.
- **DFS nhạy mạnh với thứ tự action:** 34–38 path khác nhau qua 51 thứ tự, chi phí lên tới 3,8–4× C\*. Dijkstra và A\* giữ nguyên C\*; BFS giữ nguyên L\* nhưng C dao động giữa hai tuyến 2 bước khi hòa.
- **RQ4:** `unreachable-02` — cả 5 thuật toán dừng sau khi duyệt hết 63 state (138 cạnh), `path_valid = null`; `initial-goal-02` — path rỗng, E_n = E_e = 0; `cycles-01` — các action `return_*` (no-op) bị loại, không xuất hiện trong \|E\|.
