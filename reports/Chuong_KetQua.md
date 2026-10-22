# CHƯƠNG 4 — KẾT QUẢ THỰC NGHIỆM VÀ THẢO LUẬN

*(Bản viết lại ngày 2026-10-22 theo mô hình chi phí CVSS. Số chương và số hiệu bảng/hình có thể đổi theo mẫu luận văn. Mọi số liệu lấy từ `out/cvss/` (trừ Mục 4.7), tái tạo bằng `bash scripts/reproduce.sh`. Lý do và nội dung thay đổi: `reports/ThayDoi_ChiPhiCVSS.md`.)*

## 4.1. Bối cảnh, mô hình và thiết lập thực nghiệm

### 4.1.1. Bài toán và câu hỏi nghiên cứu

AAPEF coi việc lập kế hoạch tấn công của Red Team là bài toán **lập kế hoạch trên không gian trạng thái**: biến trạng thái (quyền truy cập từng máy và tri thức đã thu được), trạng thái đầu, mục tiêu, và các hành động có tiền điều kiện cùng hiệu ứng. Cách biểu diễn này trùng với cách các nghiên cứu về mô phỏng pentest và lập kế hoạch tấn công tự động mô tả attack graph như một bài toán lập kế hoạch [2, 3]. Môi trường hoàn toàn là dữ liệu mô phỏng: không có máy ảo, khai thác thật hay lệnh hệ điều hành.

Chương này trả lời bốn câu hỏi trên cùng đồ thị trạng thái và cùng mục tiêu:

- **RQ1 — Tính tối ưu chi phí:** chi phí đường đi *C* của mỗi thuật toán lệch bao nhiêu so với chi phí tối ưu *C\**?
- **RQ2 — Tính tối ưu độ dài:** số hành động *L* lệch bao nhiêu so với giá trị tối thiểu *L\**?
- **RQ3 — Công sức tìm kiếm:** số trạng thái mở rộng (*E_n*), số cạnh xét (*E_e*) và thời gian (*T*) thay đổi thế nào theo kích thước không gian trạng thái?
- **RQ4 — Độ bền:** xử lý ra sao trạng thái trùng, mục tiêu không đạt được, mục tiêu đã thỏa từ đầu?

Chương **không** kết luận thuật toán nào "tốt nhất" một cách phổ quát; mỗi so sánh gắn với đúng một tiêu chí. Dijkstra chỉ là tham chiếu cho *C\**, BFS cho *L\**.

### 4.1.2. Mô hình chi phí: dẫn xuất từ CVSS v3.1

Chi phí mỗi hành động **không do người thiết kế đặt**, mà được tính bằng công thức công khai của CVSS v3.1 (FIRST) [1]:

```
E    = 8,22 × AV × AC × PR × UI       (Exploitability, Scope Unchanged)
p    = E / 10                          (xác suất thành công của bước)
cost = round(10 × (−ln p))             (số nguyên ≥ 0)
```

Phép −ln biến tích xác suất thành tổng, nên tổng chi phí một đường đi ≈ −10·ln(xác suất thành công cả đường) khi các bước độc lập; Dijkstra và A\* vì vậy tìm *đường có xác suất thành công cao nhất*, đúng với bài toán "đường tấn công khả thi nhất" trong tài liệu [4, 5].

**Vector CVSS được dẫn xuất từ cấu trúc của hành động:** AV = Network nếu có tiền điều kiện `reachable`, ngược lại Local; PR = mức quyền cao nhất mà hành động yêu cầu (`none`→N, `user`→L, `admin`→H); AC = Low và UI = None (mặc định công bố); hành động chỉ thu thập thông tin (không nâng quyền) được gán xác suất cố định 0,9 vì CVSS chấm lỗ hổng chứ không chấm việc quét. Trường `cvss_override` cho phép ghi đè từng hành động; **thực nghiệm trong chương này không dùng ghi đè nào**.

Kết quả là chi phí chỉ nhận bốn giá trị: **1** (thu thập), **13** (chiếm quyền từ xa, cần quyền `user`), **14** (chiếm quyền cục bộ, không cần quyền) và **17** (leo thang cục bộ, cần quyền `user`).

**Giả định công bố:** Scope Unchanged; AC=L, UI=N; chuẩn hóa p = E/10; hệ số nhân 10; xác suất thu thập 0,9; các bước độc lập; vector dẫn xuất từ cấu trúc chỉ là xấp xỉ. Mục 4.6 khảo sát độ nhạy của kết quả theo các giả định này.

### 4.1.3. Thuật toán và đại lượng đo

| Thuật toán | Tiêu chí tối ưu | Ghi chú |
|---|---|---|
| BFS | *L* | hàng đợi FIFO |
| DFS | không bảo đảm | ngăn xếp LIFO, theo thứ tự khai báo hành động |
| Dijkstra | *C* | hàng đợi ưu tiên theo tổng chi phí |
| Greedy Best-First | không bảo đảm | heuristic = số bậc quyền còn thiếu ở máy mục tiêu |
| A\* | *C* | *h* = chi phí rẻ nhất của một hành động nâng quyền máy mục tiêu lên mức mục tiêu; chấp nhận được và nhất quán (kiểm bằng test) |

Đại lượng đo: *L* (số hành động), *C* (tổng chi phí), *E_n* (trạng thái được mở rộng), *E_e* (cạnh được xét), *T* (trung vị 5 lần đo sau 2 lần khởi động) và ba cờ độc lập `path_found` / `path_valid` / `goal_reached`. *L*, *C*, *E_n*, *E_e* tất định nên đo một lần.

### 4.1.4. Bộ kịch bản

15 kịch bản, kích thước đo thực |V|, |E| (không phụ thuộc chi phí):

| Nhóm | Kịch bản | \|V\| | \|E\| |
|---|---|---:|---:|
| Viết tay | `demo-small-01`; `medium-01`; `large-01` | 4; 6; 18 | 3; 8; 36 |
| Thang kích thước (sinh tự động) | `size-v132`; `size-v352`; `size-v1026`; `size-v3024`; `size-v11264` | 132; 352; 1 026; 3 024; 11 264 | 364; 1 264; 4 131; 14 688; 68 608 |
| Bẫy Greedy | `trap-01`; `trap-02` | 126; 978 | 393; 4 863 |
| Cạnh ngược (no-op) | `cycles-01` | 306 | 1 248 |
| Biên | `unreachable-01`; `unreachable-02`; `initial-goal-01`; `initial-goal-02` | 3; 63; 2; 42 | 2; 138; 1; 85 |

Các kịch bản sinh tự động do `scen_gen.py` tạo **cấu trúc** (máy, topology, hành động, nhánh cụt, mồi nhử, đường tắt); chi phí của chúng được **tính lại hoàn toàn** bằng `python -m aapef recost`, không dùng chi phí mà bộ sinh ghi ra.

### 4.1.5. Kiểm chứng công cụ

- 54 kiểm thử tự động đạt, gồm giá trị CVSS theo đặc tả, tính đơn điệu của chi phí theo độ khó, quy tắc dẫn xuất vector, tính idempotent của `recost`, tính tối ưu của BFS/Dijkstra/A\* và các trường hợp biên.
- |V|, |E| do bộ sinh (một bộ tham chiếu viết độc lập) và do AAPEF đo khớp 11/11 kịch bản được so sánh; chi phí không ảnh hưởng tới hai giá trị này.
- Mọi đường đi đều `path_valid = true` và `goal_reached = true` khi phát lại.
- Chạy lại toàn bộ bằng `scripts/reproduce.sh` cho kết quả giống hệt ở mọi cột không phải thời gian (16 file CSV).

## 4.2. RQ1 và RQ2 — Chi phí và độ dài đường đi

*Thứ tự hành động gốc của mỗi kịch bản. Mỗi ô là (L, C).*

| Kịch bản | BFS | DFS | Dijkstra (*C\**) | Greedy | A\* |
|---|---|---|---|---|---|
| `demo-small-01` | 3, 28 | 3, 28 | 3, 28 | 3, 28 | 3, 28 |
| `medium-01` | 1, 13 | 3, **28** | 1, 13 | 1, 13 | 1, 13 |
| `large-01` | 1, 13 | 5, **43** | 1, 13 | 1, 13 | 1, 13 |
| `size-v132` … `size-v11264` (5 mức) | 2, 14 | 7, **55** | 2, 14 | 2, 14 | 2, 14 |
| `trap-01` | 2, 14 | 7, **55** | 2, 14 | 2, **30** | 2, 14 |
| `trap-02` | 2, 14 | 11, **83** | 2, 14 | 2, **30** | 2, 14 |
| `cycles-01` | 2, 14 | 11, **83** | 2, 14 | 2, 14 | 2, 14 |

### Nhận xét

1. **BFS, Dijkstra và A\* cho cùng chi phí tối ưu ở mọi kịch bản** (độ lệch *C − C\** = 0), và Greedy cũng vậy ở các kịch bản không có bẫy. Lý do: các hành động chiếm quyền gần như cùng chi phí (13), nên đường ít bước đồng thời là đường có xác suất thành công cao nhất.
2. **Đánh đổi L ≠ C không xuất hiện** ở bất kỳ kịch bản nào (0/11 kịch bản có đường đi). Đây là hệ quả của mô hình xác suất, không phải lỗi: vector khó nhất của CVSS (AV:P/AC:H/PR:H/UI:R) cho chi phí tối đa 44, trong khi một bước chiếm quyền thông thường là 13; một đường một bước chỉ có thể đắt hơn đường nhiều bước khi đường kia có tối đa khoảng ba bước thông thường. Nói cách khác, *thêm bước gần như luôn làm giảm xác suất thành công*.
3. **DFS là thuật toán lệch tối ưu rõ nhất**: chi phí gấp 2,2 đến 5,9 lần *C\** ở thứ tự gốc trên mọi kịch bản có nhiều hơn một đường (28/13 ở `medium-01`, 83/14 ở `trap-02` và `cycles-01`; riêng `demo-small-01` chỉ có một đường nên bằng 1), đồng thời đường đi dài hơn tối thiểu từ 2 đến 9 bước.
4. **Bẫy Greedy vẫn hiệu lực**: ở `trap-01/02` heuristic dẫn Greedy vào tuyến mồi với chi phí 30, gấp 2,14 lần *C\** (=14) và cao hơn cả BFS. Khoảng cách này nhỏ hơn so với mô hình chi phí cấu hình cũ (Mục 4.7) vì chi phí nay do công thức quyết định, không do bộ sinh áp đặt.

## 4.3. Độ nhạy theo thứ tự hành động

Mỗi thuật toán chạy lại trên thứ tự gốc và 50 hoán vị ngẫu nhiên (seed 42), tức 51 thứ tự.

| Kịch bản | DFS: số đường đi khác nhau | DFS: *L* | DFS: *C* | BFS: *C* |
|---|---:|---|---|---|
| `medium-01` | 4 | 1–3 | 13–28 | 13 |
| `large-01` | 15 | 1–5 | 13–43 | 13 |
| `size-v132` | 39 | 2–11 | 14–71 | 14 |
| `size-v1026` | 40 | 2–16 | 14–**112** | 14 |
| `size-v11264` | 51 | 3–17 | 15–65 | 14 |
| `trap-01` | 38 | 2–11 | 14–83 | 14–30 |
| `trap-02` | 34 | 2–15 | 14–**111** | 14–30 |
| `cycles-01` | 35 | 2–14 | 14–98 | 14 |

- **Dijkstra và A\* giữ nguyên *C\** ở mọi thứ tự** và BFS giữ nguyên *L\**, đúng với lý thuyết rằng tính tối ưu không phụ thuộc cách phá hòa.
- **DFS dao động mạnh**: tới 51 đường đi khác nhau, chi phí lên tới 8,0 lần *C\** (112/14 ở `size-v1026`). Mọi kết quả của DFS vì vậy phải được hiểu là *một mẫu* của phân phối, không phải đặc tính cố định.
- **BFS ở `trap-01/02` có chi phí 14 hoặc 30** tùy thứ tự, vì có hai đường hai bước cùng độ dài nhưng chi phí khác nhau và BFS chỉ tối thiểu hóa số bước.
- **Greedy cho đúng một đường đi trên cả 51 thứ tự** ở mọi kịch bản. Đây là giới hạn của thực nghiệm: chưa có kịch bản nào khiến heuristic hòa nhiều, nên chưa thể kết luận về độ nhạy của Greedy.

## 4.4. RQ3 — Công sức tìm kiếm theo kích thước

Số trạng thái mở rộng *E_n* (thứ tự gốc); *T* là trung vị 5 lần đo.

| Kịch bản | \|V\| | \|E\| | nhánh cụt / mồi nhử | BFS | DFS | Dijkstra | Greedy | A\* | A\*/Dijkstra | *T* Dijkstra (ms) |
|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| `medium-01` | 6 | 8 | — | 2 | 3 | 2 | 1 | 1 | 0,50 | 0,03 |
| `large-01` | 18 | 36 | — | 3 | 5 | 4 | 1 | 1 | 0,25 | 0,09 |
| `size-v132` | 132 | 364 | 1 / 1 | 9 | 7 | 17 | 3 | 5 | 0,29 | 0,64 |
| `size-v352` | 352 | 1 264 | 0 / 4 | 13 | 7 | 65 | 3 | 7 | 0,11 | 2,8 |
| `size-v1026` | 1 026 | 4 131 | 4 / 0 | 9 | 7 | 17 | 3 | 5 | 0,29 | 1,0 |
| `size-v3024` | 3 024 | 14 688 | 3 / 3 | 15 | 7 | 129 | 3 | 8 | 0,06 | 8,7 |
| `size-v11264` | 11 264 | 68 608 | 0 / 9 | 23 | 7 | 2 049 | 3 | 12 | 0,006 | 133,1 |

*[Hình 4.1 — E_n theo số mồi nhử và theo \|V\|. Dữ liệu: `out/cvss/results.csv`, `out/cvss/statespace.csv`.]*

### Nhận xét

1. **\|V\| không phải yếu tố quyết định công sức của Dijkstra trong họ kịch bản này.** *E_n* của Dijkstra không đơn điệu theo \|V\|: `size-v1026` (1 026 trạng thái) chỉ mở rộng 17 trạng thái, bằng `size-v132` (132 trạng thái), trong khi `size-v11264` mở rộng 2 049. Dijkstra buộc phải xử lý mọi trạng thái có tổng chi phí nhỏ hơn *C\**; các hành động rẻ (chi phí 1, tức mồi nhử và thu thập thông tin) tạo ra rất nhiều tổ hợp trạng thái như vậy, còn các hành động chiếm quyền (chi phí 13) của nhánh cụt không bị mở rộng trước khi tới mục tiêu. Vì thế không ước lượng một hệ số mũ theo \|V\| (đường cong không đơn điệu); công sức phụ thuộc vào *số hành động rẻ độc lập*. Đây là một **kết luận giới hạn trong họ kịch bản đã sinh**.
2. **A\* tiết kiệm mạnh** so với Dijkstra với cùng chi phí tối ưu: tỉ lệ *E_n* giảm từ 0,29 (|V| = 132) xuống 0,006 (|V| = 11 264), tức 12 so với 2 049 trạng thái. Heuristic (chi phí rẻ nhất của hành động nâng quyền = 13) gần như sát chi phí thật còn lại, nên A\* hầu như đi thẳng tới mục tiêu.
3. **BFS, DFS và Greedy gần như không đổi** theo kích thước, vì mục tiêu nằm nông (đường trực tiếp hai bước) nên chúng dừng sớm. Đây là hệ quả cấu trúc kịch bản, không phải tính chất tổng quát của các thuật toán.
4. **Thời gian chạy** đi cùng chiều với *E_n* nhưng ở thang micro đến mili giây và chịu nhiễu hệ điều hành; chênh lệch *T* ở các kịch bản nhỏ (|V| ≤ 18, *T* ≈ 0,01–0,1 ms) nằm trong cỡ IQR, nên *E_n* và *E_e* được dùng làm chỉ số chính về công sức.

## 4.5. RQ4 — Độ bền

| Tình huống | Kịch bản | Kết quả quan sát |
|---|---|---|
| Mục tiêu không đạt được | `unreachable-01`; `unreachable-02` | Cả năm thuật toán dừng sau khi duyệt hết không gian đạt tới được (3 trạng thái/2 cạnh; 63 trạng thái/138 cạnh), `path_found = false`, `path_valid = null`, không lặp vô hạn. |
| Mục tiêu đã thỏa ban đầu | `initial-goal-01`; `initial-goal-02` | Cả năm thuật toán trả đường rỗng, *C* = 0, *E_n* = *E_e* = 0, `path_valid = true`. |
| Trạng thái trùng | `large-01` và mọi kịch bản có nhánh độc lập | Khử trùng đúng theo khóa chuẩn hóa; mỗi trạng thái chỉ mở rộng một lần; hai hành động khác nhau cùng dẫn tới một trạng thái được đếm là hai cạnh trong \|E\|. |
| Cạnh ngược, hành động no-op | `cycles-01` | Các hành động `return_*` luôn là no-op nên bị loại khỏi tập kế tiếp, không xuất hiện trong \|E\|. |

**Về chu trình.** Quyền truy cập chỉ tăng và tri thức chỉ mở rộng, nên mọi cạnh không-no-op đều làm trạng thái "lớn thêm"; do đó không gian trạng thái đạt tới được luôn là đồ thị có hướng không chu trình. Tính dừng được bảo đảm, nhưng thực nghiệm **không** kiểm tra được xử lý chu trình *thật*; đây là giới hạn của mô hình hiệu ứng đơn điệu.

## 4.6. Độ nhạy theo các giả định của mô hình chi phí

Mỗi biến thể tính lại chi phí từ kịch bản gốc rồi chạy cả năm thuật toán trên 11 kịch bản có đường đi (`out/cvss/assumption_sensitivity.csv`).

| Biến thể giả định | Đánh đổi L ≠ C | A\* = *C\** | Dijkstra tối ưu chi phí |
|---|---:|---:|---:|
| Mặc định | 0/11 | 11/11 | 11/11 |
| Hệ số nhân 100 (thay vì 10) | 0/11 | 11/11 | 11/11 |
| Chuẩn hóa p = E/3,9 (thay vì E/10) | 0/11 | 11/11 | 11/11 |
| Xác suất thu thập 0,5 | 0/11 | 11/11 | 11/11 |
| Xác suất thu thập 0,99 | 0/11 | 11/11 | 11/11 |
| AC mặc định = High | 0/11 | 11/11 | 11/11 |
| UI mặc định = Required | 0/11 | 11/11 | 11/11 |

Các kết luận chính **không phụ thuộc** vào các giả định này. Lý do cấu trúc: AC và UI mặc định áp dụng như nhau cho mọi hành động chiếm quyền, và các biến thể còn lại không đổi thứ tự giữa các đường. Điều này cũng cho thấy giới hạn: để có đánh đổi L ≠ C cần *các hành động khác nhau về vector*, mà quy tắc dẫn xuất hiện tại chưa phân biệt (xem Mục 4.8).

## 4.7. Thí nghiệm đối chứng với chi phí cấu hình (mô hình cũ)

Trước khi chuyển sang CVSS, chi phí được gõ tay (kịch bản viết tay) hoặc rút ngẫu nhiên theo seed trong các khoảng tự chọn và **bị ràng buộc** để tuyến trực tiếp luôn đắt hơn tuyến dài. Bộ kết quả này (`out/`, `out/scaling/`, `out/generated/`) được giữ làm **thí nghiệm có đối chứng**: vì đánh đổi được dựng sẵn, nó kiểm tra rằng các thuật toán hành xử đúng lý thuyết khi đánh đổi *tồn tại*, nhưng nó **không** là bằng chứng về mô hình thực tế.

| Kịch bản | BFS (*L*, *C*) | Dijkstra = A\* (*L*, *C\**) | Greedy *C* | DFS *C* |
|---|---|---|---:|---:|
| `medium-01` | 1, 10 | 3, 6 | 10 | 6 |
| `large-01` | 1, 9 | 3, 7 | 9 | 10 |
| `size-v1026` | 2, 45 | 7, 20 | 45 | 20 |
| `trap-01` | 2, 40 | 7, 15 | **44** | 15 |
| `trap-02` | 2, 71 | 11, 32 | **79** | 32 |

Trong thiết lập này BFS và Greedy tốn gấp 1,3 đến 2,9 lần chi phí tối ưu, Dijkstra tốn thêm 2 đến 9 bước, và công sức của Dijkstra tăng gần tuyến tính theo |V| (từ 72 đến 3 694 trạng thái mở rộng khi |V| từ 132 đến 11 264). Những con số này **phụ thuộc hoàn toàn vào cách đặt chi phí**, nên chỉ nên dùng để minh họa tính chất của thuật toán, không dùng làm kết luận chính.

## 4.8. Thảo luận và mối đe dọa tính hợp lệ

### 4.8.1. Điều được hỗ trợ độc lập với các hạn chế

- Dijkstra và A\* đạt chi phí tối ưu; BFS đạt độ dài tối thiểu; mọi đường đi hợp lệ.
- DFS nhạy mạnh với thứ tự hành động; BFS, Dijkstra, A\* không.
- Greedy có thể bị dẫn vào tuyến tệ hơn tối ưu, thậm chí tệ hơn BFS.
- Các trường hợp biên được xử lý đúng.

### 4.8.2. Hạn chế và phạm vi kết luận

| # | Hạn chế | Ảnh hưởng | Cách diễn giải |
|---|---|---|---|
| 1 | CVSS chấm *lỗ hổng*, không chấm hành động; điểm khai thác đo mức dễ khai thác, không phải rủi ro; giả định các bước độc lập | ý nghĩa của chi phí | Chi phí là −ln xác suất thành công theo CVSS, không phản ánh độ khó thực của một cuộc tấn công cụ thể |
| 2 | Vector dẫn xuất từ cấu trúc là xấp xỉ; AC và UI chưa được phân biệt giữa các hành động nên chi phí chỉ có bốn giá trị | RQ1, RQ2: đánh đổi L ≠ C không xuất hiện | Nêu rõ là hệ quả của mô hình và của độ chi tiết vector; hướng phát triển là dùng vector CVE thật |
| 3 | Công sức của Dijkstra phụ thuộc số hành động rẻ độc lập, không chỉ |V| | RQ3 | Kết luận giới hạn trong họ kịch bản (chuỗi + nhánh cụt + mồi nhử) |
| 4 | Greedy cho một đường duy nhất qua mọi thứ tự | RQ1, RQ4 | Chỉ khẳng định Greedy không tối ưu, không khẳng định mức độ nhạy |
| 5 | Không gian trạng thái là DAG | RQ4 | Giới hạn của mô hình hiệu ứng đơn điệu |
| 6 | Mọi kịch bản sinh tự động thuộc một họ cấu trúc; dữ liệu tự thiết kế | tổng quát hóa | Không suy ra khả năng khai thác thực tế |
| 7 | Thời gian chạy ở thang nhỏ chịu nhiễu | RQ3 (*T*) | Ưu tiên *E_n*, *E_e* |

### 4.8.3. Về đánh đổi L ≠ C trong bối cảnh Red Team

Với chi phí là xác suất thành công, đường ngắn thường cũng là đường khả thi nhất, nên việc không thấy đánh đổi L ≠ C là kết quả nhất quán với bài toán "đường tấn công khả thi nhất". Đánh đổi thực tế của Red Team nằm ở chỗ khác: đường ngắn có thể nhanh nhưng dễ bị phát hiện, đường dài kín đáo hơn. Điều này cần một chiều chi phí thứ hai (rủi ro bị phát hiện) và bài toán nhiều mục tiêu. Đây là **hướng phát triển**: kế hoạch đã hoãn chi phí tổng hợp vì cần chuẩn hóa và phân tích độ nhạy, và chưa tìm thấy tài liệu nào bàn cụ thể về lập kế hoạch tấn công có xét tàng hình, nên cần khảo sát thêm trước khi phát biểu như một khoảng trống nghiên cứu.

### 4.8.4. Ranh giới học thuật

Mọi kết quả là của **mô phỏng thuần dữ liệu**. Việc "đạt mục tiêu" trong mô phỏng không hàm ý khả năng khai thác thực tế, và các điểm CVSS chỉ được dùng như tham số điểm số công khai, không kèm bất kỳ mã khai thác nào.

## 4.9. Kết luận chương

1. **RQ1.** BFS, Dijkstra và A\* cho cùng chi phí tối ưu ở mọi kịch bản; DFS lệch rõ nhất (gấp 2,2–5,9 lần *C\** ở thứ tự gốc trên các kịch bản nhiều đường, tới 8,0 lần qua 51 thứ tự); Greedy tối ưu trừ khi bị bẫy (gấp 2,14 lần).
2. **RQ2.** BFS luôn đạt độ dài tối thiểu. Trong mô hình xác suất CVSS, đường ít bước đồng thời là đường có chi phí thấp nhất ở cả 11 kịch bản, nên đánh đổi L ≠ C không xuất hiện; kết quả này bền vững trước 7 biến thể giả định.
3. **RQ3.** Công sức của Dijkstra phụ thuộc vào số hành động rẻ độc lập chứ không đơn thuần vào |V| (17 trạng thái mở rộng ở |V| = 1 026 so với 2 049 ở |V| = 11 264); A\* tiết kiệm mạnh với cùng chi phí tối ưu (tỉ lệ so với Dijkstra từ 0,29 xuống 0,006); BFS, DFS, Greedy gần như không đổi. Kết luận giới hạn trong họ kịch bản đã sinh.
4. **RQ4.** Cả năm thuật toán xử lý đúng trạng thái trùng, mục tiêu không đạt được và mục tiêu đã thỏa; chu trình thật không xuất hiện trong mô hình đơn điệu.
5. **Thứ tự hành động** ảnh hưởng mạnh tới DFS nhưng không ảnh hưởng tới giá trị tối ưu của BFS, Dijkstra, A\*.

Không có thuật toán nào vượt trội trên mọi tiêu chí: **Dijkstra/A\*/BFS** tối ưu chi phí trong mô hình này (A\* với công sức thấp nhất), **BFS** tối ưu độ dài, **Greedy** ít công sức nhưng có thể bị bẫy, **DFS** phụ thuộc thứ tự khai báo và cho chất lượng kém nhất.

## Tài liệu tham khảo của chương

*(Cần bổ sung tác giả, năm, nơi công bố khi hoàn thiện danh mục; các mục dưới đây được xác định qua tra cứu ngày 2026-10-22.)*

1. FIRST. *Common Vulnerability Scoring System v3.1: Specification Document.* https://www.first.org/cvss/v3.1/specification-document
2. *Simulated penetration testing as an AI planning problem.* arXiv:1705.05088. https://arxiv.org/pdf/1705.05088v1 (tiêu đề cần xác nhận)
3. *Attack Planning in the Real World.* arXiv:1306.4044. https://ar5iv.labs.arxiv.org/html/1306.4044
4. *Most Vulnerable Attack Trace* (ASU). https://labs.engineering.asu.edu/cnsg/wp-content/uploads/sites/147/2025/07/C66.pdf
5. Kansas State University technical report về attack graph và CVSS. https://www.cs.ksu.edu/~xou/publications/tr_homer_0809.pdf
6. Sandia National Laboratories, tóm tắt 1998 (gán xác suất hoặc mức nỗ lực lên cạnh của attack graph). https://www.osti.gov/biblio/672082
