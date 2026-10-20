# CHƯƠNG 4 — KẾT QUẢ THỰC NGHIỆM VÀ THẢO LUẬN

*(Số chương và số hiệu bảng/hình có thể đổi theo mẫu luận văn. Mọi số liệu lấy từ `out/`, tái tạo bằng `bash scripts/reproduce.sh`; phân tích gốc ở `reports/BaoCao_PhanTich.md`.)*

## 4.1. Mục tiêu và thiết lập thực nghiệm

### 4.1.1. Mục tiêu

Chương này trả lời bốn câu hỏi nghiên cứu đã đặt ra ở Chương 1, trên cùng một đồ thị không gian trạng thái (cạnh có trọng số không âm) và cùng một mục tiêu:

- **RQ1 — Tính tối ưu chi phí:** tổng chi phí đường đi *C* của mỗi thuật toán lệch bao nhiêu so với chi phí tối ưu *C\**?
- **RQ2 — Tính tối ưu độ dài:** số hành động *L* lệch bao nhiêu so với giá trị tối thiểu *L\**?
- **RQ3 — Công sức tìm kiếm và thời gian:** số trạng thái được mở rộng (*E_n*), số cạnh được xét (*E_e*) và thời gian chạy (*T*) thay đổi thế nào theo kích thước không gian trạng thái?
- **RQ4 — Độ bền:** các thuật toán xử lý ra sao với trạng thái trùng, mục tiêu không đạt được và mục tiêu đã thỏa ngay từ đầu?

Theo nguyên tắc ở Mục 3.4, chương này **không** kết luận thuật toán nào "tốt nhất" một cách phổ quát; mỗi so sánh gắn với đúng một tiêu chí. Dijkstra chỉ được dùng làm tham chiếu cho *C\**, BFS làm tham chiếu cho *L\**.

### 4.1.2. Các thuật toán

Năm thuật toán chạy trên cùng hàm sinh trạng thái kế tiếp, cùng tập hành động và cùng chi phí:

| Thuật toán | Tiêu chí tối ưu | Ghi chú |
|---|---|---|
| BFS | *L* (số cạnh) | hàng đợi FIFO |
| DFS | không bảo đảm | ngăn xếp LIFO, duyệt theo thứ tự khai báo hành động |
| Dijkstra | *C* (tổng chi phí) | hàng đợi ưu tiên theo *g* |
| Greedy Best-First | không bảo đảm | heuristic = số bậc quyền truy cập còn thiếu ở máy mục tiêu |
| A\* (tùy chọn) | *C*, nếu heuristic chấp nhận được | *h* = chi phí rẻ nhất của một hành động nâng quyền máy mục tiêu lên mức mục tiêu |

Heuristic của A\* là *chấp nhận được* (admissible) vì mọi đường tới mục tiêu phải chứa ít nhất một hành động như vậy (quyền chỉ tăng), và là *nhất quán* (consistent); cả hai tính chất được kiểm bằng kiểm thử tự động trên mọi trạng thái đạt tới được của `large-01`.

Quy tắc đồng nhất giữa các thuật toán: khử trùng theo khóa trạng thái chuẩn hóa; phá hòa của hàng đợi ưu tiên bằng bộ đếm thứ tự chèn (kết quả tất định); kiểm tra mục tiêu trước khi mở rộng trạng thái đầu.

### 4.1.3. Các đại lượng đo

| Ký hiệu | Ý nghĩa |
|---|---|
| *L* | số hành động trong đường đi |
| *C* | tổng chi phí cấu hình của các hành động |
| *E_n* | số trạng thái được mở rộng |
| *E_e* | số cạnh được xét (kể cả cạnh tới trạng thái đã thăm) |
| *T* | thời gian của riêng vòng lặp tìm kiếm: trung vị của *n* lần đo sau 2 lần khởi động, kèm khoảng tứ phân vị (IQR) |
| `path_found` / `path_valid` / `goal_reached` | ba cờ độc lập: tìm kiếm có trả đường đi, đường đi có hợp lệ khi phát lại, trạng thái cuối có thỏa mục tiêu |

*L*, *C*, *E_n*, *E_e* là tất định nên đo một lần; chỉ *T* đo lặp (30 lần ở bộ chính, 5 lần ở bộ thay đổi kích thước). Kích thước không gian trạng thái |V|, |E| được đo bằng một bước duyệt tham chiếu riêng, tách khỏi *T*.

### 4.1.4. Bộ kịch bản

**Bộ viết tay (4 kịch bản)** — dùng cho RQ1, RQ2, RQ4:

| Kịch bản | \|V\| | \|E\| | Đặc điểm |
|---|---:|---:|---|
| `demo-small-01` | 4 | 3 | một đường thẳng |
| `medium-01` | 6 | 8 | đường ngắn-đắt và đường dài-rẻ |
| `large-01` | 18 | 36 | nhánh cụt, nhánh độc lập hợp lại, hai đường tới đích |
| `unreachable-01` | 3 | 2 | mục tiêu không đạt được |

**Bộ sinh tự động (10 kịch bản)** — dùng cho RQ3 và kiểm tra độ bền, sinh bằng `scen_gen.py` với seed 42 (chi phí hành động lấy ngẫu nhiên theo seed nhưng giữ các bất biến: đường trực tiếp đắt hơn đường dài; đường tắt đắt hơn hai bước nó bỏ qua):

| Kịch bản | \|V\| | \|E\| | Mục đích |
|---|---:|---:|---|
| `size-v132` … `size-v11264` (5 mức) | 132 → 11 264 | 364 → 68 608 | thang kích thước (RQ3) |
| `trap-01`, `trap-02` | 126; 978 | 393; 4 863 | bẫy cho Greedy (RQ1, RQ4) |
| `cycles-01` | 306 | 1 248 | cạnh ngược / hành động no-op (RQ4) |
| `unreachable-02` | 63 | 138 | không có đường (RQ4) |
| `initial-goal-02` | 42 | 85 | mục tiêu đã thỏa ban đầu (RQ4) |

Kích thước tăng qua hai cơ chế độc lập: mỗi nhánh cụt nhân |V| khoảng 3 lần, mỗi "mồi nhử" (một sự kiện học độc lập) nhân khoảng 2 lần. Mã định danh của kịch bản ghi |V| *đo thực*, không phải giá trị mục tiêu.

### 4.1.5. Kiểm chứng tính đúng đắn của công cụ

Trước khi diễn giải kết quả, các điểm sau đã được kiểm chứng:

- 42 kiểm thử tự động đạt, gồm kiểm tra tính bất biến trạng thái, quy tắc no-op, nhận diện trạng thái chuẩn hóa, tính tối ưu của BFS/Dijkstra/A\* trên kịch bản tính tay, và các trường hợp biên.
- |V| và |E| do bộ sinh kịch bản (một bộ tham chiếu viết độc lập) và do AAPEF đo **khớp 11/11 kịch bản** được so sánh.
- Mọi đường đi mà thuật toán trả về đều có `path_valid = true` và `goal_reached = true` sau khi phát lại; không có ngoại lệ.
- Chạy lại toàn bộ bằng `scripts/reproduce.sh` cho kết quả giống hệt ở mọi cột không phải thời gian.

## 4.2. RQ1 và RQ2 — Chi phí và độ dài đường đi

### 4.2.1. Kết quả trên bộ viết tay

| Kịch bản | Thuật toán | *L* | *C* | *C − C\** | *L − L\** |
|---|---|---:|---:|---:|---:|
| `demo-small-01` | cả năm | 3 | 9 | 0 | 0 |
| `medium-01` | BFS | 1 | 10 | **+4** (×1,67) | 0 |
| | DFS | 3 | 6 | 0 | +2 |
| | Dijkstra / A\* | 3 | **6** | 0 | +2 |
| | Greedy | 1 | 10 | +4 (×1,67) | 0 |
| `large-01` | BFS | 1 | 9 | +2 (×1,29) | 0 |
| | DFS | 5 | 10 | **+3** (×1,43) | **+4** |
| | Dijkstra / A\* | 3 | **7** | 0 | +2 |
| | Greedy | 1 | 9 | +2 (×1,29) | 0 |

### 4.2.2. Kết quả trên bộ sinh tự động

| Kịch bản | BFS (*L*, *C*) | Greedy (*L*, *C*) | Dijkstra = A\* (*L*, *C\**) | *C*_BFS / *C\** |
|---|---|---|---|---:|
| `size-v132` | 2, 40 | 2, 40 | 7, 15 | 2,67 |
| `size-v1026` | 2, 45 | 2, 45 | 7, 20 | 2,25 |
| `size-v11264` | 2, 43 | 2, 43 | 7, 18 | 2,39 |
| `trap-01` | 2, 40 | 2, **44** | 7, 15 | 2,67 |
| `trap-02` | 2, 71 | 2, **79** | 11, 32 | 2,22 |
| `cycles-01` | 2, 65 | 2, 65 | 11, 30 | 2,17 |

### 4.2.3. Nhận xét

1. **RQ1.** Dijkstra và A\* đạt *C\** ở mọi kịch bản có lời giải. BFS và Greedy trả về đường ngắn nhưng đắt: chi phí cao hơn tối ưu từ 29% đến 67% trên bộ viết tay và gấp khoảng 2,2–2,9 lần trên bộ sinh tự động.
2. **RQ2.** BFS đạt *L\** ở mọi kịch bản. Dijkstra dài hơn *L\** từ 2 đến 9 bước — chính là cái giá của việc tối thiểu hóa chi phí. Kết quả cho thấy rõ **L ≠ C**: đường ít bước nhất không phải đường rẻ nhất, và mức chênh lệch không biến mất khi kích thước tăng (Mục 4.4).
3. **Greedy có thể kém hơn cả tìm kiếm mù về chi phí.** Ở `trap-01` và `trap-02`, heuristic (giảm số bậc quyền còn thiếu) dẫn Greedy vào đường "mồi" có chi phí 44 và 79, **cao hơn cả BFS** (40 và 71) và gấp 2,9 và 2,5 lần *C\**. Như vậy Greedy không chỉ "không bảo đảm tối ưu" mà trong một số cấu trúc còn tệ hơn việc không dùng heuristic.
4. **DFS cho kết quả phụ thuộc thứ tự khai báo.** Việc DFS trùng *C\** ở `medium-01` là do hành động của đường rẻ được khai báo trước; Mục 4.3 chứng minh bằng thực nghiệm.

## 4.3. Độ nhạy theo thứ tự hành động

### 4.3.1. Phương pháp

Mỗi thuật toán được chạy lại trên thứ tự gốc và 50 hoán vị ngẫu nhiên của danh sách hành động (seed cố định 42, tái lập được). Mục đích: tách phần kết quả do *cấu trúc bài toán* khỏi phần do *thứ tự phá hòa*.

### 4.3.2. Kết quả

| Kịch bản | Thuật toán | Số đường đi khác nhau | *L* | *C* |
|---|---|---:|---|---|
| `medium-01` | BFS | 1 | 1 | 10 |
| | DFS | **4** | 1–3 | **6–13** |
| | Dijkstra / A\* | 1 | 3 | **6** |
| | Greedy | 1 | 1 | 10 |
| `large-01` | BFS | 1 | 1 | 9 |
| | DFS | **15** | 1–5 | **7–15** |
| | Dijkstra / A\* | 1 | 3 | **7** |
| | Greedy | 1 | 1 | 9 |
| `trap-01` | DFS | **38** | 2–11 | **15–59** |
| `trap-02` | DFS | **34** | 2–15 | **32–121** |
| `cycles-01` | DFS | **35** | 2–14 | **30–93** |

### 4.3.3. Nhận xét

- **BFS giữ nguyên *L\**, Dijkstra và A\* giữ nguyên *C\** qua mọi thứ tự**, đúng với lý thuyết rằng tính tối ưu không phụ thuộc cách phá hòa. (Chỉ đường đi cụ thể có thể đổi khi có nhiều đường cùng giá trị tối ưu; riêng BFS ở `trap-01/02` dao động giữa hai đường 2 bước có chi phí khác nhau.)
- **DFS dao động mạnh**: tới 38 đường đi khác nhau trên 51 thứ tự, chi phí có lúc đạt tối ưu, có lúc gấp 3,1–3,9 lần *C**. Vì vậy mọi kết quả của DFS cần được diễn giải là *một mẫu của phân phối*, không phải đặc tính cố định.
- **Greedy cho đúng một đường đi trên cả 51 thứ tự** ở mọi kịch bản thử. Đây là một *giới hạn của thực nghiệm*: các kịch bản chưa tạo tình huống heuristic hòa nhiều, nên chưa thể kết luận về độ nhạy của Greedy (xem Mục 4.6).

## 4.4. RQ3 — Công sức tìm kiếm theo kích thước không gian trạng thái

### 4.4.1. Kết quả

*E_n* (số trạng thái mở rộng) theo kích thước; *T* là trung vị của 5 lần đo sau 2 lần khởi động.

| Kịch bản | \|V\| | \|E\| | BFS | DFS | Dijkstra | Greedy | A\* | A\*/Dijkstra | *T* Dijkstra (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `demo-small-01` | 4 | 3 | 3 | 3 | 3 | 3 | 3 | 1,00 | 0,03 |
| `medium-01` | 6 | 8 | 2 | 3 | 3 | 1 | 3 | 1,00 | 0,05 |
| `large-01` | 18 | 36 | 3 | 5 | 9 | 1 | 6 | 0,67 | 0,20 |
| `size-v132` | 132 | 364 | 9 | 7 | 72 | 3 | 58 | 0,81 | 3,2 |
| `size-v352` | 352 | 1 264 | 13 | 7 | 169 | 3 | 127 | 0,75 | 8,4 |
| `size-v1026` | 1 026 | 4 131 | 9 | 7 | 329 | 3 | 154 | 0,47 | 25,0 |
| `size-v3024` | 3 024 | 14 688 | 15 | 7 | 1 058 | 3 | 526 | 0,50 | 100,0 |
| `size-v11264` | 11 264 | 68 608 | 23 | 7 | 3 694 | 3 | 2 291 | 0,62 | 329,0 |

Hệ số mũ ước lượng của *E_n* theo |V| (từ `size-v132` đến `size-v11264`, hồi quy hai đầu mút trong hệ log–log): **Dijkstra ≈ 0,89; A\* ≈ 0,83; BFS ≈ 0,21; DFS = 0; Greedy = 0**.

*[Hình 4.1 — E_n theo \|V\|, trục log–log, 5 đường. Dữ liệu: `out/scaling/analysis.csv`, cột `num_states`, `nodes_expanded`.]*
*[Hình 4.2 — Thời gian T theo \|V\|, kèm IQR. Dữ liệu: `out/scaling/results.csv`, cột `runtime_ms`, `runtime_iqr_ms`.]*

### 4.4.2. Nhận xét

1. **Dijkstra có công sức tăng gần tuyến tính theo |V|** (|V| tăng 85 lần thì *E_n* tăng 51 lần), mở rộng khoảng 33–55% không gian trạng thái, vì phải xử lý mọi trạng thái có chi phí nhỏ hơn *C\** trước khi được phép dừng. Thời gian tăng cùng chiều (3,2 → 329 ms) và cùng thứ tự xếp hạng với *E_n*, phù hợp với việc *E_n* là chỉ số độc lập phần cứng.
2. **A\* đạt cùng *C\** nhưng mở rộng ít hơn Dijkstra**, bằng 0,47–0,81 lần. Mức tiết kiệm **không đơn điệu theo kích thước** (tốt nhất ở khoảng 1 000–3 000 trạng thái), nên không thể kết luận về xu hướng.
3. **BFS, DFS và Greedy gần như không đổi** theo |V|. Nguyên nhân nằm ở cấu trúc kịch bản: mục tiêu nằm nông (đường trực tiếp chỉ 2 bước), nên ba thuật toán này dừng rất sớm bất kể phần còn lại của không gian lớn đến đâu. Đây **không** phải tính chất tổng quát của chúng — xem Mục 4.6.
4. **Cái giá của công sức thấp** là chất lượng đường đi: ở mọi kích thước, BFS và Greedy trả về đường có chi phí gấp 2,2–2,9 lần tối ưu (Mục 4.2). Thuật toán tiết kiệm công sức nhất (Greedy: 3 trạng thái cho cả không gian 11 264 trạng thái) cũng là thuật toán cho chi phí xấu nhất trên các kịch bản bẫy.
5. **Thời gian ở thang nhỏ chịu nhiễu.** Với |V| ≤ 18, *T* ở mức 0,01–0,2 ms và chênh lệch giữa các thuật toán nằm trong cỡ IQR (tối đa khoảng 0,015 ms), nên không có ý nghĩa thống kê. Vì vậy *E_n* và *E_e* được dùng làm chỉ số chính về công sức, đúng với định nghĩa ở Mục 4.1.3.

## 4.5. RQ4 — Độ bền

| Tình huống | Kịch bản | Kết quả quan sát |
|---|---|---|
| Mục tiêu không đạt được | `unreachable-01`; `unreachable-02` | Cả năm thuật toán dừng sau khi duyệt hết không gian đạt tới được (3 trạng thái/2 cạnh; 63 trạng thái/138 cạnh), `path_found = false`, `path_valid = null`, không lặp vô hạn. |
| Mục tiêu đã thỏa ban đầu | `initial-goal-01`; `initial-goal-02` | Cả năm thuật toán trả đường đi rỗng, *C* = 0, *E_n* = *E_e* = 0, `path_valid = true`. |
| Trạng thái trùng (đường hội tụ) | `large-01`, mọi kịch bản có nhánh độc lập | Khử trùng đúng theo khóa chuẩn hóa; mỗi trạng thái chỉ mở rộng một lần. Hai hành động khác nhau cùng dẫn tới một trạng thái được đếm là hai cạnh trong |E|. |
| Cạnh ngược, hành động no-op | `cycles-01` | Các hành động `return_*` luôn là no-op nên bị loại khỏi tập kế tiếp, không xuất hiện trong |E|. |

**Về chu trình.** Trong mô hình này, quyền truy cập chỉ tăng và tập tri thức chỉ mở rộng, nên mọi cạnh không-no-op đều làm trạng thái "lớn thêm" thực sự; do đó không gian trạng thái đạt tới được luôn là **đồ thị có hướng không chu trình (DAG)**. Hệ quả: tính dừng của thuật toán được bảo đảm, nhưng thực nghiệm này **không** kiểm tra được việc xử lý chu trình *thật*. Đây là giới hạn của mô hình hiệu ứng đơn điệu, không phải khiếm khuyết cài đặt (Mục 4.6).

## 4.6. Thảo luận và mối đe dọa tính hợp lệ

### 4.6.1. Điều được hỗ trợ độc lập với các hạn chế

Các giả thuyết sau được hỗ trợ bởi kết quả mà không phụ thuộc vào đặc điểm của bộ sinh kịch bản, vì chúng được kiểm bằng so sánh với tham chiếu độc lập và bằng chứng minh/kiểm thử:

- Dijkstra và A\* đạt chi phí tối ưu; BFS đạt độ dài tối thiểu (RQ1, RQ2).
- Tồn tại cấu trúc để **L ≠ C**, và nó ổn định theo kích thước (RQ1, RQ2).
- Các thuật toán dừng đúng trong các tình huống biên: mục tiêu không đạt được, mục tiêu đã thỏa, trạng thái trùng (RQ4).

### 4.6.2. Các hạn chế giới hạn phạm vi kết luận

| # | Hạn chế | Ảnh hưởng | Cách diễn giải |
|---|---|---|---|
| 1 | Đường cong *E_n* của Dijkstra một phần do cơ chế "mồi nhử" (chi phí 1–3, rẻ hơn *C\**, nên bị mở rộng gần hết); BFS/DFS/Greedy phẳng vì mục tiêu nằm nông | RQ3 | Kết luận RQ3 chỉ đúng **trong họ kịch bản chuỗi + nhánh cụt + mồi nhử**; không khái quát hóa |
| 2 | Kích thước điều khiển theo bước nhân ×2/×3, lệch tới khoảng 30% so với mục tiêu | không ảnh hưởng kết quả | Báo cáo |V| đo thực |
| 3 | Greedy cho một đường duy nhất qua mọi thứ tự hành động | RQ1, RQ4 | Chỉ khẳng định Greedy *không tối ưu*; không khẳng định mức độ nhạy |
| 4 | Không gian trạng thái là DAG nên chưa có chu trình thật | RQ4 | Ghi rõ là giới hạn của mô hình |
| 5 | Mọi kịch bản sinh tự động thuộc một họ cấu trúc; các kịch bản là dữ liệu tự thiết kế, không phải môi trường thực | tổng quát hóa | Nêu trong kết luận; không suy ra khả năng khai thác thực tế |
| 6 | Thời gian ở thang micro-giây chịu nhiễu hệ điều hành | RQ3 (chỉ số *T*) | Ưu tiên *E_n*, *E_e* |

### 4.6.3. Ranh giới học thuật

Mọi kết quả ở đây là của một **mô phỏng thuần dữ liệu**: không có máy ảo, không có khai thác thực, không có lệnh hệ điều hành. Việc "đạt mục tiêu" trong mô phỏng không hàm ý khả năng khai thác trong thực tế, và các con số chi phí là tham số cấu hình do người thiết kế đặt ra.

## 4.7. Kết luận chương

1. **RQ1.** Dijkstra (và A\*) luôn đạt chi phí tối ưu; BFS và Greedy trả về đường đắt hơn 29–67% (bộ viết tay) hoặc gấp 2,2–2,9 lần (bộ sinh tự động). Greedy có thể tệ hơn cả BFS khi heuristic bị dẫn sai.
2. **RQ2.** BFS luôn đạt độ dài tối thiểu; việc tối thiểu hóa chi phí khiến đường đi dài hơn 2–9 bước. L ≠ C ổn định ở mọi kích thước thử.
3. **RQ3.** Trong họ kịch bản đã thử, công sức của Dijkstra tăng gần tuyến tính theo |V| (số mũ ≈ 0,89), A\* tiết kiệm 19–53% so với Dijkstra với cùng chi phí tối ưu, còn BFS/DFS/Greedy hầu như không đổi do mục tiêu nằm nông. Kết luận này **không** được khái quát ra ngoài họ kịch bản.
4. **RQ4.** Cả năm thuật toán xử lý đúng trạng thái trùng, mục tiêu không đạt được và mục tiêu đã thỏa; chu trình thật không xuất hiện trong mô hình đơn điệu.
5. **Thứ tự hành động** ảnh hưởng mạnh tới DFS (chi phí dao động tới ~4 lần *C\**) nhưng không ảnh hưởng tới giá trị tối ưu của BFS, Dijkstra và A\*.

Tổng hợp lại, không có thuật toán nào vượt trội trên mọi tiêu chí: **Dijkstra/A\*** tốt nhất về chi phí, **BFS** tốt nhất về độ dài, **Greedy** tốn ít công sức nhất nhưng có thể cho chất lượng kém nhất, và **DFS** không có ưu thế ở tiêu chí nào và phụ thuộc vào thứ tự khai báo.
