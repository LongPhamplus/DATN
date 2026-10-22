# AAPEF — Master Plan (Kế hoạch Nghiên cứu & Thiết kế)

**Automated Attack Path Execution Framework**
*Tài liệu lập kế hoạch (chưa triển khai code) — phiên bản 0.4 — 2026-10-20*
*(v0.4: thêm precondition access, thống nhất quy tắc no-op giữa Search/Validation, định nghĩa đo `|V|/|E|`, trường hợp initial-goal & no-path, quy tắc access mapping đầy đủ, thứ tự duyệt DFS.)*

> **Trạng thái (cập nhật 2026-10-22):** Đã triển khai đến GĐ7 (phần kỹ thuật): có kết quả cả 4 RQ, có demo và script tái tạo. Phần dưới là thiết kế gốc (v0.4); tiến độ thực tế theo bảng sau.
>
> | GĐ | Nội dung | Trạng thái |
> |---|---|---|
> | 0 | Chốt RQ + schema | ✅ Thiết kế v0.4 được dùng làm cơ sở triển khai |
> | 1 | Lõi transition `state.py` | ✅ Xong |
> | 2 | MVP end-to-end qua CLI | ✅ Xong |
> | 3 | BFS/DFS/Dijkstra/Greedy + correctness test | ✅ Xong |
> | 4 | Simulation + goal validation | ✅ Xong (evidence validation: không bật, [TÙY CHỌN]) |
> | 5 | Benchmark + 4 scenario + CSV/JSON | ✅ Xong (runtime: 2 warm-up, trung vị + IQR; thêm `analysis.csv`) |
> | 6 | Thực nghiệm + phân tích RQ1–4 | ✅ Có kết quả cho cả 4 RQ (`reports/BaoCao_PhanTich.md` §3, §8, §9). RQ3 đo trên 4–11.264 state bằng benchmark chính thức; kết luận RQ3 giới hạn trong họ scenario sinh (§7). Còn lại: biểu đồ và chương kết quả luận văn |
> | 6b | Chuyển sang chi phí CVSS (§9.2–9.3) | ✅ Phần kỹ thuật xong (2026-10-22): `aapef/cvss.py`, lệnh `recost`, `scenarios/cvss/`, `out/cvss/`, độ nhạy theo giả định; chi tiết `reports/ThayDoi_ChiPhiCVSS.md`. Phát hiện: đánh đổi L≠C biến mất khi chưa ghi đè vector. **Còn lại:** chọn hướng diễn giải (§7 của file thay đổi) rồi cập nhật số liệu trong chương kết quả và các báo cáo |
> | 7 | Demo + docs + bảo vệ | ✅ Phần kỹ thuật xong: lệnh `python -m aapef demo`, `scripts/reproduce.sh` (tái tạo toàn bộ kết quả, đã kiểm: mọi cột không phải thời gian giống hệt), README cập nhật. Còn lại: slide/bài viết bảo vệ |
> | 8 | A\*, composite cost, UI | 🔄 A\* đã xong (heuristic admissible + consistent, có test); composite cost và UI vẫn [HOÃN] |
>
> **Việc còn mở:** (0) hoàn tất chuyển sang chi phí CVSS rồi sinh lại số liệu, chương kết quả và hai báo cáo LaTeX; (1) biểu đồ cho luận văn, vẽ từ `out/scaling/analysis.csv` (cột `num_states`, `nodes_expanded`, `runtime_ms`, `cost_ratio`, `length_gap`); (2) thêm họ scenario thứ hai (goal ở sâu, nhiều tuyến) để kiểm tra RQ3 có tổng quát hóa không; (3) viết chương kết quả trong luận văn và chuẩn bị slide bảo vệ.
>
> **Mối đe dọa tính hợp lệ (đã kiểm chứng ngày 2026-10-21, chi tiết trong `reports/BaoCao_PhanTich.md` §7):** các hạn chế của bộ sinh scenario *không làm sai kết quả của app* (|V|, |E| do generator và AAPEF đo độc lập khớp 11/11; mọi path đều qua validation) nhưng *giới hạn phạm vi kết luận*: đường cong RQ3 của Dijkstra phụ thuộc cơ chế decoy; Greedy chưa nhạy thứ tự action; mọi scenario thuộc một họ cấu trúc. Phân tích hiện tại: `reports/BaoCao_PhanTich.md`. Kiểm thử: 54 test pass (chạy qua WSL). Đã có: thí nghiệm độ nhạy thứ tự action (`sensitivity`), config scaling `benchmark_scaling.json`.
>
> **Quy ước đánh dấu quyết định:** **[CHỐT]** = đã quyết, nằm trong critical path · **[TÙY CHỌN]** = chỉ làm nếu còn thời gian · **[HOÃN]** = ngoài MVP, chỉ là hướng mở rộng tương lai.

---

## 1. Tóm tắt đề tài

AAPEF là một **framework nghiên cứu thuật toán**: mô hình hóa việc lập kế hoạch Red Team thành bài toán **tìm kiếm trên không gian trạng thái (state-space search)** trong một môi trường **giả lập hoàn toàn bằng dữ liệu JSON**. Mục tiêu là **so sánh BFS, DFS, Dijkstra, Greedy Best-First** về chất lượng lời giải và chi phí tính toán, bằng **benchmark tái lập được**.

Không VM thật, không exploit thật, không lệnh OS, không AI/ML, không gọi công cụ tấn công ngoài. Chỉ đọc dữ liệu và áp dụng quy tắc.

**Câu hỏi nghiên cứu cốt lõi:** *Trên cùng một state-space graph (cạnh có trọng số không âm) và cùng một Goal, bốn thuật toán khác nhau thế nào về path length, total path cost, search effort (nodes expanded / edges examined), runtime, và goal correctness?*

**Nguyên tắc chủ đạo của phiên bản này:** ưu tiên **thiết kế nhỏ nhất đủ dùng** (xem §2). Một prototype end-to-end nhỏ, đúng, tái lập được, có giá trị hơn một framework lớn và trừu tượng.

---

## 2. Implementation Philosophy: Simplicity First (Triết lý: Đơn giản trước)

> Đây là nguyên tắc **xuyên suốt**, áp dụng cho kiến trúc, module, data model, thuật toán và roadmap bên dưới. Mục tiêu **không** phải là ít dòng code nhất, mà là **thiết kế hiệu quả nhỏ nhất chứng minh và đánh giá đúng ý tưởng nghiên cứu**.

1. **Chọn cách cài đặt đơn giản nhất thỏa mãn mục tiêu nghiên cứu.** Không thêm độ phức tạp chỉ để kiến trúc trông "chuyên nghiệp" hay "production-ready".
2. **Ưu tiên thư viện chuẩn của Python** (`heapq`, `collections.deque`, `json`, `time.perf_counter`, `dataclasses`, `csv`, `argparse`, `pytest`) và cấu trúc dữ liệu đơn giản (dict, tuple, frozenset). Chỉ thêm dependency ngoài khi có lợi ích rõ ràng và cần thiết.
3. **Dùng hàm đơn giản và module nhỏ với trách nhiệm rõ ràng.** Chỉ đưa vào class/interface/abstraction/DI/factory/registry/design pattern khi chúng giải quyết một vấn đề cụ thể.
4. **Tránh overengineering:** không kế thừa thừa, không generic framework, không cấu hình rườm rà, không event system / plugin system, không kiến trúc phân tán / microservices, không tầng xử lý lỗi cầu kỳ.
5. **JSON schema nhỏ, tường minh + vài hàm validate đơn giản.** Không xây ngôn ngữ mô tả kịch bản tổng quát hay rule engine phức tạp.
6. **Giữ môi trường, state transition và hành vi tìm kiếm tất định (deterministic) ở mọi nơi có thể.** Tái lập quan trọng hơn việc mô phỏng mọi tình huống đời thực.
7. **Lõi là ứng dụng command-line trước.** API, frontend, dashboard, database, hạ tầng triển khai **không** thuộc MVP trừ khi có yêu cầu được ghi nhận rõ làm nó trở nên thiết yếu.
8. **Ưu tiên bản cài đặt tối thiểu dễ hiểu, dễ debug, dễ test, dễ giải thích trong luận văn.**
9. **Không hy sinh** tính đúng đắn, khả năng tái lập, validation thiết yếu, hay tính hợp lệ của kết quả benchmark để đổi lấy ít dòng code hơn.
10. **Với mỗi component/abstraction đề xuất, tự hỏi:** *"Nó có trực tiếp phục vụ một research question, một yêu cầu correctness, hay một workflow cần thiết không?"* Nếu không → bỏ hoặc hoãn.

---

## 3. Phạm vi, giả định & ranh giới an toàn

### 3.1. Trong phạm vi (MVP) — [CHỐT]
Mô hình hóa môi trường/trạng thái/hành động bằng JSON nhỏ · sinh successor tất định · BFS/DFS/Dijkstra/Greedy · simulation replay + goal validation · benchmark runner xuất CSV/JSON · CLI.

### 3.2. Ngoài phạm vi — ràng buộc an toàn [CHỐT, bắt buộc]
- ❌ Không chạy lệnh OS, không khai thác lỗ hổng thật, không truy cập trái phép / lateral movement thật.
- ❌ Không gọi Metasploit / CALDERA / Infection Monkey để thực thi (chỉ khảo sát khái niệm; **không** tuyên bố benchmark trực tiếp với chúng).
- ❌ Không huấn luyện AI/ML. ❌ Không yêu cầu VM/hạ tầng thật.

### 3.3. Giả định — [CHỐT]
- Chi phí cạnh **không âm** (điều kiện cần cho Dijkstra).
- Môi trường & transition **tất định** trong toàn bộ nhánh so sánh thuật toán.
- Trạng thái **canonical-hóa được** để so sánh bằng nhau (§5).

### 3.4. Ranh giới học thuật — [CHỐT]
"Mô phỏng đạt goal" **≠** "có khả năng khai thác thực tế". Evidence là dữ liệu mô phỏng, không suy ra được khả năng tấn công thật.

---

## 4. Câu hỏi nghiên cứu & mục tiêu thuật toán

### 4.1. Năm đại lượng đo — định nghĩa chính xác, không trộn lẫn [CHỐT]

| Ký hiệu | Tên | Định nghĩa | Nguồn |
|---|---|---|---|
| **L** | Path length | Số **action/edge** trong path trả về | Search |
| **C** | Total path cost | **Tổng** `cost` của các action trong path. Với mô hình CVSS (§9.2–9.3): `cost` = round(10·(−ln p)) nên C ≈ −10·ln(xác suất thành công cả path) khi các bước độc lập; với mô hình cấu hình cũ (PA-A): tổng `cost` gõ tay | Search |
| **E_n** | Search effort — nodes | Số state được **expand** (lấy ra khỏi frontier để sinh successor) | Search |
| **E_e** | Search effort — edges | Số edge (successor) **được khảo sát** | Search |
| **T** | Runtime | Thời gian chạy đo bằng `perf_counter` | Search |
| **G** | Goal correctness | State cuối sau **simulation** có thỏa goal predicate không | Simulation |

> **L ≠ C**: BFS tối thiểu L, không nhất thiết tối thiểu C. **T ≠ E_n**: E_n độc lập phần cứng hơn, là chỉ số chính cho "công sức tìm kiếm". **G** đến từ pha Simulation, tách khỏi "Search có trả path không".

### 4.2. Câu hỏi nghiên cứu (đo lường được) [CHỐT]

- **RQ1 — Tính tối ưu chi phí:** Trên đồ thị cạnh không âm, C của mỗi thuật toán lệch bao nhiêu so với **C tối ưu** (tham chiếu Dijkstra)? *Kỳ vọng: Dijkstra đạt C tối ưu; BFS/DFS/Greedy có thể lệch.*
- **RQ2 — Tối ưu độ dài:** L của mỗi thuật toán so với **L tối thiểu** (tham chiếu BFS trên đồ thị không trọng số)? *Kỳ vọng: BFS đạt L tối thiểu.*
- **RQ3 — Search effort & runtime:** E_n, E_e, T thay đổi thế nào theo kích thước state-space? Greedy giảm E_n bao nhiêu so với tìm kiếm mù, đánh đổi gì ở C/L?
- **RQ4 — Robustness:** Các thuật toán xử lý **cycle / state trùng / goal không đạt được** ra sao (có dừng đúng, có báo no-path đúng không)?

### 4.3. Mục tiêu tối ưu khác nhau của từng thuật toán [CHỐT]

- **BFS:** tìm path **ít edge nhất** trên đồ thị tìm kiếm không trọng số. Không tối ưu C khi cạnh có trọng số khác nhau.
- **DFS:** **không** đảm bảo path tối ưu (cả L lẫn C); kết quả phụ thuộc thứ tự duyệt.
- **Dijkstra:** tìm path **chi phí nhỏ nhất** khi cạnh không âm.
- **Greedy Best-First:** ưu tiên heuristic hướng goal; **không** đảm bảo tối ưu L hay C.

> **Không khẳng định thuật toán nào tốt nhất một cách phổ quát.** So sánh luôn gắn với tiêu chí cụ thể của từng RQ. Dijkstra chỉ là **tham chiếu C tối ưu**, không phải baseline cho mọi chỉ số (không phải chuẩn cho L, E_n hay T).

---

## 5. Mô hình trạng thái & state identity

### 5.1. Phân biệt các loại "fact" — chỉ giữ cái cần cho RQ [CHỐT]

| Loại | Thuộc về | Tĩnh/Động | Ví dụ |
|---|---|---|---|
| **Environment fact** | Scenario (môi trường) | **Tĩnh**, read-only | `svc_svcY_present@B` — một service giả lập tồn tại |
| **Topology** | Scenario | **Tĩnh** | cạnh `A→B` trong `topology` (reachability) |
| **Known fact** | **State** (attacker đã khám phá) | **Động** | `known_service@B:svcY` |
| **Access level** | **State** | **Động** | `access[C] = admin` |

**Quyết định đơn giản hóa [CHỐT]:** reachability dùng **topology tĩnh** trong scenario. *Reachability phụ thuộc state* (ví dụ chỉ reachable sau khi chiếm được host trung gian) là **[HOÃN]** — chỉ thêm nếu một RQ đòi hỏi, với acceptance criteria riêng. Lý do: giữ state model nhỏ, tránh mô hình hóa phân biệt không cần thiết.

### 5.2. Biểu diễn State tối thiểu [CHỐT]

Một State chỉ gồm **hai trường động**:
- `access`: ánh xạ `host_id → level` với `level ∈ {none, user, admin}` (có thứ tự `none < user < admin`).
- `known`: tập các known-fact (chuỗi), ví dụ `"known_service@B:svcY"`.

Environment facts và topology **không** nằm trong State (chúng tĩnh, nằm ở scenario) → State nhỏ, số node ít hơn, so sánh nhanh.

**Quy tắc đầy đủ của `access` mapping [CHỐT]** (để `state_key` không mơ hồ: một state thiếu key host và một state khai báo host đó = `none` **không** được tạo ra hai key khác nhau):
- `initial_state.access` phải chứa **đầy đủ tất cả host ID** khai báo trong scenario (không thiếu, không thừa).
- Mỗi host có **đúng một** level trong `{none, user, admin}`.
- `apply` **không bao giờ xóa** host khỏi `access`; `set_access` **chỉ nâng** level, **giữ nguyên** mọi host mapping, **không hạ** quyền.
- Vì mọi host luôn hiện diện với đúng một level ngay từ initial state và không bị xóa, mọi state về sau đều có **cùng tập host key** ⇒ `state_key` (§5.3) nhất quán.
- **Scenario validator từ chối** access mapping **thiếu host**, **thừa host**, hoặc **level không hợp lệ** — báo lỗi rõ ràng, **không** tự động chuẩn hóa để che giấu lỗi schema.

### 5.3. Canonical `state_key` — chống lặp vô hạn & trùng node [CHỐT]

```
state_key(state) =
    ( tuple(sorted(state.access.items())),     # ví dụ (("A","user"),("B","none"),("C","none"))
      tuple(sorted(state.known)) )             # ví dụ ("known_service@B:svcY",)
```

- **Trường tham gia key:** `access` và `known` — đúng và chỉ những trường định nghĩa trạng thái động. Sắp xếp để **bất biến với thứ tự dict**.
- Hai state có cùng `state_key` là **cùng một node**. `state_key` là tuple bất biến, hashable → dùng trực tiếp làm phần tử của `visited` set / khóa của `dist` map.
- **Mọi thuật toán** kiểm tra visited theo `state_key` ⇒ state-space hữu hạn, không lặp vô hạn, không tách state tương đương thành node khác nhau.

---

## 6. Hành động & JSON schema

### 6.1. Nguyên tắc schema [CHỐT]
Một **scenario = một file JSON** (gộp hosts + topology + actions + initial_state + goal) để ít file, dễ nạp. Mỗi field có **nghĩa, kiểu, ví dụ** xác định. Validate bằng **vài hàm Python đơn giản**, **không** dùng framework schema-validation nặng.

### 6.2. Các kiểu precondition & effect tối thiểu [CHỐT]

**Precondition** (mọi điều kiện phải đúng thì action mới applicable):
| `type` | Trường | Ý nghĩa | Kiểm tra dựa trên |
|---|---|---|---|
| `access_at_least` | `host, level` | access của host ≥ level | State |
| `known` | `fact` | attacker đã biết fact | State |
| `env_fact` | `fact` | môi trường có fact tĩnh | Scenario (tĩnh) |
| `reachable` | `from, to` | có cạnh topology from→to | Scenario (tĩnh) |

**Effect** (áp dụng khi action chạy thành công):
| `type` | Trường | Ý nghĩa |
|---|---|---|
| `set_access` | `host, level` | nâng access của host lên level (chỉ nâng, không hạ) |
| `learn` | `fact` | thêm fact vào `known` |

**Goal predicate** (MVP): `{ "type": "access_at_least", "host": ..., "level": ... }`. (Mở rộng goal phức hợp = **[HOÃN]**.)

**Quy ước khai báo precondition [CHỐT]:**
- Mỗi action phải khai báo **đầy đủ** mọi precondition cần thiết theo mô hình giả lập.
- Nếu action mô tả attacker **thao tác từ một host nguồn**, phải có precondition `access_at_least` kiểm tra access trên host đó (ví dụ `discover_svcY_on_B` thao tác từ A ⇒ cần `access_at_least A user`).
- **Topology/reachability không tự động cấp quyền** và **không thay thế** precondition kiểm tra access: `reachable` chỉ nói "có đường từ X tới Y", không nói "đã có quyền trên X".
- Mục tiêu là **nhất quán logic của scenario**, không phải mô phỏng chi tiết hành vi Red Team thực tế.

### 6.3. Ví dụ `scenario.json` (hợp lệ, nhất quán) [CHỐT]

```json
{
  "scenario_id": "demo-small-01",
  "description": "3 host gia lap, goal = admin tren C",
  "hosts": [
    { "id": "A", "ip": "10.0.0.1", "hostname": "ws",     "os": "sim-os",
      "services": [{ "name": "svcX", "port": 8080, "protocol": "tcp" }] },
    { "id": "B", "ip": "10.0.0.2", "hostname": "appsrv", "os": "sim-os",
      "services": [{ "name": "svcY", "port": 5432, "protocol": "tcp" }] },
    { "id": "C", "ip": "10.0.0.3", "hostname": "target", "os": "sim-os",
      "services": [] }
  ],
  "topology": [["A", "B"], ["B", "C"]],
  "env_facts": ["svc_svcY_present@B", "svc_svcZ_present@C"],
  "initial_state": {
    "access": { "A": "user", "B": "none", "C": "none" },
    "known": []
  },
  "actions": [
    {
      "id": "discover_svcY_on_B",
      "name": "Discover simulated service svcY on B",
      "preconditions": [
        { "type": "access_at_least", "host": "A", "level": "user" },
        { "type": "reachable", "from": "A", "to": "B" }
      ],
      "cost": 1,
      "effects": [
        { "type": "learn", "fact": "known_service@B:svcY" }
      ],
      "evidence": ["svc_banner_sim@B:svcY"]
    },
    {
      "id": "gain_user_on_B",
      "name": "Gain simulated user access on B",
      "preconditions": [
        { "type": "known",   "fact": "known_service@B:svcY" },
        { "type": "env_fact", "fact": "svc_svcY_present@B" }
      ],
      "cost": 3,
      "effects": [
        { "type": "set_access", "host": "B", "level": "user" }
      ],
      "evidence": ["access_token_sim@B:user"]
    },
    {
      "id": "pivot_and_admin_on_C",
      "name": "Pivot to C and gain simulated admin",
      "preconditions": [
        { "type": "access_at_least", "host": "B", "level": "user" },
        { "type": "reachable", "from": "B", "to": "C" },
        { "type": "env_fact",  "fact": "svc_svcZ_present@C" }
      ],
      "cost": 5,
      "effects": [
        { "type": "set_access", "host": "C", "level": "admin" }
      ],
      "evidence": ["access_token_sim@C:admin"]
    }
  ],
  "goal": { "type": "access_at_least", "host": "C", "level": "admin" }
}
```

> **Fix so với v0.1:** bản trước có effect sai cú pháp `{ "set_access", "args": [...] }` (thiếu khóa) và tách nhiều file. Nay dùng một schema effect `{ "type": ..., "host": ..., "level": ... }` nhất quán, gộp vào một scenario file.

**`hosts[].services` vs `env_facts` — nguồn sự thật duy nhất [CHỐT]:** hai trường có mục đích **tách biệt, không trùng lặp vai trò**:
- **`env_facts`** là **nguồn sự thật duy nhất (single source of truth)** cho các fact mà **precondition** kiểm tra (qua `env_fact`). Chỉ những gì nằm trong `env_facts` mới ảnh hưởng tới tính applicable của action.
- **`hosts[].services`** là **metadata mô tả thuần túy** (name/port/protocol) phục vụ hiển thị và đọc hiểu kịch bản. **Precondition không bao giờ đọc `services`.** Việc một host liệt kê `svcY` nhưng không có `svc_svcY_present@B` trong `env_facts` là hợp lệ và có nghĩa là service đó *không* được dùng làm điều kiện.

Nhờ quy ước này, không có fact nào bị định nghĩa ở hai nơi: logic thuật toán chỉ phụ thuộc `env_facts`, `services` chỉ để mô tả.

### 6.4. `benchmark_config.json` [CHỐT]
```json
{
  "scenarios": ["demo-small-01", "medium-01", "large-01", "unreachable-01"],
  "algorithms": ["bfs", "dfs", "dijkstra", "greedy"],
  "cost_model": "config",
  "runtime_repeats": 30,
  "seed": 42
}
```
`evidence` ở §6.3 là **[TÙY CHỌN]** — chỉ validate nếu thiết kế yêu cầu (xem §8).

---

## 7. State transition & successor generation

### 7.1. Một hàm transition duy nhất, dùng chung [CHỐT]

Toàn hệ thống dùng **đúng hai hàm thuần (pure)**, không side-effect, dùng lại ở cả Search, Simulation và Validation:

```
applicable(state, scenario, action) -> bool
    # True nếu MỌI precondition của action đúng với (state tĩnh + scenario)

apply(state, action) -> new_state
    # Trả về State MỚI (copy), áp dụng effects; KHÔNG sửa state gốc
```

- `apply` tạo State mới (copy `access`, `known`), áp dụng từng effect (`set_access` chỉ nâng cấp; `learn` thêm fact). **Không** mutate input, **không** đụng scenario.
- Đầu vào tương đương ⇒ đầu ra tương đương (tất định).

### 7.2. `successors(state)` — tất định, side-effect-free [CHỐT]

```
successors(state, scenario) -> list[(action, next_state, cost)]
    out = []
    for a in scenario.actions:                       # thu tu co dinh trong file
        if not applicable(state, scenario, a):
            continue
        nxt = apply(state, a)
        if state_key(nxt) == state_key(state):        # no-op: action khong doi trang thai
            continue                                  # -> loai khoi successor (MVP)
        out.append((a, nxt, a.cost))
    return out
```

- Duyệt actions theo **thứ tự cố định trong file** ⇒ danh sách successor **tất định** (quan trọng cho tie-break tái lập).
- **No-op action [CHỐT] — quy tắc thống nhất:** một action *applicable* nhưng cho `state_key(apply(state,a)) == state_key(state)` (effect không thay đổi gì: ví dụ `set_access` xuống mức đã có, `learn` một fact đã biết) là **no-op**.
  1. **Cạnh hợp lệ** của state-space graph = action *applicable* **và** state sau khác state trước theo `state_key`.
  2. `successors` **loại** no-op (như code trên) ⇒ **self-loop không bao giờ xuất hiện** trong graph.
  3. Khi **replay & validate** một candidate path, mỗi action phải **(a)** applicable tại state hiện tại **và (b)** tạo state mới khác state hiện tại theo `state_key`. Nếu một action là no-op → **path bị đánh dấu `path_valid = false`** (xem §8).
  4. `apply(state, action)` **giữ nguyên semantics**, vẫn là hàm thuần — **không** sửa `apply` để tự loại no-op; việc phát hiện no-op là do so sánh `state_key` ở `successors` và Validation thực hiện.
  Nhờ vậy quy tắc no-op **nhất quán** giữa Search và Validation: cả hai coi "cạnh/bước không đổi state" là không hợp lệ.
- Không mutate state gốc hay scenario. Đây là **nguồn duy nhất** sinh edge — cả benchmark lẫn simulation dùng cùng semantics ⇒ không có ba bản sao logic transition.

---

## 8. Tách Search / Simulation / Validation (không trùng lặp)

Ba trách nhiệm **tách bạch nhưng tối thiểu**, cùng tựa trên `applicable`/`apply` ở §7:

- **Search** — khám phá state-space qua `successors`, trả về **candidate path** (chuỗi action) + metrics (L, C, E_n, E_e, T). Không simulate.
- **Simulation** — **replay** path trên một **copy của initial_state**, áp dụng từng action theo thứ tự bằng chính `apply`. Cho ra state cuối.
- **Validation** — kiểm tra, với mỗi action trong path, theo thứ tự: **(a)** action **applicable** tại state hiện tại (bằng chính `applicable`); **(b)** `apply` tạo ra state **khác** state hiện tại theo `state_key` (không phải no-op — §7.2); nếu một action no-op → `path_valid = false`. Sau khi replay hết path, kiểm tra state cuối **thỏa goal predicate** (`goal_reached`). Validate `evidence` **chỉ khi** thiết kế chọn yêu cầu nó — **[TÙY CHỌN]**, mặc định MVP không bắt buộc.

> **Không** dựng "execution-engine" cầu kỳ hay tầng abstraction thừa. Search/Simulation/Validation chỉ là ba hàm gọi lại `applicable`/`apply`/`state_key` — **không tự cài đặt logic transition khác**.

---

## 9. Mô hình đồ thị & chi phí

### 9.1. State-space graph sinh động (lazy) [CHỐT]
Node = State (`state_key`). Edge = action áp dụng được **và làm thay đổi trạng thái** (no-op bị loại, §7.2), sinh **lúc duyệt** qua `successors` (không dựng sẵn toàn đồ thị → tránh bùng nổ bộ nhớ). Mọi thuật toán chạy trên **cùng** `successors`, cùng goal, cùng scenario.

### 9.2. Mô hình chi phí [CHỐT / HOÃN] — *sửa đổi 2026-10-22*
- **[CHỐT]** **Chi phí dẫn xuất từ CVSS (PA-C):** `cost` nguyên ≥ 0 trong JSON do công thức CVSS v3.1 *tính ra* (§9.3), không phải do người thiết kế gõ. Đây là mô hình chi phí **chính** cho các thực nghiệm mới. Lý do thay đổi: chi phí gõ tay dựa trên phán đoán của người thiết kế, khó bảo vệ; CVSS là chuẩn công khai, có bảng hệ số cố định, trích dẫn được.
- **[GIỮ, vai trò hồi quy]** **Config cost (PA-A):** các kịch bản và kết quả cũ (chi phí gõ tay/sinh ngẫu nhiên theo seed) được giữ nguyên để kiểm thử hồi quy và đối chiếu; **không** dùng làm cơ sở cho kết luận chính của luận văn sau thay đổi này.
- **[HOÃN]** **Composite/normalized cost (PA-B):** chỉ là mở rộng tùy chọn, **phải** kèm chuẩn hóa về [0,1], trọng số công bố tường minh, và **phân tích độ nhạy**; báo cáo **tách biệt**. Không gộp đại lượng khác đơn vị vào một công thức tùy tiện.

### 9.3. Chi phí dẫn xuất từ CVSS v3.1 (PA-C) [CHỐT]
**Cơ sở.** Điểm *Exploitability* của CVSS v3.1 (FIRST): `E = 8,22 × AV × AC × PR × UI`, với hệ số cố định theo đặc tả (Scope Unchanged): AV N/A/L/P = 0,85/0,62/0,55/0,2 · AC L/H = 0,77/0,44 · PR N/L/H = 0,85/0,62/0,27 · UI N/R = 0,85/0,62.

**Biến đổi sang chi phí.** `p = E / 10` (E tối đa ≈ 3,887 nên p ≤ 0,389); `cost = round(10 × (−ln p))`. Vì −ln biến tích xác suất thành tổng, tổng `cost` dọc path ≈ −10·ln(xác suất thành công cả path) khi các bước độc lập; Dijkstra/A\* vì vậy tìm path *có xác suất thành công cao nhất*. Chi phí luôn ≥ 0 (điều kiện của Dijkstra) và là số nguyên (validator hiện tại).

**Dẫn xuất vector từ cấu trúc action** (quy tắc công bố, tất định):
- **AV** = `N` nếu action có precondition `reachable`, ngược lại `L`.
- **PR** = mức cao nhất trong các precondition `access_at_least` (`none`→`N`, `user`→`L`, `admin`→`H`); không có precondition quyền → `N`.
- **AC** = `L`, **UI** = `N` (mặc định công bố, có thể đổi bằng tham số).
- **Ghi đè từng action:** trường tùy chọn `cvss_override` (một phần của vector, ví dụ `{"AC": "H"}`). Vector hiệu lực được ghi vào `cvss`; `cost_model` ghi các tham số đã dùng.
- **Action thu thập thông tin** (effects chỉ có `learn`, không có `set_access`): CVSS chấm *lỗ hổng* nên không áp dụng; dùng xác suất cố định `p = 0,9` (cost 1).

**Giả định phải công bố trong luận văn:** Scope Unchanged; AC=L, UI=N mặc định; chuẩn hóa p=E/10; hệ số 10; p_thu_thập=0,9; các bước độc lập; vector dẫn xuất từ cấu trúc chỉ là *xấp xỉ* (quyền nguồn ≠ quyền trên đích theo nghĩa CVSS).

**Hệ quả cần chấp nhận.** (i) Các bất biến do bộ sinh áp đặt (tuyến trực tiếp luôn đắt hơn tuyến dài, bẫy Greedy luôn hiệu lực) **không còn được đảm bảo**; đánh đổi L≠C chỉ xuất hiện khi cấu trúc hoặc `cvss_override` tạo ra nó, và **không điều chỉnh số để ép kết quả**. (ii) Hai action cùng vector có cùng chi phí nên tuyến ít bước thường rẻ hơn. (iii) Mọi số liệu C\*, bảng RQ1–RQ3 và báo cáo phải tính lại.

**Hạn chế (nêu trong luận văn):** CVSS chấm lỗ hổng chứ không chấm hành động; điểm khai thác đo mức dễ khai thác, không phải rủi ro; giả định độc lập giữa các bước; chi phí không phản ánh độ khó thực của một cuộc tấn công cụ thể.

**Triển khai.** `aapef/cvss.py` (công thức, dẫn xuất, tính lại), lệnh `python -m aapef recost` (đọc kịch bản, ghi bản đã tính lại vào `scenarios/cvss/`), kiểm tra `cvss`/`cvss_override` trong validator. **Phân tích độ nhạy theo giả định:** đổi AC/UI mặc định, chuẩn hóa (10 so với 3,887), hệ số nhân, p_thu_thập; báo cáo kết luận nào giữ nguyên.

---

## 10. So sánh thuật toán

Giao diện chung [CHỐT]: mỗi thuật toán là một **hàm** nhận `(initial_state, successors, is_goal)`, trả `(path | None, metrics)`. Không cần class/registry — một dict `name → function` là đủ.

| Thuật toán | Cấu trúc frontier | Tối ưu theo | Visited / lặp | Tie-break (tất định) | Dừng | No-path |
|---|---|---|---|---|---|---|
| **BFS** | `deque` FIFO | L (số edge) | `visited` set theo `state_key` | thứ tự FIFO (theo thứ tự successors) | goal lần đầu pop | queue rỗng → `None` |
| **DFS** | stack (LIFO) | — (không tối ưu) | `visited` theo `state_key` | thứ tự successors cố định | gặp goal | stack rỗng → `None` |
| **Dijkstra** | `heapq` theo g | C (tổng chi phí) | `dist` map + settled theo `state_key` | g bằng nhau → thứ tự chèn | pop goal khỏi PQ | PQ rỗng → `None` |
| **Greedy** | `heapq` theo h | h (heuristic) — không tối ưu | `visited` theo `state_key` | h bằng nhau → thứ tự chèn | gặp goal | PQ rỗng → `None` |
| **A\*** [TÙY CHỌN] | `heapq` theo f=g+h | C (nếu h admissible) | g-map theo `state_key` | f bằng → g rồi thứ tự chèn | pop goal | PQ rỗng → `None` |

**Quy tắc chung bắt buộc (đồng nhất giữa các thuật toán) [CHỐT]:**
- Visited/relaxation luôn theo canonical `state_key` (§5.3).
- **DFS [CHỐT]:** dùng **stack (LIFO)** + `visited` theo `state_key`, **không** depth-limit trong MVP (state-space đã hữu hạn nhờ `visited` + loại no-op/self-loop §7.2; depth-limit chỉ thêm nếu có kịch bản cụ thể đòi hỏi — hiện **[HOÃN]**). **Thứ tự duyệt tất định:** thứ tự action trong JSON xác định thứ tự ưu tiên mong muốn; khi đẩy successors vào stack, **push theo thứ tự ngược (reversed)** để action đứng **trước** trong JSON được **pop ra xử lý trước**. Nhờ vậy DFS cho kết quả tất định và bám theo thứ tự ưu tiên đã khai báo.
- **Tie-break PQ tất định (Dijkstra & Greedy) [CHỐT]:** dùng một **biến đếm thứ tự chèn** `counter` tăng dần. Mỗi phần tử đẩy vào `heapq` là tuple `(priority, counter, state_key, path)` — khi `priority` bằng nhau, `heapq` so sánh `counter` (luôn duy nhất) ⇒ **không bao giờ so sánh trực tiếp object State** (tránh lỗi "unorderable" và đảm bảo kết quả tái lập 100%). BFS/DFS đã tất định nhờ thứ tự successors nên không cần counter.
- Phân biệt "thuật toán báo no-path" với "có path nhưng Simulation fail".
- **Trường hợp biên — `initial_state` đã thỏa goal [CHỐT]:** mọi thuật toán **kiểm tra goal trước khi expand state đầu tiên**, nên khi initial state đã đạt goal, kết quả thống nhất cho cả bốn thuật toán: path rỗng `[]`, `path_found = true`, `num_actions = 0`, `total_cost = 0`, `nodes_expanded = 0`, `edges_examined = 0`, `runtime_ms` vẫn đo theo §12.3. Simulation giữ nguyên initial state ⇒ `path_valid = true`, `goal_reached = true`.

**Heuristic cho Greedy [CHỐT]:** đơn giản, có cơ sở, ví dụ `h = 0 nếu goal đã thỏa, ngược lại = số "mức access còn thiếu để đạt goal"`. Ghi rõ công thức để tái lập; Greedy **không** yêu cầu admissible.

**A\* [TÙY CHỌN]:** chỉ đưa vào **kết luận tối ưu** nếu chứng minh được heuristic **admissible** (ví dụ: `(số bậc access còn thiếu) × (cost action rẻ nhất)` — cần chứng minh không vượt chi phí thật). Nếu không chứng minh được → giữ ở mức thảo luận, **không** mở rộng thuật toán chỉ để tăng số lượng.

---

## 11. Kiến trúc & ranh giới MVP

### 11.1. Workflow tối thiểu [CHỐT]
```
Load Scenario → Initialize State → Generate Successors → Run Search
    → Replay Path → Validate Result → Record Benchmark Metrics
```

### 11.2. Cấu trúc module tối giản [CHỐT]

| Module (file gợi ý) | Trách nhiệm duy nhất | Input tối thiểu | Output tối thiểu | Vì sao cần | Ngoài phạm vi (explicit) |
|---|---|---|---|---|---|
| `scenario.py` | Nạp + validate scenario JSON | đường dẫn file | object scenario (hosts, topology, env_facts, actions, initial_state, goal) | Mọi thứ bắt đầu từ dữ liệu hợp lệ | Không ngôn ngữ kịch bản tổng quát, không rule engine |
| `state.py` | State + `state_key` + `applicable` + `apply` + `successors` | state, scenario, action | bool / state mới / list successor | Lõi transition dùng chung §7 | Không ORM, không persistence |
| `search.py` | BFS/DFS/Dijkstra/Greedy (+A\* nếu có) | initial_state, successors, is_goal | path | None + metrics | Mỗi thuật toán 1 hàm | Không framework thuật toán, không class thừa |
| `simulate.py` | Replay path + validate goal (tái dùng `apply`/`applicable`) | path, scenario | state cuối + {valid, goal_reached} | Tách Search khỏi kết quả mô phỏng | Không execution-engine cầu kỳ |
| `benchmark.py` | Chạy đồng điều kiện, đếm metrics, xuất CSV/JSON | benchmark_config, scenarios | file CSV/JSON | Thu số liệu RQ | Không database, không dashboard |
| `cli.py` | Điểm vào command-line (`argparse`) | tham số dòng lệnh | gọi các module trên | Chạy end-to-end | Không web server |

> Có thể gộp thêm nếu đơn giản hơn (ví dụ `state.py` + `search.py`). **Không** tạo một module riêng cho mỗi helper nhỏ chỉ để theo kiến trúc cứng nhắc.

### 11.3. Ranh giới MVP [CHỐT]
Trong MVP: 6 module trên + CLI, output **CSV/JSON**. Ngoài MVP: **API, frontend, dashboard, database, deployment** = **[HOÃN]** (chỉ làm nếu có yêu cầu được ghi nhận). **A\*, composite cost, replanning, tích hợp công cụ thật** = **[TÙY CHỌN]/[HOÃN]**, ngoài critical path.

---

## 12. Thiết kế benchmark

### 12.1. Bộ kịch bản — đo **độ phức tạp state-space thật**, không lấy số host làm proxy [CHỐT]

| Scenario | Đặc điểm | Kiểm tra hành vi kỳ vọng |
|---|---|---|
| `demo-small-01` | 1 path thẳng tới goal, tính tay được | Correctness cơ bản; mọi thuật toán tìm ra path |
| `medium-01` | **Nhiều path khác nhau về L và C** | BFS chọn ít-edge; Dijkstra chọn rẻ nhất; cho thấy L≠C |
| `large-01` | Nhiều nhánh + **dead-end** + **cycle** + nhiều đường tới goal | Robustness, visited/loop handling, E_n tăng rõ |
| `unreachable-01` | Goal **không đạt được** | No-path handling đúng, không lặp vô hạn, dừng đúng |

> Báo cáo `|V|, |E|` **thực đo** cho mỗi scenario — **không** suy từ số host. Cách đo chuẩn ở **§12.5** (bước tham chiếu riêng, tách khỏi mỗi lần chạy thuật toán). Nếu cần sinh scenario tự động, dùng dữ liệu **tất định + seed cố định**.

### 12.2. Điều kiện công bằng [CHỐT]
Mọi thuật toán dùng **cùng** scenario, initial_state, goal predicate, action semantics, cost. Tie-break tất định (§10).

### 12.3. Chỉ số & cách đếm [CHỐT]
Đo tối thiểu: `path_found` (bool), `path_valid` (bool khi có path, `null` khi no-path — từ Validation), `goal_reached` (bool, từ Simulation), `num_actions` (L), `total_cost` (C), `nodes_expanded` (E_n), `edges_examined` (E_e), `runtime_ms` (T).

- **Cách đếm — định nghĩa y hệt cho cả bốn thuật toán [CHỐT]:**
  - **`E_n` (node expanded) +1** đúng một lần cho mỗi state khi nó được **lấy khỏi frontier và được xử lý** (sinh successors). Với Dijkstra/Greedy dùng PQ có thể chứa bản sao cũ (stale): nếu pop ra một `state_key` **đã settled/visited** thì **bỏ qua, KHÔNG đếm** `E_n` và không sinh successors.
  - **`E_e` (edge examined) +1** cho **mỗi successor** mà `successors(state)` trả về trong một lần expand — **bao gồm cả** edge dẫn tới `state_key` **đã visited** (edge vẫn được "xét" dù không được nạp vào frontier). Vì no-op/self-loop đã bị loại ở §7.2 nên không có edge tự-lặp nào được đếm.
  - **`T` (runtime)** = thời gian của **riêng vòng lặp tìm kiếm**: thao tác frontier (push/pop), gọi `successors` (gồm `applicable`/`apply`), kiểm tra goal, kiểm tra `visited`/`dist`. **Loại trừ**: nạp & validate scenario, Simulation, Validation, và xuất CSV/JSON.
- **Schema kết quả khi Search trả no-path [CHỐT]:**

  | Field | Giá trị khi không tìm được path |
  |---|---|
  | `path_found` | `false` |
  | `path_valid` | `null` |
  | `goal_reached` | `false` |
  | `num_actions` | `null` |
  | `total_cost` | `null` |
  | `nodes_expanded` | giá trị đo được |
  | `edges_examined` | giá trị đo được |
  | `runtime_ms` | giá trị đo được |

  `path_valid = null` vì **không có candidate path để validate**. `goal_reached = false` ở đây nghĩa là **Search không tạo ra path nào để mô phỏng** — **không** được diễn giải là "đã replay một path nhưng thất bại". (Vì vậy `path_valid` là *bool khi có path*, *null khi no-path*.)
- **Phân biệt với trường hợp có path nhưng Simulation/Validation thất bại:** khi đó `path_found = true`, `path_valid = false` (ví dụ gặp no-op hoặc action không applicable lúc replay), `goal_reached` = kết quả kiểm tra goal trên state cuối. Luôn tách rõ ba cờ `path_found` / `path_valid` / `goal_reached`.
- `L`, `C`, `E_n`, `E_e` là **tất định** → đo **1 lần** là đủ. Chỉ `T` đo lặp (`runtime_repeats = 30`, có 1–2 lần warm-up), báo cáo **trung vị + IQR**.

### 12.4. Baseline & giới hạn [CHỐT]
Dijkstra = tham chiếu **C tối ưu** (cạnh không âm). BFS = tham chiếu **L tối thiểu**. **Giới hạn:** không dùng Dijkstra làm chuẩn cho L, E_n hay T.

### 12.5. Đo kích thước toàn bộ state-space `|V|`, `|E|` (bước tham chiếu riêng) [CHỐT]

Các thuật toán dùng **lazy search** nên mỗi lần chạy chỉ khám phá **một phần** graph trước khi gặp goal. Vì vậy `|V|, |E|` được đo bằng **một bước duyệt tham chiếu độc lập**, cho mỗi scenario, **một lần**:

- Bắt đầu từ `initial_state`, duyệt **toàn bộ** state reachable **bằng chính hàm `successors`** (cùng semantics với tìm kiếm).
- Dùng một `visited` set theo `state_key` để mỗi state **duy nhất** chỉ đếm một lần ⇒ xử lý được **cycle và state trùng, không lặp vô hạn**.
- **`|V|`** = số `state_key` **duy nhất** reachable từ `initial_state`.
- **`|E|`** = **tổng số cạnh có hướng** sinh ra từ các state reachable. Nếu **nhiều action khác nhau** cùng dẫn tới một state đích, **mỗi cạnh-theo-action vẫn đếm riêng**.
- **No-op không được tính là cạnh** (đã bị `successors` loại, §7.2).
- Không cần lưu toàn bộ graph trong bộ nhớ: chỉ cần `visited` set + một bộ đếm cạnh trong lúc duyệt (BFS/DFS trên state-space đều được).

**Tách biệt rõ (không nhầm lẫn) [CHỐT]:**
- `|V|`, `|E|` = **kích thước toàn bộ state-space reachable** của scenario (thuộc tính của scenario, không phụ thuộc thuật toán tìm kiếm cụ thể).
- `nodes_expanded` (E_n), `edges_examined` (E_e) = **lượng công việc của một lần chạy một thuật toán** (§12.3), thường **nhỏ hơn** `|V|`/`|E|` vì lazy search dừng khi gặp goal.
- Bước đo `|V|, |E|` là **benchmark phụ**, chạy riêng và **nằm ngoài** `runtime_ms` của từng thuật toán — **không** thay đổi định nghĩa `runtime_ms` ở §12.3.

---

## 13. Chiến lược test & tiêu chí nghiệm thu

### 13.1. Test (pytest, gọn nhưng đủ) [CHỐT]
- Scenario file **hợp lệ / không hợp lệ** → validate chấp nhận / báo lỗi rõ.
- `applicable` đúng với precondition thỏa/không thỏa; `apply` áp dụng đúng effect.
- **State immutability:** `successors`/`apply` **không** sửa state gốc (so sánh trước/sau).
- **No-op bị loại:** action applicable nhưng không đổi `state_key` **không** xuất hiện trong `successors` (self-loop không tồn tại trong graph).
- **Canonical identity:** hai dict access/known khác thứ tự → cùng `state_key`.
- **BFS** cho L tối thiểu trên scenario tính tay.
- **Dijkstra** cho C tối thiểu trên scenario tính tay.
- **DFS/Greedy:** kiểm tra chạy đúng & dừng, **không** khẳng định tối ưu (không có assert optimality).
- **Cycle / state trùng / goal unreachable:** thuật toán dừng, báo no-path đúng, không lặp vô hạn.
- **Simulation replay** cho state cuối đúng; **goal validation** đúng/sai đúng kỳ vọng.
- **Benchmark tất định:** chạy lại cho `L/C/E_n/E_e` giống hệt (loại trừ dao động `T`).
- **Đếm metric nhất quán** giữa các thuật toán trên cùng scenario nhỏ: `E_n`/`E_e` khớp định nghĩa §12.3 (edge tới state đã visited vẫn tính `E_e`; pop stale ở Dijkstra/Greedy không tính `E_n`).
- **Tie-break tất định (Dijkstra/Greedy):** scenario có nhiều đường cùng priority → kết quả path giống hệt qua nhiều lần chạy; PQ không so sánh object State (dùng `counter`).

**Test bổ sung cho các quy tắc v0.4 [CHỐT]:**
1. **Precondition access:** `discover_svcY_on_B` **không** applicable nếu `access[A] < user`; applicable khi `access[A] >= user` (các precondition khác thỏa).
2. **No-op bị Validation từ chối:** một candidate path chứa action no-op (state sau = state trước theo `state_key`) → Validation trả `path_valid = false`.
3. **Đo `|V|,|E|` an toàn:** trên scenario có **cycle** và **state trùng**, bước đo §12.5 kết thúc (không lặp vô hạn) và đếm mỗi state duy nhất một lần.
4. **Cạnh song song:** nhiều action khác nhau cùng dẫn tới một state đích → mỗi action vẫn được tính là **một cạnh riêng** trong `|E|`.
5. **Initial-goal:** khi `initial_state` đã thỏa goal → path `[]`, `path_found=true`, `num_actions=0`, `total_cost=0`, `nodes_expanded=0`, `edges_examined=0`, `path_valid=true`, `goal_reached=true` (cho cả bốn thuật toán).
6. **Validator access mapping:** scenario có `initial_state.access` **thiếu host**, **thừa host**, hoặc **level không hợp lệ** → bị **từ chối** với lỗi rõ ràng.
7. **No-path schema:** khi Search không tìm được path → `path_found=false`, `path_valid=null`, `goal_reached=false`, `num_actions/total_cost=null`, vẫn có `nodes_expanded/edges_examined/runtime_ms`.
8. **Thứ tự ưu tiên DFS:** trên scenario có nhánh, DFS pop/xử lý action theo **thứ tự khai báo trong JSON** (nhờ push reversed) và cho kết quả tất định.

Tránh hạ tầng test thừa — một thư mục `tests/` + `pytest` là đủ.

### 13.2. Tiêu chí nghiệm thu MVP (cụ thể, test được) [CHỐT]
1. Nạp + validate `scenario.json` theo §6 (gồm **đầy đủ `access` mapping** §5.2); file sai (thiếu/thừa host, level không hợp lệ, cú pháp) bị từ chối với thông báo rõ.
2. Sinh `initial_state` và `state_key` tất định (test §13.1 pass).
3. `successors` tất định, side-effect-free (test immutability pass).
4. BFS/DFS/Dijkstra/Greedy chạy trên cùng đồ thị, trả path + đủ 6 metric.
5. Correctness: BFS đạt L tối thiểu, Dijkstra đạt C tối thiểu trên scenario tính tay.
6. Simulation replay + goal validation: path hợp lệ → `goal_reached=true`; path sai → fail đúng.
7. Benchmark chạy 4 scenario (small/medium/large/unreachable), xuất CSV/JSON **tái lập với seed**.
8. Kết quả phân biệt rõ `path_found` (Search) vs `path_valid` (Validation) vs `goal_reached` (Simulation); no-path cho `path_valid=null` (§12.3), path no-op cho `path_valid=false` (§7.2/§8).
9. Xử lý đúng hai trường hợp biên: `initial_state` đã đạt goal (path rỗng, metric §3.4/§10) và goal không đạt được (no-path schema §12.3).
10. Báo cáo `|V|,|E|` theo bước đo tham chiếu §12.5, **tách** khỏi `nodes_expanded/edges_examined` và ngoài `runtime_ms`.

---

## 14. Roadmap 4–6 tháng (một sinh viên)

> Ưu tiên **đạt MVP end-to-end sớm**, không hoãn tích hợp tới khi mọi module hoàn thiện riêng lẻ.

| GĐ | ~Thời lượng | Nội dung | Deliverable | Acceptance |
|---|---|---|---|---|
| **0** | 2 tuần | Chốt RQ + schema tối thiểu | Tài liệu này được duyệt (§17) | §17 phê duyệt |
| **1** | 3 tuần | `state.py`: State, `state_key`, `applicable`, `apply`, `successors` | lõi transition | test §13.1 (identity, immutability) pass |
| **2 ⭐** | 2 tuần | **MVP end-to-end "mỏng":** 1 scenario small + BFS + simulate + validate + in metric qua CLI | **đường đi xuyên suốt chạy được** | chạy `cli.py` ra path + goal_reached cho small |
| **3** | 3 tuần | Thêm DFS/Dijkstra/Greedy + correctness test | 4 thuật toán | BFS→L min, Dijkstra→C min pass |
| **4** | 2 tuần | Hoàn thiện `simulate.py` + goal validation + (evidence nếu chọn) | simulation đầy đủ | test replay/goal pass |
| **5** | 3 tuần | `benchmark.py` + 4 scenario + export CSV/JSON | số liệu RQ | benchmark tái lập với seed |
| **6** | 3 tuần | Thực nghiệm + phân tích RQ1–4 + viết luận | kết quả + phân tích | trả lời được 4 RQ |
| **7** | 1–2 tuần | Demo + docs + bảo vệ | demo end-to-end | chạy đủ workflow §11.1 |
| **8** | nếu còn | **[TÙY CHỌN]** A\*, composite cost, hoặc UI đọc CSV | mở rộng | không ảnh hưởng GĐ1–6 |

⭐ **Mốc MVP end-to-end (GĐ2)** là mốc tích hợp sớm — ưu tiên đạt trước khi mở rộng số thuật toán.

**Ngoài critical path [HOÃN/TÙY CHỌN]:** API, UI, database, A\*, composite cost, replanning, tích hợp công cụ thật.

---

## 15. Rủi ro & giảm thiểu

| Rủi ro | Giảm thiểu |
|---|---|
| Đồ thị quá nhỏ → benchmark vô nghĩa | Scenario large có dead-end/cycle/nhiều đường; báo cáo `|V|,|E|` thực đo |
| Mô hình chi phí tùy ý → thiên lệch | Chi phí dẫn xuất từ CVSS v3.1 (§9.3) thay cho chi phí gõ tay; giả định công bố + phân tích độ nhạy; composite = [HOÃN] |
| Đánh đổi L≠C do thiết kế chứ không do dữ liệu (hội đồng phản biện "tính chất được dựng sẵn") | Với chi phí CVSS, không áp đặt bất biến chi phí; báo cáo trung thực khi đánh đổi biến mất; `cvss_override` phải kèm giải thích theo định nghĩa CVSS |
| Thuật toán tối ưu mục tiêu khác nhau → so sánh khập khiễng | So sánh đúng tiêu chí từng RQ; nêu rõ BFS=L, Dijkstra=C |
| State thiếu → path sai | Canonical `state_key` + correctness test tính tay |
| "Mô phỏng thành công" bị hiểu là khai thác thật | Ghi rõ ranh giới học thuật §3.4 trong luận văn |
| Nhầm C với T | Tách 5 đại lượng §4.1, báo cáo cột riêng |
| Quá nhiều module → mất thời gian cho thuật toán | Simplicity First §2; MVP = 6 module/CLI; mốc E2E sớm GĐ2 |
| Tie-break không tất định → benchmark dao động | Tie-break cố định cho mọi thuật toán §10 |
| A\* heuristic không admissible | Chỉ đưa A\* vào kết luận tối ưu nếu chứng minh admissible; nếu không → thảo luận |
| Overengineering (class/pattern thừa) | §2.10: mỗi abstraction phải phục vụ RQ/correctness/workflow, nếu không → bỏ |

---

## 16. Bảng quyết định: Chốt / Tùy chọn / Hoãn

| Hạng mục | Trạng thái |
|---|---|
| State = `{access, known}`, topology/env_fact tĩnh | **[CHỐT]** |
| Canonical `state_key` = sorted(access)+sorted(known) | **[CHỐT]** |
| Một scenario JSON + vài hàm validate | **[CHỐT]** |
| Chi phí dẫn xuất từ CVSS v3.1: cost = round(10·(−ln(E/10))), E = Exploitability (§9.3) | **[CHỐT]** (từ 2026-10-22) |
| Config cost (số nguyên gõ tay/ngẫu nhiên theo seed) | **[GIỮ]** chỉ làm bộ hồi quy và đối chiếu; không dùng cho kết luận chính |
| BFS/DFS/Dijkstra/Greedy là bộ so sánh | **[CHỐT]** |
| Lõi CLI, output CSV/JSON | **[CHỐT]** |
| `applicable`/`apply`/`successors` thuần, dùng chung | **[CHỐT]** |
| No-op bị loại ở `successors` **và** làm path invalid ở Validation | **[CHỐT]** |
| `access` mapping đầy đủ mọi host; validator từ chối thiếu/thừa/sai level | **[CHỐT]** |
| Đo \|V\|,\|E\| bằng bước duyệt tham chiếu riêng, ngoài `runtime_ms` | **[CHỐT]** |
| DFS push reversed theo thứ tự action JSON; Dijkstra/Greedy dùng `counter` | **[CHỐT]** |
| Initial-goal → path rỗng; no-path → `path_valid=null` | **[CHỐT]** |
| Reachability phụ thuộc state | **[HOÃN]** |
| Evidence validation | **[TÙY CHỌN]** |
| A\* | **[TÙY CHỌN]** (cần heuristic admissible) |
| Composite/normalized cost | **[HOÃN]** (cần sensitivity analysis) |
| Replanning, stochastic failure, tích hợp công cụ thật | **[HOÃN]** |
| API / Frontend / Dashboard / Database | **[HOÃN]** |

---

## 17. Quyết định cần người dùng phê duyệt

1. **Mô hình chi phí:** ~~xác nhận **config cost** là chính, composite là [HOÃN]~~ → **đã đổi (2026-10-22): chi phí dẫn xuất từ CVSS v3.1 (§9.3) là chính; config cost chỉ giữ làm hồi quy; composite vẫn [HOÃN].** Lý do: chi phí gõ tay khó bảo vệ trước hội đồng.
2. **Bộ thuật toán:** giữ đúng BFS/DFS/Dijkstra/Greedy; A\* là [TÙY CHỌN] có điều kiện admissible? *(khuyến nghị: Có)*
3. **State model:** đồng ý State = `{access, known}` + topology/env_fact tĩnh, bỏ reachability-động khỏi MVP? *(khuyến nghị: Có)*
4. **Schema một-file + validate bằng hàm đơn giản** (không framework)? *(khuyến nghị: Có)*
5. **Evidence validation:** bật trong MVP hay để [TÙY CHỌN]? *(khuyến nghị: để [TÙY CHỌN])*
6. **Mốc MVP end-to-end sớm (GĐ2)** với BFS trước, các thuật toán khác thêm sau — đồng ý? *(khuyến nghị: Có)*

---

### Điều kiện hoàn thành (self-check)
- ✅ RQ đo lường được, phân biệt L/C/E_n·E_e/T/G (§4).
- ✅ Kiến trúc nhất quán mock-data → benchmark, tối giản (§11).
- ✅ Tách Search/Simulation/Validation, **dùng chung một transition**; quy tắc no-op **nhất quán** hai phía (§7–8).
- ✅ So sánh công bằng, tie-break tất định; thứ tự DFS tất định (§10, §12).
- ✅ `|V|,|E|` (kích thước scenario) **tách** khỏi `E_n,E_e` (công sức một lần chạy) (§12.3, §12.5).
- ✅ Trường hợp biên initial-goal & no-path có kết quả xác định (§3.4, §10, §12.3).
- ✅ `access` mapping đầy đủ ⇒ `state_key` không mơ hồ (§5.2–5.3).
- ✅ Ví dụ JSON khớp schema & quy ước precondition (§6).
- ✅ Phù hợp 1 sinh viên 4–6 tháng, có mốc E2E sớm (§14).
- ✅ Không exploit/VM/AI-ML thật (§3.2). ✅ Không thêm chức năng thừa (§2); giữ 4 thuật toán, A\* vẫn [TÙY CHỌN].

**Trạng thái:** Implementation đã đi theo các khuyến nghị ở §17 (config cost, 4 thuật toán, State = `{access, known}`, schema một file, evidence = [TÙY CHỌN], mốc E2E sớm). Tiến độ chi tiết: xem bảng ở đầu tài liệu.
