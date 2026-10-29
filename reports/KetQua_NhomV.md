# Kết quả nhóm V (thí nghiệm chính, 2026-10-28)

*Dữ liệu: snapshot `2026-10-28:7453da5422a4`; kịch bản theo `reports/QuyTac_GanCVE.md` (commit `0b33924`, công bố trước khi chạy); 4 cấu trúc NASim × m ∈ {1, 2, 3, 5} × 10 seed = 160 mạng; K = 6; Random 200 seed; rủi ro = chiếm ít nhất một máy nhạy cảm. Chạy bằng `scripts/run_group_v.sh` (khoảng 4,5 giờ CPU). Số liệu: `out/policies/V/` (`stats-m<m>/policies.csv`, `pairs.csv`; `summary.csv.gz` từng nhóm).*

## 1. AUC trung bình (40 mạng mỗi m; càng nhỏ càng tốt; 1,0 = 6 lần vá không giảm rủi ro)

"Ngữ cảnh (X)" = Context-greedy chọn vá bằng mô hình X. Optimal chỉ chạy được ở m = 1 trên 2 cấu trúc small (20 mạng).

**Chấm bằng M-EPSS**

| m | Ngữ cảnh (cvss) | Ngữ cảnh (epss) | Ngữ cảnh (kev) | CVSS-Base | CVSS-Exploit | EPSS | KEV-trước | Random | Optimal |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 0,119 | 0,096 | 0,107 | 0,446 | 0,458 | 0,400 | 0,416 | 0,581 | 0,095 |
| 2 | 0,274 | 0,122 | 0,133 | 0,681 | 0,671 | 0,465 | 0,467 | 0,839 | – |
| 3 | 0,528 | 0,135 | 0,152 | 0,637 | 0,616 | 0,536 | 0,548 | 0,897 | – |
| 5 | 0,655 | 0,116 | 0,144 | 0,682 | 0,627 | 0,493 | 0,485 | 0,917 | – |

**Chấm bằng M-KEV** (`p_kev` = 0,9)

| m | Ngữ cảnh (cvss) | Ngữ cảnh (epss) | Ngữ cảnh (kev) | CVSS-Base | CVSS-Exploit | EPSS | KEV-trước | Random | Optimal |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 0,128 | 0,106 | 0,097 | 0,485 | 0,482 | 0,414 | 0,424 | 0,580 | 0,093 |
| 2 | 0,283 | 0,131 | 0,125 | 0,681 | 0,685 | 0,485 | 0,475 | 0,839 | – |
| 3 | 0,550 | 0,148 | 0,122 | 0,634 | 0,599 | 0,559 | 0,555 | 0,894 | – |
| 5 | 0,663 | 0,134 | 0,131 | 0,719 | 0,672 | 0,543 | 0,535 | 0,923 | – |

**Chấm bằng M-CVSS**

| m | Ngữ cảnh (cvss) | Ngữ cảnh (epss) | Ngữ cảnh (kev) | CVSS-Base | CVSS-Exploit | EPSS | KEV-trước | Random | Optimal |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 0,133 | 0,146 | 0,149 | 0,575 | 0,591 | 0,559 | 0,561 | 0,633 | 0,122 |
| 2 | 0,348 | 0,440 | 0,469 | 0,947 | 0,940 | 0,946 | 0,954 | 0,958 | – |
| 3 | 0,618 | 0,783 | 0,791 | 0,994 | 0,996 | 1,000 | 1,000 | 0,994 | – |
| 5 | 0,841 | 0,974 | 0,958 | 1,000 | 1,000 | 1,000 | 1,000 | 0,998 | – |

## 2. So sánh cặp (Wilcoxon có dấu, 40 mạng; r = rank-biserial, âm = chính sách đứng trước tốt hơn)

| So sánh | Mô hình chấm | m = 1 | m = 2 | m = 3 | m = 5 |
|---|---|---|---|---|---|
| Ngữ cảnh (epss) vs EPSS | epss | thắng 34–0, p = 4e-7, r = −1,00 | 39–1, p = 4e-8 | 38–2, p = 5e-8 | 40–0, p = 4e-8 |
| Ngữ cảnh (kev) vs KEV-trước | kev | 35–0, p = 2e-7 | 39–1, p = 4e-8 | 38–2, p = 5e-8 | 39–1, p = 4e-8 |
| Ngữ cảnh (cvss) vs CVSS-Exploit | cvss | 36–0, p = 2e-7 | 40–0, p = 4e-8 | 34–0, p = 4e-7 | 30–0, p = 2e-6 |
| EPSS vs CVSS-Base | epss | 22–11, p = 0,11 | 28–9, p = 1e-4, r = −0,74 | 25–8, p = 0,03 | 29–8, p = 7e-4, r = −0,64 |
| KEV-trước vs EPSS | kev | 2–5 (hòa 33), p = 0,22 | 7–11 (hòa 22), p = 0,90 | 11–7 (hòa 22), p = 0,52 | 7–8 (hòa 25), p = 0,72 |
| **Ngữ cảnh (cvss) vs EPSS** | **epss** | 31–3, p = 5e-6 | 28–12, p = 0,005 | 19–20, p = 0,85 | **12–28, p = 0,002, r = +0,55** |

## 3. Kết luận sơ bộ (theo giả thuyết đã công bố)

1. **H1 (ngữ cảnh không kém, và vượt khi có điểm nghẽn):** ủng hộ mạnh. Khi chính sách theo ngữ cảnh dùng cùng nguồn dữ liệu với chính sách điểm tương ứng, nó thắng ở 30–40/40 mạng, mọi m, mọi mô hình chấm (p ≤ 2e-6; vẫn có ý nghĩa sau hiệu chỉnh Holm cho khoảng 24 phép thử mỗi m). Ở m = 1, nó gần mức tối ưu (0,096–0,133 so với 0,093–0,122).
2. **Thứ tự các chính sách điểm:** EPSS ≈ KEV-trước, tốt hơn CVSS-Base ≈ CVSS-Exploit, tốt hơn Random (dưới M-EPSS và M-KEV). KEV-trước và EPSS hòa ở đa số mạng: CVE thuộc KEV thường có EPSS cao nên thứ tự gần như trùng.
3. **H3 (thứ hạng bền khi đổi mô hình):** **không hoàn toàn.** Lợi thế của ngữ cảnh phụ thuộc vào việc dùng đúng mô hình xác suất. Ngữ cảnh (cvss), khi chấm bằng M-EPSS, thua chính sách EPSS đơn giản ở m = 5 (12–28 mạng, p = 0,002). Nghĩa là: biết đường tấn công mà đoán sai xác suất thì có thể tệ hơn chỉ xếp theo EPSS. Đây là kết quả cần báo cáo.
4. **Dưới M-CVSS, các chính sách điểm gần như vô dụng khi m ≥ 2** (AUC 0,94–1,00 ≈ Random). Nguyên nhân: phần lớn CVE truy cập ban đầu có cùng Exploitability (AV:N/AC:L/PR:N/UI:N, p = 0,39), vá một CVE thì còn CVE ngang ngửa ở cùng chỗ; với m = 5, K = 6 không đủ để đóng một chỗ lỗ hổng.

## 4. Hạn chế của phân tích này

- **40 mạng mỗi m không độc lập hoàn toàn:** 10 seed dùng chung 4 cấu trúc. Nên báo cáo thêm theo từng cấu trúc (10 mạng mỗi ô) trước khi viết luận.
- **Nhiều phép kiểm định:** đọc p-value cùng hiệu chỉnh Holm; các kết luận 1 và 3 vẫn đứng sau hiệu chỉnh, kết luận "EPSS tốt hơn CVSS-Base" ở m = 1 và m = 3 thì không.
- **Lợi thế "tự chấm":** Ngữ cảnh (X) được chấm bằng chính X trên đường chéo; vì vậy các so sánh chéo (ví dụ dòng in đậm ở §2) quan trọng hơn đường chéo.
- K = 6 nhỏ so với 70–135 đơn vị vá ở m = 5; K = 15 cho cùng kết luận (§5).
- Độ nhạy: xem §5. Còn chưa chạy: snapshot thứ hai.

## 5. Phân tích độ nhạy (công bố trước, `QuyTac_GanCVE.md` §6, `MasterPlan.md` §8.4)

*Mỗi biến thể đổi đúng một điểm so với lượt chạy chính; 40 mạng mỗi m; Random 50 seed (thay vì 200, để rút thời gian; chỉ ảnh hưởng mốc ngẫu nhiên). Chạy bằng `scripts/run_group_v.sh --sensitivity`. Thống kê: `out/policies/V_<biến thể>/stats-m<m>/`.*

| Biến thể | Đổi gì |
|---|---|
| V_K15 | ngân sách K = 15 (thay 6) |
| V_kev50 | rút CVE theo tầng: 50% từ KEV (thay tỉ lệ tự nhiên 7–11%) |
| V_shared | cùng exploit NASim nhận cùng bộ CVE trên mọi máy (đội máy đồng nhất) |
| V_pkev050, V_pkev099 | `p_kev` = 0,5 và 0,99 (thay 0,9); chỉ ảnh hưởng mô hình M-KEV |

**Thắng–thua trên 40 mạng (p, Wilcoxon), các so sánh chính**

*Ngữ cảnh (EPSS) vs EPSS, chấm bằng M-EPSS*

| Biến thể | m = 1 | m = 2 | m = 3 | m = 5 |
|---|---|---|---|---|
| chính (V) | 34–0, p = 4e-7 | 39–1, p = 4e-8 | 38–2, p = 5e-8 | 40–0, p = 4e-8 |
| K = 15 | 34–0, p = 4e-7 | 39–1, p = 4e-8 | 39–1, p = 4e-8 | 40–0, p = 4e-8 |
| 50% KEV | 34–0, p = 4e-7 | 40–0, p = 4e-8 | 40–0, p = 4e-8 | 40–0, p = 4e-8 |
| đội máy đồng nhất | 33–0, p = 5e-7 | 39–1, p = 5e-8 | 39–1, p = 5e-8 | 39–1, p = 4e-8 |

*Ngữ cảnh (KEV) vs KEV-trước, chấm bằng M-KEV:* thắng 32–40 mạng, p ≤ 8e-7 ở mọi biến thể và mọi m, kể cả `p_kev` = 0,5 và 0,99 (kết quả gần như trùng lượt chạy chính).

*Ngữ cảnh (CVSS) vs CVSS-Exploit, chấm bằng M-CVSS:* thắng 27–40 mạng, không thua mạng nào, p ≤ 6e-6 ở mọi biến thể.

*EPSS vs CVSS-Base, chấm bằng M-EPSS*

| Biến thể | m = 1 | m = 2 | m = 3 | m = 5 |
|---|---|---|---|---|
| chính | 22–11, p = 0,1 | 28–9, p = 1e-4 | 25–8, p = 0,03 | 29–8, p = 7e-4 |
| K = 15 | 23–12, p = 0,1 | 31–9, p = 4e-5 | 32–7, p = 2e-4 | 31–8, p = 1e-5 |
| **50% KEV** | **11–20, p = 0,2** | 27–10, p = 0,006 | 23–13, p = 0,1 | **23–15, p = 0,6** |
| đội máy đồng nhất | 15–8, p = 0,008 | 26–11, p = 6e-4 | 30–3, p = 3e-5 | 28–7, p = 3e-4 |

*KEV-trước vs EPSS:* không khác biệt có ý nghĩa ở mọi biến thể (p ≥ 0,2; đa số mạng hòa).

*Ngữ cảnh (CVSS) vs EPSS, chấm bằng M-EPSS (đánh giá chéo)*

| Biến thể | m = 1 | m = 2 | m = 3 | m = 5 |
|---|---|---|---|---|
| chính | 31–3 | 28–12 | 19–20 | **12–28, p = 0,002** |
| K = 15 | 31–3 | 28–12 | 21–19 | **12–28, p = 0,006** |
| 50% KEV | 30–4 | 29–11 | 27–13 | 21–17, p = 0,03 |
| đội máy đồng nhất | 28–2 | 24–16 | 14–26, p = 0,1 | 16–23, p = 0,1 |

### Kết luận độ nhạy
1. **Kết luận chính bền:** chính sách theo ngữ cảnh thắng chính sách điểm cùng nguồn ở mọi biến thể, mọi m, mọi mô hình chấm (p ≤ 6e-6), không phụ thuộc K, tỉ lệ KEV, đội máy đồng nhất hay `p_kev`.
2. **`p_kev` không quan trọng:** đổi 0,5 ↔ 0,99 gần như không đổi thứ hạng.
3. **Ưu thế của EPSS so với CVSS-Base phụ thuộc vào tỉ lệ KEV:** giữ ở lượt chính, K = 15 và đội máy đồng nhất, nhưng **mất** khi 50% CVE thuộc KEV (m = 1: CVSS-Base còn tốt hơn ở 20/40 mạng; m = 5: p = 0,6). Khi lỗ hổng "nguy hiểm theo EPSS/KEV" có mặt khắp nơi, chính điểm số không còn phân biệt được nên vá cái nào; chính sách theo ngữ cảnh thì không bị ảnh hưởng.
4. **Nguy cơ của ngữ cảnh dùng sai mô hình** (Ngữ cảnh (CVSS) thua EPSS ở m lớn) lặp lại ở K = 15; yếu đi khi 50% KEV hoặc đội máy đồng nhất (không còn ý nghĩa thống kê). Đây là kết quả có điều kiện, báo cáo như vậy.
5. **Lỗi phát hiện khi chạy độ nhạy và đã sửa:** `policies.optimal` hỏng khi K lớn hơn số đơn vị vá (K = 15, mạng 12–14 đơn vị); đã sửa và thêm test, chạy lại 2 nhóm bị ảnh hưởng. Lượt chạy chính (K = 6) không bị ảnh hưởng.

## 6. Cấu trúc bổ sung: NASim `medium` (thêm sau lượt chạy chính, 2026-10-29)

*Mục đích: kiểm tra kết luận chính trên một cấu trúc ngoài 4 cấu trúc ban đầu. `medium` được thêm **sau** khi đã có kết quả lượt chạy chính, nên trình bày tách riêng, không gộp vào 160 mạng. Quy tắc gán CVE, snapshot và thiết lập giữ nguyên (K = 6, ba mô hình, Random 200 seed). Chuyển bằng `nasim2aapef.py` (không sửa), gán CVE bằng `scripts/assign_cves.py`; 4 mức m × 10 seed = 40 mạng ở `scenarios/V_medium`. Chạy lại: `scripts/run_group_v.sh --extra-structure`. Số liệu: `out/policies/V_medium/` (`stats-m<m>/`).*

**Vì sao chỉ thêm `medium`.** Trong 5 kịch bản NASim chưa dùng: `small-honeypot` giống hệt `small` trừ một máy có thêm http và giá trị âm (honeypot), mà AAPEF không mô hình giá trị máy, nên chỉ là bản lặp của `small`; `tiny`, `tiny-hard`, `tiny-small` có 2 subnet, quá nhỏ (suy biến như nhóm N). `medium` (16 máy, 5 subnet, hai tầng sau DMZ, 25 chỗ lỗ hổng, R(0) = 0,54 theo `prob` gốc) sâu hơn các cấu trúc cũ nhưng vẫn chỉ có **một** đường vào (1 đường rời nhau). Không có kịch bản NASim nào có nhiều cửa vào.

**AUC trung bình (10 mạng mỗi m), chấm bằng M-EPSS**

| m | Ngữ cảnh (cvss) | Ngữ cảnh (epss) | Ngữ cảnh (kev) | CVSS-Base | CVSS-Exploit | EPSS | KEV-trước | Random |
|---|---|---|---|---|---|---|---|---|
| 1 | 0,083 | 0,083 | 0,083 | 0,675 | 0,708 | 0,717 | 0,733 | 0,684 |
| 2 | 0,217 | 0,093 | 0,093 | 0,641 | 0,519 | 0,396 | 0,409 | 0,858 |
| 3 | 0,453 | 0,132 | 0,145 | 0,844 | 0,821 | 0,626 | 0,672 | 0,918 |
| 5 | 0,718 | 0,090 | 0,107 | 0,841 | 0,724 | 0,678 | 0,678 | 0,938 |

**Thắng–thua trên 10 mạng (Wilcoxon; với 10 mạng p nhỏ nhất có thể là 0,002)**

| So sánh | Mô hình chấm | m = 1 | m = 2 | m = 3 | m = 5 |
|---|---|---|---|---|---|
| Ngữ cảnh (epss) vs EPSS | epss | 8–0 (hòa 2), p = 0,008 | 10–0, p = 0,002 | 10–0, p = 0,002 | 10–0, p = 0,002 |
| Ngữ cảnh (kev) vs KEV-trước | kev | 8–0, p = 0,008 | 10–0, p = 0,002 | 10–0, p = 0,002 | 10–0, p = 0,002 |
| Ngữ cảnh (cvss) vs CVSS-Exploit | cvss | 8–0, p = 0,008 | 10–0, p = 0,002 | 10–0, p = 0,002 | 9–0, p = 0,004 |
| EPSS vs CVSS-Base | epss | 3–3, p = 0,88 | 8–0, p = 0,008 | 5–3, p = 0,25 | 4–2, p = 0,31 |
| Ngữ cảnh (cvss) vs EPSS | epss | 8–0, p = 0,008 | 7–3, p = 0,11 | 6–4, p = 0,13 | 5–4, p = 0,73 |
| KEV-trước vs EPSS | kev | 0–1 (hòa 9) | 1–4 (hòa 5) | 1–2 (hòa 7) | hòa 10/10 |

### Kết luận
1. **Kết luận chính lặp lại trên `medium`:** chính sách theo ngữ cảnh thắng chính sách điểm cùng nguồn ở 8–10/10 mạng, mọi m, cả ba mô hình chấm, không thua mạng nào.
2. **Ở m = 1, chính sách điểm không tốt hơn Random** (AUC 0,68–0,73 so với 0,68), trong khi ngữ cảnh chặn hết sau 1 lần vá (0,083). Lý do: mạng chỉ có một đường vào, mỗi chỗ lỗ hổng một CVE, nên vá đúng một CVE trên đường là chặn được; vá chỗ khác thì rủi ro không đổi. Vì vậy ở m = 1, AUC giống hệt nhau dưới cả ba mô hình (R(k) chỉ nhận 1 hoặc 0). Đây là trường hợp cực đoan nhất của "điểm cao nhưng sai chỗ".
3. **Nguy cơ của ngữ cảnh dùng sai mô hình không lặp lại trên `medium`:** Ngữ cảnh (cvss) không thua EPSS ở mạng nào có ý nghĩa (m = 5: 5–4, p = 0,73), khác lượt chính (12–28 ở m = 5). Thêm bằng chứng rằng kết quả này phụ thuộc cấu trúc và chỉ nên báo cáo là có điều kiện.
4. **EPSS vs CVSS-Base:** chỉ khác biệt có ý nghĩa ở m = 2; nhất quán với lượt chính là ưu thế của EPSS so với CVSS-Base yếu và có điều kiện.
5. **Giới hạn:** chỉ 10 mạng mỗi m (một cấu trúc), nên p bị chặn dưới ở 0,002; `medium` vẫn chỉ có một đường vào, nên câu hỏi "mạng có nhiều cửa vào" vẫn chưa được kiểm tra.
