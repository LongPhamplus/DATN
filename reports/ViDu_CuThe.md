# Ví dụ cụ thể có số liệu (việc 7.3)

*Lấy từ thí nghiệm chính nhóm V (`out/policies/V`, snapshot `2026-10-28:7453da5422a4`), chấm bằng M-EPSS. Mỗi ví dụ tái lập được bằng lệnh `python -m aapef.attck scenarios/V/<file> --model epss --snapshot data/snapshots [--patch ...]` sau khi sinh kịch bản bằng `scripts/run_group_v.sh`. Mô phỏng: xác suất là của mô hình, không phải dự báo về một mạng thật.*

## Ví dụ 1: lỗ hổng điểm thấp nhưng là cửa vào duy nhất (`small-m1-s8`)

Đường tấn công tốt nhất (ATT&CK):

| Bước | Kỹ thuật | Hành động | CVE | p (EPSS) |
|---|---|---|---|---|
| 1 | T1190 Exploit Public-Facing Application | http từ Internet vào H1_0 (DMZ) | CVE-2023-51962 | 0,007 |
| 2 | T1046 Network Service Discovery | quét vùng 2 từ H1_0 | – | 0,9 |
| 3 | T1210 Exploitation of Remote Services | ssh từ H1_0 sang H2_0 | CVE-2024-21653 | 0,005 |
| 4 | T1068 Exploitation for Privilege Escalation | leo thang trên H2_0 | CVE-2024-38628 | 0,002 |

Rủi ro ban đầu P\* = 5,6·10⁻⁸.

- **Chính sách EPSS** vá trước CVE-2026-55040 trên H3_1 (EPSS 0,695, thuộc KEV) và CVE-2025-58360 trên H3_3 (EPSS 0,612, thuộc KEV): đều là lỗ hổng "đáng sợ" theo điểm, nhưng **không nằm trên đường tốt nhất**. Sau 2 lần vá, P\* vẫn 5,6·10⁻⁸; sau 6 lần vẫn không giảm (AUC = 1,00).
- **Chính sách theo ngữ cảnh** vá ngay CVE-2023-51962 trên H1_0, dù EPSS chỉ 0,007 và không thuộc KEV: đây là **cửa vào duy nhất** từ Internet. Sau 1 lần vá: **không còn đường tấn công** (AUC = 0,08).
- CVSS-Base (9,8 cho CVE-2023-51962) vá nó ở lần thứ hai: AUC = 0,25.

**Ý nghĩa:** điểm của lỗ hổng không nói lên vị trí của nó; một lỗ hổng EPSS thấp ở điểm nghẽn quan trọng hơn hai lỗ hổng KEV ở chỗ không dẫn tới đâu.

## Ví dụ 2: vá CVE nổi tiếng nhưng sai chỗ (`medium-multi-site-m1-s8`)

Đường tốt nhất: T1190 http vào H5_1 (CVE-2024-0188, EPSS 0,007) → T1046 quét → T1210 smtp sang máy nhạy cảm H2_1 (CVE-2024-29725) → T1068 leo thang (CVE-2024-24105). P\* = 9,9·10⁻⁸.

- **EPSS và CVSS-Base** cùng vá trước CVE-2024-3094 trên H3_1: đây là backdoor trong xz-utils (base 10,0, EPSS 0,909). Sau khi vá, **P\* không đổi** (9,9·10⁻⁸): H3_1 không nằm trên đường tốt nhất. Cả hai chính sách có AUC = 1,00.
- **Theo ngữ cảnh** vá CVE-2024-0188 trên H5_1 (EPSS 0,007, base 8,1): **mục tiêu không còn tới được** sau 1 lần vá (AUC = 0,08).

**Ý nghĩa:** "vá CVE nổi tiếng nhất trước" là hợp lý khi không biết gì về mạng, nhưng trong mạng này nó không làm giảm rủi ro tới tài sản quan trọng.

## Ví dụ 3 (ngược chiều): biết đường mà sai xác suất

Không phải lúc nào xét ngữ cảnh cũng thắng. Ở m = 5 (5 CVE mỗi chỗ lỗ hổng), chính sách theo ngữ cảnh dùng xác suất CVSS, khi chấm bằng M-EPSS, **thua** chính sách EPSS đơn giản: EPSS tốt hơn ở 28/40 mạng, p = 0,002, AUC trung bình 0,66 so với 0,49 (`reports/KetQua_NhomV.md` §2). Lý do: dưới CVSS, phần lớn CVE truy cập ban đầu có cùng xác suất (0,39), nên chính sách này không phân biệt được CVE nào kẻ tấn công sẽ dùng thật; EPSS thì có.

**Ý nghĩa:** giá trị của ngữ cảnh phụ thuộc vào việc ước lượng đúng khả năng khai thác. Kết hợp cả hai (đường tấn công + EPSS) cho kết quả tốt nhất: AUC 0,12 ở m = 5.

## Lưu ý khi trình bày
- P\* rất nhỏ (cỡ 10⁻⁷) vì EPSS của đa số CVE năm 2024 thấp; nên so **tỉ lệ** R(k)/R(0) thay vì giá trị tuyệt đối.
- Ví dụ 1 và 2 được chọn vì chênh lệch lớn nhất (chọn có chủ đích để minh họa); con số đại diện là trung bình ở `KetQua_NhomV.md`.
