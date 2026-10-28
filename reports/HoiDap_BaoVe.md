# Hỏi đáp dự kiến khi bảo vệ (bản nháp 2026-10-28)

*Mỗi câu trả lời dẫn tới tài liệu hoặc số liệu trong repo. Cập nhật khi có kết quả độ nhạy và snapshot thứ hai.*

## A. Đề tài và đóng góp

**1. Đồ án giải quyết vấn đề gì?**
Tổ chức không vá hết được lỗ hổng nên phải ưu tiên. CVSS, EPSS, KEV chấm từng lỗ hổng riêng lẻ, không biết lỗ hổng nằm ở đâu trên đường tới tài sản quan trọng. Đồ án đo, bằng mô phỏng attack graph, việc xét đường tấn công giúp giảm rủi ro được bao nhiêu so với chỉ xếp theo điểm, và khi nào thì không.

**2. Đóng góp mới là gì? Đã có ai làm chưa?**
Có công trình gần (VulRG 2025: đồ thị mạng + CVSS/EPSS; SmartPatch, PatchRank; Pinto 2026 so CVSS/EPSS với KEV nhưng không xét mạng). Đồ án không tuyên bố "chưa ai làm". Đóng góp: một khung đánh giá **định lượng, tái lập được** (dữ liệu snapshot có hash, quy tắc gán CVE công bố trước, mã và lệnh tái lập), so sánh chính sách điểm và theo ngữ cảnh trên mạng công khai (NASim), có đối chiếu với tối ưu, đánh giá chéo ba mô hình xác suất và phân tích độ nhạy. (`KhaoSat_TaiLieu.md`)

**3. Kiến thức ATTT nằm ở đâu?**
Quản lý lỗ hổng theo rủi ro (CVSS/EPSS/KEV và giới hạn của từng loại); đọc vector CVSS v3.1 (suy vai trò, bộ lọc C:H/I:H); chuỗi tấn công theo MITRE ATT&CK (T1190, T1046, T1210, T1068); kiến trúc mạng phòng thủ (DMZ, firewall, điểm nghẽn); network hardening. Chi tiết: bảng ở `MasterPlan.md` §2.

## B. Phương pháp

**4. Rủi ro được đo thế nào?**
P\* = xác suất thành công của đường tấn công tốt nhất tới ít nhất một máy nhạy cảm; xác suất đường = tích xác suất các bước (giả định độc lập). Tìm bằng A\* với chi phí −ln p (tổng nhỏ nhất ⇔ tích lớn nhất). R(k) = P\* sau k lần vá; AUC = diện tích dưới R(k)/R(0).

**5. Vì sao dùng −ln p?**
−ln biến tích thành tổng; xác suất trong (0, 1] cho chi phí không âm, nên dùng được Dijkstra/A\* và đường chi phí nhỏ nhất chính là đường có xác suất thành công cao nhất.

**6. Ba mô hình xác suất khác nhau thế nào, vì sao cần cả ba?**
M-CVSS: độ dễ khai thác theo đặc tả (Exploitability/10). M-EPSS: xác suất bị khai thác thực tế. M-KEV: 0,9 nếu đã bị khai thác thật, ngược lại EPSS. Không ai biết xác suất thật, nên mỗi chính sách được chấm dưới cả ba (đánh giá chéo); nếu chỉ dùng một, chính sách cùng nguồn sẽ được lợi "tự chấm".

**7. Dữ liệu lấy từ đâu, có tái lập được không?**
NVD API 2.0, danh mục KEV (bản sao chính thức của CISA trên GitHub, CC0), EPSS (FIRST). Lưu snapshot `2026-10-28:7453da5422a4` kèm SHA-256; bộ nạp từ chối nếu file bị sửa. Mạng: 4 kịch bản NASim (MIT). `scripts/reproduce.sh` chạy lại toàn bộ.

**8. CVE được gán vào máy thế nào, có chọn tay không?**
Không. Quy tắc công bố trước (`QuyTac_GanCVE.md`, commit trước khi chạy): mỗi chỗ lỗ hổng NASim nhận m CVE rút ngẫu nhiên có seed từ nhóm đúng vai trò (khai thác qua mạng ← truy cập ban đầu; leo thang ← privesc AV:L). Vai trò suy từ vector bằng quy tắc có kiểm tra: khớp 72,5% trên mẫu kiểm tra độc lập.

**9. Ai phân loại mẫu để kiểm tra quy tắc vai trò?**
Một mô hình ngôn ngữ, gán **mù** (chỉ thấy mô tả NVD, không thấy vector hay quy tắc), theo hướng dẫn công bố. Đây là ngoại lệ có chủ đích với ràng buộc "không AI/ML": AI chỉ dùng để kiểm tra quy tắc, không nằm trong phương pháp. Bộ lọc được chốt trước khi gán mẫu thứ hai. Hạn chế: chưa có người xác nhận. (`ViecCanLam_GanNhanCVE.md`)

**10. Vì sao có hai nhóm N và V?**
NASim không có CVE. Nhóm N dùng mạng NASim gốc (xác suất của NASim hoặc CVSS suy từ cấu trúc); nhóm V gắn CVE thật để so được CVSS/EPSS/KEV. Nhóm N cho thấy mạng NASim có điểm nghẽn rất hẹp (1–2 lần vá là chặn hết), nên phép so sánh chính dựa vào nhóm V.

**11. "Suy biến" là gì, đã xử lý thế nào?**
Mạng NASim chỉ có một máy nối Internet với 1–2 lỗ hổng, nên mọi chính sách hoặc chặn ngay hoặc không giảm được gì; không so sánh tinh được. Đã thử mạng NASim lớn hơn và giả định "đã bị xâm nhập": vẫn suy biến. Giải pháp: nhiều CVE mỗi chỗ (m = 1, 2, 3, 5). (`ThietKe_ThiNghiem.md` §12–13)

## C. Kết quả

**12. Kết quả chính là gì?**
Chính sách theo ngữ cảnh thắng chính sách điểm cùng nguồn ở 30–40/40 mạng, mọi m, mọi mô hình chấm (p ≤ 2·10⁻⁶). Ví dụ m = 5, chấm bằng M-EPSS: AUC 0,12 so với 0,49 (EPSS), 0,68 (CVSS-Base), 0,92 (ngẫu nhiên). Ở m = 1 gần tối ưu (0,096 so với 0,095). (`KetQua_NhomV.md`)

**13. Trong các thang điểm, cái nào tốt nhất?**
EPSS ≈ KEV-trước, tốt hơn CVSS-Base ≈ CVSS-Exploit, tốt hơn ngẫu nhiên (dưới M-EPSS và M-KEV). KEV-trước và EPSS hòa ở đa số mạng vì CVE thuộc KEV thường có EPSS cao. Thứ tự này đổi theo cấu trúc mạng: ở `medium-multi-site`, m = 1, CVSS-Base tốt hơn EPSS.

**14. Có trường hợp nào xét ngữ cảnh thua không?**
Có. Xét đường nhưng dùng xác suất CVSS, khi chấm bằng EPSS ở m = 5, thua EPSS đơn giản (EPSS tốt hơn ở 28/40 mạng, p = 0,002). Ngữ cảnh chỉ có lợi khi ước lượng đúng khả năng khai thác; kết hợp đường tấn công + EPSS là tốt nhất.

**15. Cho một ví dụ cụ thể?**
Mạng `medium-multi-site-m1-s8`: EPSS và CVSS-Base vá trước CVE-2024-3094 (backdoor xz-utils, base 10, EPSS 0,91) nhưng máy đó không nằm trên đường tới tài sản nhạy cảm, rủi ro không đổi. Chính sách theo ngữ cảnh vá CVE-2024-0188 (EPSS 0,007) ở cửa vào: không còn đường tấn công. (`ViDu_CuThe.md`)

## D. Giới hạn

**16. Kết quả có áp dụng cho mạng thật không?**
Chỉ trong mô hình. Giả định: các bước độc lập, kẻ tấn công tối ưu và biết toàn bộ mạng, vá hoàn hảo và tức thời, chưa tính giá trị tài sản, CVE gắn theo vai trò chứ không theo đúng sản phẩm, mạng nhỏ (≤ 18 máy). Kết quả là bằng chứng có điều kiện, không phải khuyến nghị vận hành trực tiếp.

**17. Chính sách theo ngữ cảnh có khả thi ngoài thực tế không?**
Nó cần biết topology, lỗ hổng trên từng máy và mục tiêu; tổ chức có công cụ quét lỗ hổng và kiểm kê tài sản thì có các dữ liệu này. Chi phí tính toán: mỗi lần tính rủi ro 0,01–0,4 giây trên mạng 18 máy; mạng lớn hơn cần thêm nghiên cứu.

**18. Vì sao không dùng vét cạn cho mọi mạng?**
Bài toán chọn tập vá nhỏ nhất để chặn mọi đường là khó (được nêu trong tài liệu network hardening; *cần dẫn nguồn đã kiểm*). Vét cạn chỉ chạy được khi số đơn vị vá ≤ 14 (C(14,6) = 3.003 tổ hợp); mạng lớn hơn so với tham lam.

**19. Có lỗi nào đã phát hiện trong quá trình làm?**
Có, và được sửa minh bạch: NVD đôi khi ghi chính đánh giá của mình là "Secondary" khiến script lấy nhầm vector CNA (67 CVE, ví dụ Zerologon); đã sửa, tải snapshot mới, giữ snapshot cũ để truy vết.

*Còn bổ sung khi có:* kết quả độ nhạy (K = 15, 50% KEV, đội máy đồng nhất, `p_kev`), snapshot thứ hai.
