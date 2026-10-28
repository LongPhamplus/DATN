# Khảo sát tài liệu (bước đầu, việc 1.1)

*2026-10-27. Danh sách ứng viên từ một đợt tìm kiếm web, **chưa đọc toàn văn**. Mô tả dựa trên tóm tắt trong kết quả tìm kiếm; các con số của tác giả bài báo chưa được kiểm chứng. Tác giả cần đọc và xác nhận trước khi trích dẫn.*

| # | Nguồn | Chủ đề | Dùng để | Trạng thái |
|---|---|---|---|---|
| 1 | [VulRG: Multi-Level Explainable Vulnerability Patch Ranking for Complex Systems Using Graphs (arXiv 2502.11143)](https://arxiv.org/pdf/2502.11143) | xếp hạng vá lỗ hổng bằng đồ thị truyền thông mạng và đường tới tài sản quan trọng; phê phán chỉ dùng CVSS | **công trình gần nhất, phải đọc kỹ để định vị tính mới** | chưa đọc |
| 2 | [A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges (arXiv 2502.11070)](https://arxiv.org/pdf/2502.11070) | khảo sát ưu tiên lỗ hổng, có phần attack graph và mô hình dựa CVSS + ngữ cảnh | tổng quan, tìm thêm tài liệu | chưa đọc |
| 3 | [Evaluating Vulnerability Prioritization Strategies Based on CVSS and EPSS (SBSeg)](https://sol.sbc.org.br/index.php/sbseg/article/view/44316) | so CVSS và EPSS với KEV làm chuẩn trên 31.779 CVE năm 2024 | phương pháp so sánh chính sách theo độ phủ và nỗ lực | chưa đọc |
| 4 | [Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights (arXiv 2302.14172)](https://arxiv.org/pdf/2302.14172) | EPSS phiên bản 3, so với CVSS, KEV, Metasploit | định nghĩa EPSS, giới hạn | chưa đọc |
| 5 | [Exploit Prediction Scoring System (EPSS) (arXiv 1908.04856)](https://arxiv.org/pdf/1908.04856) | bài gốc về EPSS | nền tảng | chưa đọc |
| 6 | [Efficient Minimum-Cost Network Hardening via Exploit Dependency Graphs (ACSAC 2003)](https://acsac.org/2003/abstracts/98.html) | chọn tập biện pháp tối thiểu để chặn attack graph | cơ sở cho vá tập tối thiểu | chưa đọc |
| 7 | Wang, Noel, Jajodia, "Minimum-cost network hardening using attack graphs", Computer Communications 29(18), 2006 | bài toán hardening tối thiểu | trích dẫn khi nói về độ khó | **đã đọc toàn văn** (2026-10-28); không tự chứng minh NP-khó, trích [Sheyner 2002; Jha 2002] |
| 8 | [Topology-Aware Prioritized Patching for EV Charging Infrastructure (SciTePress 2025)](https://scitepress.org/publishedPapers/2025/132933/pdf/index.html) | vá theo đường tấn công nghiêm trọng nhất | công trình liên quan | chưa đọc |
| 9 | [RiskBridge (arXiv 2601.06201)](https://www.arxiv.org/pdf/2601.06201) | kết hợp CVSS v4, EPSS, KEV | công trình liên quan | chưa đọc |
| 10 | [NASim docs](https://networkattacksimulator.readthedocs.io/) | môi trường mạng mô phỏng, nguồn kịch bản | nguồn dữ liệu | đã đọc phần kịch bản (xem `DuLieuMang_CoSan.md`) |

## Đã đọc (2026-10-27, đọc bản HTML/trang tóm tắt; VulRG và khảo sát chỉ đọc khoảng 2/3 đầu do giới hạn công cụ)

**VulRG (mục 1).** Dựng đồ thị truyền thông mạng (từ cấu hình firewall, router, log) và đồ thị phụ thuộc hệ thống; dùng Dijkstra tìm đường ngắn nhất tới tài sản quan trọng; rủi ro = khả năng khai thác (trộn CVSS, EPSS, có exploit hay không, trọng số α, β, γ) × tác động × độ trung tâm, cộng rủi ro lan truyền. Không thấy dùng KEV. Đánh giá bằng 3 kịch bản nhỏ (5 lỗ hổng OpenPLC; 6 tài sản, 11 CVE) và một mạng minh họa 9 tài sản tự dựng; so sánh chủ yếu **định tính** (khớp với nhận xét của bài trước), không thấy chỉ số định lượng như R(k); trọng số do tác giả đặt, không thấy phân tích độ nhạy.

**Khảo sát 2502.11070 (mục 2).** 82 nghiên cứu, 5 nhóm chỉ số. Phương pháp đồ thị là nhánh lớn; CVSS vẫn là chuẩn chủ đạo; không thấy nhắc KEV. Khảo sát **không** mô tả việc đánh giá chính sách vá bằng mô phỏng rủi ro đường tấn công còn lại; gần nhất là SmartPatch (Yadav và cộng sự, 2022) với "residual impact score". Nhận xét mô phỏng có ở 13 nghiên cứu nhưng "dựa vào dữ liệu tổng hợp có thể hạn chế tính tổng quát".

**Pinto, SBSeg 2026 (mục 3).** So CVSS, EPSS và kết hợp OR/AND trên 31.779 CVE năm 2024, lấy KEV làm chuẩn; chỉ số: độ phủ, kích thước tập ưu tiên, tỉ lệ KEV trong tập. Kết quả: CVSS phủ rộng nhưng tập lớn; EPSS chọn lọc hơn; OR cân bằng. **Không xét mạng/topology.**

**Định vị đồ án sau khi đọc (đề xuất):** các bài so sánh CVSS/EPSS/KEV (Pinto, EPSS) không xét mạng; các bài theo đồ thị (VulRG, PatchRank/SmartPatch) xét mạng nhưng đánh giá định tính hoặc trên vài ví dụ, trọng số tự đặt. Khoảng trống hợp lý để đồ án đứng: **đánh giá định lượng, tái lập được** (rủi ro đường tấn công còn lại R(k) theo ngân sách vá) các chính sách điểm đơn lẻ và theo ngữ cảnh trên mạng công khai (NASim), có đối chiếu với tối ưu và phân tích độ nhạy. Đây là định vị **sau khi đọc 3 bài**, chưa phải khảo sát đầy đủ.

**Cần đọc tiếp:** PatchRank (Yadav & Paul 2019) và SmartPatch (Yadav và cộng sự 2022), gần nhất về "rủi ro còn lại"; Homer và cộng sự 2013 (xác suất trên attack graph từ CVSS), cơ sở cho mô hình −ln p; phần còn lại của VulRG (kịch bản 3, hạn chế).

## Kết luận tạm
- **Tính mới cần thận trọng.** VulRG (mục 1) và công trình hardening (mục 6–7) đã dùng đồ thị mạng để chọn lỗ hổng cần vá. Đề tài không nên tuyên bố "chưa ai làm". Hướng nói an toàn: đóng góp là một khung đánh giá tái lập được, so sánh các chính sách dùng điểm đơn lẻ với chính sách theo ngữ cảnh trên các mạng NASim, kèm phân tích độ bền. Cần đọc VulRG để biết họ so sánh gì và với dữ liệu nào.
- Tìm được các bài so sánh CVSS/EPSS/KEV (mục 3–5), nhưng chúng đánh giá trên **toàn bộ CVE**, không xét vị trí trên mạng; điểm khác này có thể là chỗ đồ án đứng.
- Cần thêm: tìm bài về đánh giá chính sách vá bằng mô phỏng attack graph có xác suất, và bài mô hình xác suất từ CVSS trên attack graph (VulRG trích dẫn một bài như vậy nhưng chưa xác định tên).

## Việc tiếp theo (tuần 1)
1. Đọc VulRG và khảo sát 2502.11070, ghi: họ so sánh chính sách nào, dữ liệu gì, kết luận gì.
2. Đọc mục 3 (phương pháp đánh giá).
3. ~~Tìm bản gốc bài Wang–Noel–Jajodia; kiểm tra chứng minh độ khó.~~ Xong 2026-10-28 (xem mục cuối).
4. Hoàn thành bảng 10–15 nguồn đã đọc.

## Đọc thêm 2026-10-28 (agent nghiên cứu đọc; C kiểm lại nguyên văn các câu trích quan trọng)

*Mức truy cập ghi rõ cho từng bài. Không trích nội dung của bài chỉ đọc được tóm tắt ngoài những gì có trong tóm tắt.*

| # | Nguồn | Truy cập | Ý chính dùng cho luận văn |
|---|---|---|---|
| 11 | G. Yadav, K. Paul, "PatchRank: Ordering updates for SCADA systems", IEEE ETFA 2019, tr. 110–117, DOI 10.1109/ETFA.2019.8869110 | **chỉ tóm tắt** | xếp thứ tự vá có ngữ cảnh cho SCADA (Viable System Model + CVSS + lý thuyết trò chơi), so với SecureRank, CVSS, density-based; "hội tụ tới trạng thái an toàn khả dụng nhanh hơn" |
| 12 | G. Yadav, P. Gauravaram, A. K. Jindal, K. Paul, "SmartPatch: A patch prioritization framework", Computers in Industry 137 (2022) 103595, DOI 10.1016/j.compind.2021.103595 | **không đọc được bài, kể cả tóm tắt**; chỉ qua trang dự án và tóm tắt luận án tiến sĩ của tác giả (IIT Delhi) | mở rộng PatchRank; "Residual Impact Score" (RIS) sau mỗi vòng vá; ca nghiên cứu IEEE 5-Bus; RIS giảm nhanh hơn các phương pháp khác. Gần nhất với R(k) của đồ án về **cách đánh giá** |
| 13 | J. Homer, S. Zhang, X. Ou, D. Schmidt, Y. Du, S. R. Rajagopalan, A. Singhal, "Aggregating vulnerability metrics in enterprise networks using attack graphs", J. Computer Security 21 (2013) 561–597, DOI 10.3233/JCS-130475 | **toàn văn** (cse.usf.edu/~xou/publications/jcs13.pdf) | xác suất có điều kiện mỗi bước từ **CVSS v2 Access Complexity** {low → 0,9, medium → 0,6, high → 0,2} (đã kiểm nguyên văn); nhân dọc chuỗi tiền điều kiện (Prop. 4.2); xử lý phụ thuộc chung và chu trình; metric là xác suất **≥ 1 đường** thành công, không phải đường tốt nhất |
| 14 | S. Jha, O. Sheyner, J. Wing, "Two formal analyses of attack graphs", IEEE CSFW-15, 2002 | **toàn văn** | **nguồn chứng minh độ khó** (đã kiểm nguyên văn, phụ lục): "the hitting set problem is NP-complete, the MCSA problem is NP-hard. Lemma 1 in [15] proves that MCSA is in NP. Therefore, MCSA is NP-complete." và "the problem of finding a minimum set of measures whose adoption will make the network safe is also NP-complete." |
| 15 | O. Sheyner, J. Haines, S. Jha, R. Lippmann, J. Wing, "Automated generation and analysis of attack graphs", IEEE S&P 2002 | **chưa đọc** (PDF là ảnh quét) | chứng minh NP-complete gốc theo lời Jha 2002; chỉ trích qua Jha 2002 |

**Wang, Noel, Jajodia 2006 (mục 7), đã đọc toàn văn:** tìm tập điều kiện ban đầu chi phí nhỏ nhất để không còn đường tới mục tiêu, bằng biểu thức logic rồi DNF; lời giải chính xác có độ phức tạp mũ trường hợp xấu nhất; đánh giá bằng ví dụ định tính. Bài **không** tự chứng minh NP-khó; nguyên văn (§3.2, đã kiểm): "It has also been shown that finding critical sets with the minimum cardinality is NP-hard, whereas finding a minimal critical set … is polynomial" [15 = Sheyner 2002, 6 = Jha 2002].

**Câu trích được dùng trong luận văn:** "Bài toán tìm tập tấn công (hay biện pháp) nhỏ nhất cắt mọi đường tấn công là NP-complete, chứng minh bằng quy dẫn từ Minimum Hitting Set [Jha, Sheyner, Wing 2002; Sheyner và cộng sự 2002]; Wang và cộng sự (2006) cho thấy lời giải chính xác có độ phức tạp mũ trong trường hợp xấu nhất."

**Lập luận đồ án phải tự trình bày (không có sẵn trong tài liệu):** câu hỏi "có k bản vá làm R(k) = 0 không" là bản quyết định của bài toán tập biện pháp nhỏ nhất (mỗi bản vá loại các cạnh của một CVE trên một máy), nên bài toán của đồ án ít nhất khó như vậy; vì thế vét cạn chỉ dùng cho mạng nhỏ.

**Homer 2013 và mô hình của đồ án:** ủng hộ việc lấy xác suất từng bước từ CVSS và nhân dọc chuỗi; nhưng (a) Homer dùng AC của CVSS v2, đồ án dùng Exploitability v3.1/10 — đây là lựa chọn của đồ án, lấy cảm hứng từ Homer; (b) Homer tính xác suất ≥ 1 đường, đồ án dùng đường tốt nhất, nên P\* của đồ án là cận dưới của đại lượng Homer (lập luận của đồ án); (c) Homer cảnh báo phép nhân đánh giá thấp rủi ro khi cùng một lỗ hổng xuất hiện ở nhiều máy — đưa vào mục hạn chế.

**Định vị (cập nhật):** đồ án nằm ở giao của ba hướng: hardening tối thiểu trên attack graph (Jha/Sheyner 2002, Noel 2003, Wang 2006: mục tiêu nhị phân chặn hết đường); gộp xác suất trên attack graph (Homer 2013); xếp thứ tự vá có ngữ cảnh và đánh giá bằng độ giảm rủi ro còn lại sau mỗi lần vá (PatchRank, SmartPatch). Điểm khác: ngân sách k và đường cong R(k) theo xác suất đường tốt nhất; so CVSS/EPSS/KEV với tham lam theo ngữ cảnh và với tối ưu vét cạn; đánh giá chéo ba mô hình xác suất; mạng công khai (NASim), dữ liệu snapshot có hash. Trong 4 bài đã đọc, không bài nào dùng EPSS/KEV hoặc so với tối ưu vét cạn (với PatchRank/SmartPatch, nhận định này chỉ dựa trên tóm tắt).

**Không được viết:**
- "Wang và cộng sự (2006) chứng minh NP-khó" (bài chỉ nhắc lại).
- Chi tiết chứng minh trong Sheyner 2002 (chưa đọc được).
- "Chọn k bản vá để cực tiểu P\* đã được chứng minh NP-khó trong tài liệu" (đó là lập luận của đồ án).
- "Homer dùng Exploitability / CVSS v3" hay "Homer dùng đường tốt nhất".
- Công thức RIS, dữ liệu, số liệu của SmartPatch; dữ liệu, số liệu của PatchRank ngoài tóm tắt.
