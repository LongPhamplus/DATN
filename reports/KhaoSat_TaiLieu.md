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
| 7 | Wang, Noel, Jajodia, "Minimum-cost network hardening using attack graphs", Computer Communications 2006 | bài toán hardening tối thiểu | trích dẫn khi nói về độ khó | **chưa tìm được bản đọc**; cần kiểm tra bài có chứng minh NP-khó hay không trước khi trích |
| 8 | [Topology-Aware Prioritized Patching for EV Charging Infrastructure (SciTePress 2025)](https://scitepress.org/publishedPapers/2025/132933/pdf/index.html) | vá theo đường tấn công nghiêm trọng nhất | công trình liên quan | chưa đọc |
| 9 | [RiskBridge (arXiv 2601.06201)](https://www.arxiv.org/pdf/2601.06201) | kết hợp CVSS v4, EPSS, KEV | công trình liên quan | chưa đọc |
| 10 | [NASim docs](https://networkattacksimulator.readthedocs.io/) | môi trường mạng mô phỏng, nguồn kịch bản | nguồn dữ liệu | đã đọc phần kịch bản (xem `DuLieuMang_CoSan.md`) |

## Kết luận tạm
- **Tính mới cần thận trọng.** VulRG (mục 1) và công trình hardening (mục 6–7) đã dùng đồ thị mạng để chọn lỗ hổng cần vá. Đề tài không nên tuyên bố "chưa ai làm". Hướng nói an toàn: đóng góp là một khung đánh giá tái lập được, so sánh các chính sách dùng điểm đơn lẻ với chính sách theo ngữ cảnh trên các mạng NASim, kèm phân tích độ bền. Cần đọc VulRG để biết họ so sánh gì và với dữ liệu nào.
- Tìm được các bài so sánh CVSS/EPSS/KEV (mục 3–5), nhưng chúng đánh giá trên **toàn bộ CVE**, không xét vị trí trên mạng; điểm khác này có thể là chỗ đồ án đứng.
- Cần thêm: tìm bài về đánh giá chính sách vá bằng mô phỏng attack graph có xác suất, và bài mô hình xác suất từ CVSS trên attack graph (VulRG trích dẫn một bài như vậy nhưng chưa xác định tên).

## Việc tiếp theo (tuần 1)
1. Đọc VulRG và khảo sát 2502.11070, ghi: họ so sánh chính sách nào, dữ liệu gì, kết luận gì.
2. Đọc mục 3 (phương pháp đánh giá).
3. Tìm bản gốc bài Wang–Noel–Jajodia; kiểm tra chứng minh độ khó.
4. Hoàn thành bảng 10–15 nguồn đã đọc.
