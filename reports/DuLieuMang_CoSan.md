# Bộ dữ liệu mô hình mạng có sẵn: khảo sát khả năng dùng cho AAPEF

*2026-10-26. Khảo sát này đọc dữ liệu thật đã tải về thư mục tạm (không đưa vào repo). **Không** gồm bộ chuyển đổi hay bộ sinh kịch bản; việc chuyển đổi/dựng kịch bản thuộc phần của tác giả (GĐ 12 trong `MasterPlan.md`).*

## 1. Kết luận ngắn
- Có hai nguồn công khai, giấy phép MIT, chứa mô hình mạng dạng tệp: **NASim** và **gói Zenodo 12514591**. Đã tải và đọc.
- **Không nguồn nào chứa mã CVE thật.** Lỗ hổng chỉ là nhãn (dịch vụ + xác suất, hoặc `vulExists(host, local|remote, hậu quả)`). Phần CVE vẫn phải do tác giả gán (từ NVD/KEV/EPSS), đúng với phân công hiện tại.
- Dùng được làm **nguồn cấu trúc mạng (topology, subnet, firewall)** và làm mạng đối chiếu. Chưa phải bộ "mạng + CVE" hoàn chỉnh.

## 2. NASim (Network Attack Simulator)
- Repo: `github.com/Jjschwartz/NetworkAttackSimulator`, giấy phép **MIT** (đã xem `LICENSE.md`).
- 9 kịch bản tĩnh YAML trong `nasim/scenarios/benchmark/`: `tiny`, `tiny-hard`, `tiny-small`, `small`, `small-honeypot`, `small-linear`, `medium`, `medium-single-site`, `medium-multi-site` (3–16 máy, 2–7 subnet). Ngoài ra có kịch bản sinh tự động (`generated.py`, tới 95 máy) — tham số theo seed, không phải tệp cố định.
- Định dạng (đã đọc `small.yaml`): `subnets` (số máy mỗi subnet), `topology` (ma trận kết nối subnet), `sensitive_hosts` (máy mục tiêu kèm giá trị), `os`, `services`, `processes`, `exploits` (service, os, `prob`, `cost`, quyền đạt được), `privilege_escalation`, chi phí quét, `host_configurations` (từng máy: os, dịch vụ, tiến trình), `firewall` (theo cặp subnet và theo dịch vụ được phép).

**Khớp với AAPEF**
| NASim | AAPEF |
|---|---|
| máy, subnet, kết nối | `hosts`, `topology` |
| `sensitive_hosts` | `goal` |
| exploit (user) / privilege_escalation (root) | action với `set_access` user / admin |
| quét dịch vụ, subnet | action thu thập (`learn`) |
| `prob` | nguồn xác suất; trong kế hoạch mới thay bằng xác suất từ CVE |

**Mất hoặc lệch khi chuyển**
- Firewall theo *dịch vụ* (ví dụ cặp subnet cho `ssh` nhưng không cho `http`); AAPEF `reachable` chỉ có cạnh máy→máy, không theo dịch vụ.
- Có nhiều mục tiêu `sensitive_hosts` với giá trị; AAPEF có một goal. Cần chọn quy ước.
- `os`/`processes` quyết định exploit nào áp dụng; AAPEF dùng `env_fact`.
- `prob`, `cost` của exploit là số tuỳ ý của tác giả NASim, không phải CVE; chỉ mượn **cấu trúc**, không mượn số.
- Môi trường NASim có quan sát một phần (partial observability); mô hình AAPEF tất định và biết toàn bộ.

## 3. Gói Zenodo 12514591 (Maoz & Busany, FM 2024)
- Giấy phép trong gói: **MIT, © 2022 Accenture** (trang Zenodo ghi thêm CC BY 4.0 / Apache 2.0; phải chọn và dẫn đúng khi dùng). ~125 MB, đã giải nén kiểm tra.
- Đầu vào dạng **MulVAL** (tệp `.P` các sự kiện Prolog) và đồ thị tấn công dạng JSON:

| Tập | Nội dung (đã đếm) | Nhận xét |
|---|---|---|
| Running Example | `toy_input.P`, 62 dòng: miền Windows (máy trạm, server, DC), nhóm, phiên đăng nhập, `dcSync` | Dạng Active Directory; mục tiêu `domainCompromised`; không có `hacl`, không có CVE |
| SET I | `1_pulp_and_paper_input.P` (1046 dòng), `2_vehicle_assembly_input.P` (313 dòng) | Mạng công nghiệp theo tên; không có `hacl`/`vulExists`/CVE |
| SET II | `aag_16_computers.P` (450 dòng; 295 `hacl`, 6 `vulExists`); `aag_4_computers.P` rỗng; `aag_14_6_20.P` | Có kết nối máy→máy theo cổng; lỗ hổng chỉ dạng `local|remote` + hậu quả (`code_exec`, `dos`…) |
| SET III | `input.P`, 275 dòng | Không có `hacl`, CVE |
| SET IV | `Synthetic.zip` (~117 MB): `small.json` (60 nút, 75 cạnh), `medium.json` (802 nút, 1763 cạnh), `large.json` (~300K nút), `xl.zip` (~10M nút) | Đây là *đồ thị tấn công đã sinh* theo một kịch bản miền Windows, không phải mô hình mạng đầu vào |

- Gói chỉ có đồ thị/đầu vào kiểu MulVAL (quyền, nhóm, phiên); không có mapping sang `access/known` của AAPEF sẵn.

**Nhận định.** `aag_16_computers.P` là ứng viên duy nhất có cấu trúc kết nối máy→máy nhiều (295 cạnh `hacl`, 16 máy); còn lại thiên về mô hình Active Directory. Muốn dùng phải viết bộ chuyển đổi riêng và chịu mất mát đáng kể (mô hình quyền AD ≠ mô hình access của AAPEF). Giá trị so với NASim thấp hơn cho đồ án này.

## 4. Các nguồn khác (chưa tải, chưa kiểm)
- **CyberBattleSim** (Microsoft): mạng cố định ToyCTF (hub-and-spoke) và Chain; mô hình thông tin đăng nhập khác AAPEF. Mã trong repo, chưa đọc.
- **MulVAL** testcase `3host`: chỉ 3 máy, mang tính ví dụ.
- **FASHION** (arXiv 1910.07921): theo bài, chưa có benchmark attack graph chuẩn; họ tự tạo >600 mẫu, chưa rõ có công bố hay không.

## 5. Khuyến nghị cho đồ án
1. **Dùng NASim làm nguồn cấu trúc** cho bốn họ mạng (phẳng/DMZ/phân đoạn/…): `small-linear`, `medium-single-site`, `medium-multi-site`, `small-honeypot` có sẵn các cấu trúc tương ứng. Ghi nguồn, giấy phép, và ánh xạ sang JSON của AAPEF trong luận văn.
2. **CVE vẫn do tác giả gán** từ snapshot NVD/KEV/EPSS (không có sẵn ở đâu). Quy tắc gán công bố trước.
3. **Nêu rõ trong luận văn:** cấu trúc từ bộ có sẵn (NASim, MIT), lỗ hổng từ dữ liệu công khai (NVD/KEV/EPSS), phần ghép hai thứ là của tác giả; chi phí/xác suất NASim không dùng.
4. **Gói Zenodo:** chỉ để trích dẫn như công trình liên quan, không nên dùng làm dữ liệu chính.
5. **Hỏi thầy** xem NASim (mạng mô phỏng công khai, MIT) có thoả yêu cầu "bộ dữ liệu có sẵn" không.

## 6. Việc chưa làm / chưa kiểm
- Chưa chạy hay nạp thử NASim; chưa đọc `generated.py` và các YAML còn lại (chỉ đọc `small.yaml`).
- Chưa kiểm số máy/subnet từng kịch bản ngoài bảng trong tài liệu NASim.
- Chưa đọc `Paper.pdf`/`README.pdf` của gói Zenodo; chưa kiểm `large.json`/`xl.zip`.
- Chưa tìm thêm bộ khác (khảo sát này một lượt, không toàn diện).

## 7. Kiểm tra NASim bằng số liệu (2026-10-26)

Đọc cả 9 tệp YAML tĩnh bằng PyYAML (chỉ đếm cấu trúc, **không** chuyển đổi, **không** chạy NASim). Số liệu khớp bảng trong tài liệu NASim (3–16 máy).

| Kịch bản | Subnet | Máy | Liên kết subnet | Hướng firewall (đóng hoàn toàn) | Mục tiêu nhạy | Exploit / leo thang |
|---|---|---|---|---|---|---|
| tiny | 2 | 3 | 4 | 8 (2) | 2 | 1 / 1 |
| tiny-hard | 2 | 3 | 4 | 8 (2) | 2 | 3 / 2 |
| tiny-small | 3 | 5 | 5 | 10 (2) | 2 | 3 / 2 |
| small | 4 | 8 | 5 | 10 (2) | 2 | 3 / 2 |
| small-honeypot | 4 | 8 | 5 | 10 (2) | 2 | 3 / 2 |
| small-linear | 6 | 8 | 7 | 14 (4) | 2 | 3 / 2 |
| medium | 5 | 16 | 6 | 12 (2) | 2 | 5 / 3 |
| medium-single-site | 1 | 16 | 1 | 2 (1) | 2 | 5 / 3 |
| medium-multi-site | 6 | 16 | 10 | 20 (8) | 2 | 5 / 3 |

(Số subnet không tính "internet"; "liên kết" = số cặp subnet kết nối trong ma trận `topology`; cột firewall đếm các hướng có khai báo và số hướng không cho dịch vụ nào đi qua.)

**Đánh giá phù hợp**
- **Phù hợp cho RQ-P2 (cấu trúc mạng):** có sẵn đủ dải cấu trúc: một site phẳng (`medium-single-site`), nhiều site nối (`medium-multi-site`, 10 liên kết, 8 hướng đóng), tuyến tính (`small-linear`). Chưa có cấu trúc hình sao rõ ràng; nếu cần phải tự dựng.
- **Kích thước nhỏ:** tối đa 16 máy. Kế hoạch dự kiến 10–50 máy; bộ sinh tự động của NASim (tới 95 máy) có thể mở rộng nhưng không phải tệp cố định. Kích thước 16 máy vẫn trong tầm của AAPEF (đã chạy tới hàng chục nghìn trạng thái), nhưng **chưa thử**.
- **Hai mục tiêu nhạy ở mọi kịch bản:** AAPEF có một `goal`. Cần quy ước (chọn một mục tiêu, hoặc mỗi kịch bản sinh hai bản). Phải ghi rõ trong luận văn.
- **Ít đa dạng dịch vụ:** 1–5 loại dịch vụ, 1–5 exploit; gán CVE thật sẽ là phần quyết định tính thực tế của dữ liệu.
- **Kết luận:** NASim đủ làm **nguồn cấu trúc** cho một phần lớn bộ mạng (nhất là cấu trúc nhiều subnet, firewall), kèm các cấu trúc tự dựng (hình sao) và quy mô lớn hơn. Không đủ làm bộ dữ liệu độc lập.

**Chưa kiểm:** việc nạp bằng chính thư viện NASim; hành vi các kịch bản sinh tự động; khả năng AAPEF chạy hết các kịch bản đã chuyển (cần bộ chuyển đổi do tác giả làm).

## 8. Nguồn KEV (kiểm tra 2026-10-26)
- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`: tải trực tiếp bằng `curl` mặc định trả **403 Access Denied**. Không dùng cách vượt kiểm tra để tải; script tải sau này phải kiểm tra điều kiện truy cập của CISA.
- Bản sao chính thức của CISA trên GitHub, `cisagov/kev-data` (tệp `known_exploited_vulnerabilities.json`, nhánh `main`): tải được (HTTP 200, ~1,8 MB), `catalogVersion` 2026.10.23, **1756 mục**, có trường `cveID`, `vendorProject`… Đây là nguồn khả thi cho snapshot.
