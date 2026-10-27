# Snapshot dữ liệu lỗ hổng (KEV, NVD, EPSS)

Bản sao cố định của dữ liệu công khai, tải bằng `scripts/fetch_snapshots.py`. Thí nghiệm chỉ đọc qua `aapef/data.py`; bộ nạp tính lại SHA-256 từng tệp và **từ chối** nếu khác `MANIFEST.json`. Không sửa tệp; muốn dữ liệu mới thì tạo snapshot mới (ngày khác).

| Tệp | Nguồn | Nội dung | Điều kiện sử dụng |
|---|---|---|---|
| `kev_<ngày>.json` | CISA KEV, bản sao chính thức `github.com/cisagov/kev-data` | nguyên văn | CC0 1.0 (tệp `LICENSE` của repo đó); không được dùng logo CISA/DHS hay ngụ ý được CISA bảo trợ |
| `nvd_<ngày>.json` | NVD CVE API 2.0 | mọi CVE thuộc KEV (`hasKev`) và mọi CVE công bố trong khoảng `population.published`; mỗi CVE chỉ giữ: ngày công bố, trạng thái, vector CVSS v3 (ưu tiên v3.1, ưu tiên bản Primary của NVD, nếu không có thì bản Secondary của CNA, ghi ở `vector_source`), base score, exploitability score, CWE | "This product uses data from the NVD API but is not endorsed or certified by the NVD." Giới hạn 5 yêu cầu / 30 giây khi không có khóa API |
| `epss_<ngày>.json` | tệp CSV EPSS hằng ngày (FIRST, Empirical Security) | `[epss, percentile]` của các CVE trong hai tệp trên; ghi `model_version`, `score_date` và SHA-256 của tệp `.csv.gz` gốc để đối chiếu | miễn phí, không cần đăng ký; yêu cầu ghi nguồn khi công bố (FAQ của FIRST EPSS) |

`snapshot_id` = `<ngày>:<12 ký tự đầu của SHA-256 ghép các hash tệp>`; mọi tệp kết quả thí nghiệm phải mang giá trị này.

Tái tạo (từ thư mục gốc repo): `python scripts/fetch_snapshots.py --pub-range 2024-01-01:2024-12-31`. NVD và KEV là trạng thái tại lúc tải, nên chạy lại vào ngày khác sẽ ra dữ liệu khác; đó là lý do dữ liệu được lưu lại thay vì tải lại.
