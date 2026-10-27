# NASim benchmark scenarios (dữ liệu nguồn)

Các tệp `.yaml` ở đây được sao nguyên văn từ thư mục `nasim/scenarios/benchmark/` của
NetworkAttackSimulator (NASim), https://github.com/Jjschwartz/NetworkAttackSimulator,
commit `4f26de37cfdc3e4553ed8b7484c4db8e2924bdea` (tải ngày 2026-10-26). Giấy phép MIT: xem `LICENSE.md`.

Không chỉnh sửa các tệp này. Kịch bản AAPEF được sinh từ chúng bằng `nasim2aapef.py`, ví dụ:

    python nasim2aapef.py data/nasim/small.yaml -o scenarios/small.json --id nasim-small

Khảo sát và đánh giá mức phù hợp: `reports/DuLieuMang_CoSan.md`.
