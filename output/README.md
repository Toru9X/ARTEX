# output/

Nơi để sản phẩm của một đợt test: báo cáo, evidence, request/response thô.
Đây là dữ liệu của khách hàng, không phải mã nguồn — xem phần Git ở cuối.

## Phân loại: một thư mục cho một hệ thống

```
output/
  <he-thong>-<moi-truong>/
    report/       báo cáo và phụ lục (.md, .docx, .pdf)
    evidence/     ảnh chụp, log, dump, file tải về
    traffic/      request/response thô, .har, PoC gửi tay
  _unsorted/      chưa xác định được thuộc hệ thống nào
```

Tên lấy theo đúng cách repo đặt tên, để không phải nhớ hai bộ quy ước:

- **chữ thường, nối bằng gạch ngang** — giống `skills/api-recon`,
  `skills/edr-bypass-re`, `docs/vulnerability-traffic-evidence.md`
- **ba thư mục con mang đúng từ ARTEX đang dùng**: `report/`, `evidence/`,
  `traffic/` là tên ba package ở gốc repo. ARTEX gọi request/response là
  *traffic* ở mọi nơi — kho `data/traffic/`, trang `/function/traffic`, package
  `traffic/` — nên ở đây cũng gọi thế, không gọi `http/`.
- **tiền tố `_` cho thư mục không phải dữ liệu một hệ thống**, giống
  `data/traffic/_blobs`, `_ca`, `_index` và `web/src/app/(main)/_components`.

Lấy **tên hệ thống**, không lấy tên khách hàng hay ngày tháng, vì khi tìm
người ta nhớ hệ thống trước. Thêm môi trường nếu một hệ thống có nhiều môi
trường:

```
vsf-iam-uat          đúng
pcp-uat              đúng
bao-cao-thang-11     sai  — không tìm được theo hệ thống
iam_final_v2_moi     sai  — gạch dưới, không nói hệ thống nào, lại còn "v2_moi"
```

## Đặt tên file

`<he-thong>-<loai>-<mo-ta-ngan>.<ext>`, cùng tiền tố với thư mục để file vẫn
tự mô tả khi bị gửi đi lẻ hoặc tải về nằm chung một chỗ:

```
vsf-iam-uat/report/vsf-iam-uat-bao-cao-pentest.md
vsf-iam-uat/report/vsf-iam-uat-phu-luc-raw-http.txt
vsf-iam-uat/traffic/vsf-iam-uat-f02-bola-orders.http
vsf-iam-uat/evidence/vsf-iam-uat-f01-admin-console.png
```

Có mã finding thì đặt ngay sau tên hệ thống (`f01`, `f02`…) để evidence và
traffic của cùng một lỗi nằm cạnh nhau khi sắp xếp theo tên.

## Git

Chỉ file README này được track. Toàn bộ nội dung còn lại trong `output/` bị
`.gitignore` chặn: đó là dữ liệu thật của khách hàng, và một khi đã vào lịch sử
git thì xoá ở commit sau không gỡ được, phải rewrite history.

Muốn commit một file cụ thể thì phải cố ý: `git add -f output/<đường-dẫn>`.
