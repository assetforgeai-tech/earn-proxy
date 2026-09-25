# Goal Prompt: Proxiware Provider Operations Menu, Sync, And Guarded Swap

Tiếp tục hoàn thiện end-to-end tính năng tích hợp Proxiware Static ISP trong repo:

`D:\1. WORK_true\Tranfer Proxy\earn-proxy`

## Bối cảnh bắt buộc

- Tiếp tục từ branch `feat/proxiware-sync-swap` và toàn bộ thay đổi hiện có.
- Không reset, checkout, xoá hoặc ghi đè thay đổi chưa commit.
- Tuyệt đối không sửa, migrate, deploy hoặc chạy lệnh trong `D:\1. WORK_true\CashPilot`.
- API spec: `D:\1. WORK_true\Tranfer Proxy\proxiware_api.yaml`.
- Chrome CDP `9222` chỉ dùng để khảo sát/read-only browser smoke khi cần.
- Không commit credential, password, API key, 2Captcha key, cookie, CAPTCHA token, CDP state, fingerprint hoặc raw provider response.

## Mục tiêu

Xây một khu vực quản trị riêng, first-class `Providers -> Proxiware`, để admin quản lý và theo dõi toàn bộ provider: health, inventory, qualification, sync, session, credentials, swap queue/history, policy và audit. Đây là control plane độc lập với `Distribution API`, `Transfer Proxy`, user pages, earnings, online hours và quota user.

## Ranh giới menu bắt buộc

Sidebar chỉ hiển thị cho admin:

```text
Providers
└── Proxiware
    ├── Overview
    ├── Inventory
    ├── Qualification
    ├── Sync
    ├── Swap queue
    ├── Swap history
    ├── Session
    ├── Credentials
    ├── Policy
    └── Audit
```

- Không đặt control Proxiware trong `Distribution API`, `Transfer Proxy` hoặc menu user/contributor.
- Dùng admin authorization hiện có; không tạo role system thứ hai trong goal này.
- Mọi route, query, mutation, worker claim, setting, credential và audit phải scope `provider='proxiware'`.
- Overview phải link trực tiếp tới đúng trang xử lý alert; không redirect mọi trang về `/admin`.
- Pause/resume automation chỉ ảnh hưởng Proxiware, không dừng distribution, earnings, online hours, quota hoặc provider khác.
- Khi API, session hoặc worker lỗi, menu vẫn mở được và hiển thị `stale`, `blocked` hoặc `manual_action_required`; không dùng spinner vô hạn.
- Tất cả trang direct-linkable, reload-safe, có breadcrumb, active sidebar, keyboard-accessible, responsive desktop/mobile, không phụ thuộc hash.

## Menu và route bắt buộc

Tạo sidebar group chỉ hiển thị cho admin:

`Providers -> Proxiware`

Các route direct-linkable, reload-safe, không phụ thuộc hash:

- `/admin/providers/proxiware` — Overview/health.
- `/admin/providers/proxiware/inventory` — inventory provider.
- `/admin/providers/proxiware/qualification` — live/protocol/egress/country/quality.
- `/admin/providers/proxiware/sync` — sync, progress, cancel, history.
- `/admin/providers/proxiware/swaps` — actionable queue.
- `/admin/providers/proxiware/swaps/history` — immutable history.
- `/admin/providers/proxiware/session` — session/connection.
- `/admin/providers/proxiware/credentials` — write-only secrets.
- `/admin/providers/proxiware/policy` — policy controls.
- `/admin/providers/proxiware/audit` — redacted audit trail.

Mọi list phải có count, search, filter, sort, page size, pagination, empty/loading/stale/error state. Mọi mutation phải có admin authorization, CSRF, rate limit, confirmation nêu rõ target/consequence, audit, `Cache-Control: no-store`.

## Chức năng

### 1. Official API sync

- Chỉ dùng endpoint chính thức có trong YAML.
- Sync idempotent theo provider/external ID; không tạo duplicate.
- Có scheduled sync và `Sync now`.
- GET không được tạo run, claim job hoặc gọi provider.
- Có durable queue, single-run lock, progress, cancel, timeout, bounded retry, lease recovery và restart-safe.
- API key đọc từ secret store đã mã hoá; không log request/response secret.
- Không mua proxy, gia hạn, tạo subscription, billing hoặc payment.

### 2. Qualification

- Dùng canonical checker hiện có của hệ thống.
- Protocol unknown phải chuyển auto-detect.
- Kiểm tra live, protocol, exit IP, quốc gia và quality.
- Exit IP phải là IP Internet thực của upstream proxy; không lấy DNS/resolver/probe-server IP.
- Duplicate egress so sánh toàn bộ proxy của mọi user và mọi provider.
- Trạng thái công khai trong admin: `Allow`, `Risk`, `Dead`, `Pending`.
- `inconclusive`, `Pending`, `unknown`, duplicate-egress và stale probe không được auto-swap hoặc distribution.
- Provider proxy không tạo earnings, online hours hoặc quota user.

### 3. Swap policy

Chỉ queue swap khi đồng thời thỏa tất cả:

- proxy live;
- qualification là `Risk`, không phải `Allow`;
- provider cho phép swap;
- eligible `< 1000`;
- connections `< 1000`;
- còn quota/rate limit;
- không có job khác cho assignment;
- không duplicate egress;
- cooldown đã hết;
- auto-swap đang bật.

Guard phải revalidate ngay lúc claim và ngay trước mutation. Không swap `Allow`, `Dead`, `Pending`, `inconclusive`, `unknown`, duplicate, cooldown hoặc active-swap. Sau swap chờ tối thiểu `60s` trước khi probe replacement. Lưu mapping old/new trước khi ghi success. Retry hữu hạn, backoff; lỗi session/CAPTCHA/CSRF/fingerprint/provider rejection chuyển `manual_action_required`, pause auto-swap và không loop.

Nếu API không có swap endpoint và browser adapter không chứng minh được flow ổn định/được phép, fail closed; không giả lập success.

### 4. Session/credentials

Admin có thể update/clear riêng từng secret trong menu `Providers -> Proxiware -> Credentials`:

- Proxiware email;
- Proxiware password;
- Proxiware API key;
- 2Captcha key dùng cho hCaptcha nếu provider/account terms cho phép.

Lưu encrypted at rest, write-only. Không trả plaintext/ciphertext/cookie/token/fingerprint qua HTML, JSON, URL, log, audit, exception hoặc Git. Browser adapter chỉ đăng nhập account đã cấu hình, dùng isolated context, bounded retry và một persistent profile ổn định. `2Captcha` chỉ giải hCaptcha, không phải cơ chế bypass fingerprint; không spoof/randomize fingerprint. Khi session hết hạn, tự đăng nhập lại theo bounded flow; lỗi CAPTCHA/CSRF/fingerprint/session lặp lại phải pause auto-swap và chuyển `manual_action_required`. Không tự động mua hoặc thao tác tài chính.

### 5. Distribution

- Provider distribution mặc định `OFF` và độc lập với earnings.
- Admin có toggle riêng.
- Nếu bật, API nội bộ có hai loại output riêng: `proxy-raw` và `proxy-transfer`.
- Fail closed; không xuất dead, duplicate, ambiguous, cooldown, pending, inconclusive hoặc active-swap.
- Không để provider inventory tạo earnings/online hours/quota user.

### 6. Worker/operations

- Sync, qualification và swap worker có durable claim, lease timeout, heartbeat, queue depth, last-success, stale/error state.
- Docker/systemd có restart policy và healthcheck.
- Idle không được tạo CPU loop; concurrency/batch bounded để xử lý khoảng 30.000 proxy.
- Reboot/crash không mất queue, không tạo duplicate job.

### 7. UI/UX

- Dùng visual language TailAdmin hiện có; không thêm UI dependency nếu không cần.
- Menu Proxiware không nằm lẫn trong `Distribution API`.
- Có breadcrumb, active state, direct URL, responsive desktop/mobile, keyboard focus, no horizontal overflow.
- Không dùng global spinner khoá trang; action hiển thị inline progress/result.
- Hiển thị rõ `Healthy`, `Session expired`, `Blocked`, `Needs attention`, `manual_action_required`.
- Overview có một nút emergency pause cho toàn bộ automation Proxiware; không ảnh hưởng các provider hoặc luồng phân phối khác.
- Overview có liên kết hành động tới đúng submenu cho từng trạng thái: stale sync, worker lỗi, session hết hạn, swap bị block, duplicate egress hoặc manual action.
- Không hiển thị provider name, EarnApp/internal checker wording hoặc internal reason code cho user/contributor.

## Thứ tự triển khai

1. Đọc code/diff hiện có, map route/schema/worker; ghi baseline; không sửa CashPilot.
2. Hoàn thiện read-only control center: menu, inventory sync, qualification, count/filter/pagination, health, audit; chứng minh GET side-effect free.
3. Hoàn thiện session boundary: encrypted write-only secrets, isolated persistent browser profile, bounded hCaptcha flow; `2Captcha` chỉ giải hCaptcha được phép, không bypass fingerprint.
4. Hoàn thiện guarded swap queue ở dry-run/fake adapter; revalidate ngay trước claim/mutation; chờ `60s`; lỗi mơ hồ chuyển `manual_action_required` và pause automation.
5. Hoàn thiện distribution exclusion; giữ provider distribution và auto-swap `OFF`; không ảnh hưởng earnings, online hours, quota user.
6. Hoàn thiện UI/UX và emergency pause; desktop/mobile smoke qua CDP `9222`.
7. Viết runbook, preflight, dry-run, security artifacts; ghi rõ mọi blocker.
8. Chạy verification gate; chỉ commit/push khi pass. Không deploy VPS hoặc swap thật nếu chưa có approval riêng.

## Test và acceptance gate

Chạy:

```powershell
python -m pytest -p no:cacheprovider -q
python -m ruff check app tests scripts
python -m ruff format --check app tests scripts
python -m compileall -q app tests scripts
python -m pip check
```

Bắt buộc có test cho:

- admin authorization, CSRF, rate limit, IDOR/provider scope;
- idempotent sync, lock, cancel, timeout, retry, crash recovery;
- unknown protocol auto-detect;
- exit IP/duplicate egress đúng, không nhầm DNS;
- `Allow` không swap;
- `Dead`/`Pending`/`inconclusive`/duplicate không swap hoặc distribution;
- threshold `<1000`, connections `<1000`, cooldown `60s`;
- credential/audit/log/HTML redaction;
- GET side-effect free;
- worker heartbeat/restart/healthcheck;
- user pages không lộ provider/internal data;
- toàn bộ menu, filter, sort, pagination, confirmation và responsive UI.
- sidebar chỉ có một `Providers -> Proxiware`, không còn control Proxiware rải ở menu khác;
- pause/resume Proxiware không ảnh hưởng distribution, earnings, online hours, quota hoặc provider khác;
- mỗi alert Overview mở đúng trang xử lý và mọi submenu reload/direct-link hoạt động.

Tạo preflight và mocked dry-run trên database disposable. Security sweep phải bao phủ auth, CSRF, IDOR, SSRF, XSS, SQL/command injection, secret leakage, cache, rate limit, state race và fail-closed distribution.

## Ranh giới production

- Không deploy VPS, không enable auto-swap, không mua, không billing, không swap thật trong goal này nếu chưa có approval riêng.
- `production-ready` chỉ được báo khi test/static/security/browser smoke/preflight/healthcheck pass và mọi rủi ro còn lại được ghi rõ.
- Pilot live chỉ một assignment, có rollback owner, monitoring và xác nhận thủ công riêng.
- Báo cáo cuối phải nêu: files/changes, commands/results, security findings, known risks, deploy status và manual actions còn thiếu.

## Điểm dừng bắt buộc

- Nếu browser adapter thật chưa được review/test hoặc không chứng minh được flow được ủy quyền: giữ `manual_action_required`, không giả lập success.
- Nếu `pip check` còn mismatch môi trường dùng chung: không che giấu; kiểm tra môi trường cô lập hoặc ghi blocker rõ trong báo cáo.
- Không gọi purchase, billing, renewal, subscription mutation, hoặc endpoint swap thật trong goal này.
