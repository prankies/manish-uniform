# Manish Uniform — stitching & cloth tracker

Mobile-first web app for a school-uniform shop that buys cloth, sends it to a tailor
(stitching vendor) for job work, and gets the finished uniforms back.

Same stack as GPCI ERP: Python + Flask + SQLite, React 18 from CDN in one
`static/index.html` (no build step), JWT login.

## Run
Double-click `start.bat`, then open http://localhost:5004 (phone on the same Wi-Fi:
`http://<pc-ip>:5004`). First login: `admin@manishuniform.com` / `admin123`,
so change it under More → Change password.

## The flow it tracks
1. **Cloth order (CO)**: order placed on the cloth vendor (cloth, qty, rate).
2. **Cloth despatch (CD)**: what the cloth vendor actually sent against that order, with
   qty, rate, amount, freight, despatch date, where it went (a tailor, or your own godown), and
   the received date. Vendors often send more than needed because of their MOQ.
3. **Stitch order (SO)**: order on the tailor with product, size, pieces, stitching rate/pc,
   cloth and cloth-per-piece. Extra costs (transport, buttons, labels) go under *Other charges*.
4. **Cloth moves (CT)**: cloth sent from your godown to a tailor, taken back, or moved
   from one tailor to another.
5. **Goods from tailor (SD)**: the tailor's despatch date, your received date, pieces per line,
   cloth used, and any leftover cloth sent back with the goods.

Leave "Received date" blank while something is on the way. It then shows on the dashboard
under *Awaiting receipt* with a one-tap **Received** button.

## How stock is worked out
Stock is kept per location: your godown and each tailor.
`stock = received in − sent out − used in stitching`.
Cloth leaves the sender on the despatch date and reaches the receiver on the received date,
so until then it shows as "on the way".

## How average cost is worked out
- Cloth rate = weighted average landed cost of that cloth over all despatches
  (qty × rate + freight) ÷ qty.
- Per piece = (cloth used × cloth rate + pieces × stitch rate + the order's other charges
  shared out by pieces) ÷ pieces.
- Leftover cloth is **not** charged to the uniforms. It stays in stock at its value.

## Files
- `app.py`: all API routes, schema (`init_db`), stock & costing logic
- `static/index.html`: the whole UI
- `data/manish.db`: database (auto-created); daily backups go to `data/backups/` (kept 30 days)
- `.env`: `JWT_SECRET`, `PORT=5004`

Roles: **staff** can enter and edit everything. **admin** can also delete and manage users.

## Hosting (Railway): https://uniform.gpci.in
- Railway project `manish-uniform`, service `manish-uniform`, deployed from GitHub
  `prankies/manish-uniform` (branch `main`). Every push to `main` redeploys.
- Volume `manish-uniform-volume` is mounted at `/data`; `DATA_DIR=/data` is set in the Dockerfile.
  The database, daily backups and the generated JWT secret (`/data/.jwt_secret`) live there.
- On a fresh volume the first admin password is random and printed once in the deploy log
  (`railway logs --deployment`). `ADMIN_EMAIL` / `ADMIN_PASSWORD` variables override it.
- DNS (Cloudflare, gpci.in): CNAME `uniform` → the target shown by `railway domain list`,
  plus the `_railway-verify.uniform` TXT record.
