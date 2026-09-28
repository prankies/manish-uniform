# Manish Uniform — stitching & cloth tracker

Mobile-first web app for a school-uniform shop that buys cloth, sends it to a tailor
(stitching vendor) for job work, and gets the finished uniforms back.

Same stack as GPCI ERP: Python + Flask + SQLite, React 18 from CDN in one
`static/index.html` (no build step), JWT login.

## Run
Double-click `start.bat`, then open http://localhost:5004 (phone on the same Wi-Fi:
`http://<pc-ip>:5004`). First login: `admin@manishuniform.com` / `admin123`,
so change it under ☰ → Change password.

## The flow it tracks
1. **School order (SCH)**: what a school ordered, item by item and size by size.
2. **Stitch order (SO)**: work given to a tailor, usually made from a school order
   ("Give to tailor" fills in the sizes not yet given out). Each item has a school, cloth,
   cloth width and stitching rate; cloth per piece comes from the item's size chart.
   On saving, the app shows the **material required** (metres per cloth) against what is
   already with the tailor or on order, and offers to raise a cloth order for the shortfall.
3. **Cloth order (CO)**: order on the cloth vendor. It can be linked to several stitch orders
   (and a stitch order to several cloth orders); the extra over the need is the vendor's MOQ.
4. **Cloth despatch (CD)**: what the cloth vendor actually sent, by rate or by total bill,
   with freight, dates and destination (a tailor, or your own godown).
5. **Cloth moves (CT)**: cloth sent from your godown to a tailor, taken back, or moved
   from one tailor to another.
6. **Goods from tailor (SD)**: the tailor's despatch date, your received date, pieces per size,
   cloth used, and any leftover cloth sent back with the goods.
7. **Tailor bill**: the total of the tailor's bill for an order; when entered it replaces
   pieces × rate as the stitching cost.

## Items, sizes and cloth width
Menu → *Items & sizes* holds the standard uniform items with a size chart of metres per piece,
written for a 58" wide cloth. The charts are starting estimates — correct them to the tailor's
figures. When a cloth lot comes in a different width, set that width on the stitch order line;
metres per piece scale by chart width ÷ actual width (switch this off per item for things like
dupattas and ties whose length doesn't depend on width). New items, schools and cloths can also
be added straight from any dropdown ("+ Add new …").

Leave "Received date" blank while something is on the way. It then shows on the dashboard
under *Awaiting receipt* with a one-tap **Received** button.

## How stock is worked out
Stock is kept per location: your godown and each tailor.
`stock = received in − sent out − used in stitching`.
Cloth leaves the sender on the despatch date and reaches the receiver on the received date,
so until then it shows as "on the way".

## How average cost is worked out
- Cloth rate = weighted average landed cost of that cloth over all despatches
  (bill amount + freight) ÷ qty.
- Per piece = (cloth used × cloth rate + stitching + the order's other charges shared out by
  pieces) ÷ pieces. Stitching is pieces × rate, or the tailor's bill total once entered.
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
