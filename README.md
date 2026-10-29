# TopUp Hub — customer top-up backend

Clean copy of the Avardo Copy 2 auth/store backend, adapted for the
customer top-up store at https://customer-top-up-store.vercel.app.
The original in `~/workspace/avardo-copy2-auth/` was NOT modified, and
nothing here has been pushed or deployed anywhere.

## Start

```bash
npm install
npm start
```

The service listens on `PORT` (default 3000). On boot it creates the
tables it needs (`ensureSchema()` in `server.js` is the schema source;
`schema.sql` is only the users-table reference copy).

## Health

- `GET /` → `{ "service": "customer-top-up-backend", "ok": true }`
- `GET /api/health` → `{ "ok": true, "db": true|false }`
  (`db: false` just means `DATABASE_URL` is not set yet.)

## Environment variables (all secrets via env only — none are in this repo)

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | Yes, for auth/orders | Postgres connection string (e.g. a fresh Neon database for this store — do NOT reuse the Avardo database, or the two stores would share users/orders) |
| `JWT_SECRET` | Yes, for auth | Long random string for 30-day JWTs |
| `CORS_ORIGIN` | No (has a default) | Comma-separated allowed origins. Default: `https://customer-top-up-store.vercel.app` — and the Google callback always redirects to the FIRST origin in this list, so keep the storefront first |
| `GOOGLE_CLIENT_ID` | For Google sign-in | OAuth Web client ID |
| `GOOGLE_CLIENT_SECRET` | For Google sign-in | OAuth Web client secret |
| `GOOGLE_REDIRECT_URI` | No | Defaults to `<this-service>/api/auth/google/callback` |
| `BUSAN_API_KEY` | For Busan features | 1gamestopup API key (USD wallet). Without it, check-id reports unconfigured, fulfilment is skipped, and orders stay manual — nothing breaks |
| `XTRA_USER_TOKEN` | For UPI payments | PaySafe/XtraGateway merchant token. Without it, UPI create/status return 503 |
| `XTRA_BASE_URL` | No (has a default) | PaySafe base URL. Default: `https://paysafe.mlbbstore.in` |
| `PORT` | No (default 3000) | Set automatically by most hosts |

## Routes (all kept from the original)

- Auth: `POST /api/auth/register`, `POST /api/auth/login`,
  `GET /api/auth/me` (Bearer JWT), `GET /api/auth/google`,
  `GET /api/auth/google/callback` (finds-or-creates by email, redirects
  to the storefront with `#token=<jwt>`)
- Store: `GET /api/store` (public; reseller prices stripped for
  anonymous/non-reseller visitors), `PUT /api/admin/store` (admin only)
- Wallet: `GET /api/wallet/me`, `POST /api/wallet/topup-request`
- Orders: `POST /api/orders` (wallet/whatsapp/upi; server-side price
  resolution from saved store data; reseller price when set),
  `GET /api/orders/me`, `GET /api/orders/:id`,
  `GET /api/admin/orders`, `POST /api/admin/orders/:id/status`
  (transitions: pending → paid/delivered/cancelled,
  paid → delivered/cancelled/refunded, delivered → refunded;
  cancelling a paid wallet order and refunding a paid/delivered wallet
  order both credit the wallet + write a ledger entry; UPI/WhatsApp
  refunds are a status record only — the money moves outside the system)
- Top-up requests: `GET /api/admin/topup-requests`,
  `POST /api/admin/topup-requests/:id/decision`
- Coupons: `POST /api/coupons/validate`, `GET /api/admin/coupons`,
  `POST /api/admin/coupons`, `POST /api/admin/coupons/:id/toggle`
- Resellers/users: `GET /api/admin/resellers`,
  `POST /api/admin/resellers`, `GET /api/admin/users`
- Busan: `POST /api/games/check-id` (public, rate-limited, plain
  customer-facing errors), `GET /api/admin/busan/status`,
  `GET /api/admin/busan/products`, `POST /api/admin/orders/:id/fulfil`
  (paid orders with a `busanProductId` mapping auto-deliver on payment;
  failures stay `paid` with the error recorded, never fake-delivered)
- UPI: `POST /api/payments/upi/create`, `GET /api/payments/upi/status`
  (gateway COMPLETED → order `paid` + Busan fulfil hook; cancelled/
  refunded are terminal and never flip back)
- Misc: `POST /api/region-check`, `GET /api/leaderboard` (masked names
  only), `GET /api/stats/best-sellers`

## What was changed from Avardo Copy 2

- Service name: `avardo-copy2-auth` → `customer-top-up-backend`
  (root `/` response, startup log, `package.json`, headers)
- Branding: Avardo → TopUp Hub (comments, payment remark)
- Admin: `['sumanmusahari@gmail.com', 'avardoofficialstore@gmail.com']`
  → `['kwsalmusahari@gmail.com']` only
- Order codes: `CP2-<id>` → `TP-<id>` everywhere, including wallet
  ledger refs (`order_payment`, `order_refund`) and the gateway order id
  (`TP<id><timestamp>`)
- Payment return: `https://www.avardoofficial.in/?payment_return=<id>`
  → `https://customer-top-up-store.vercel.app/?payment_return=<id>`
- CORS default: `https://avardo-official-copy-2.onrender.com`
  → `https://customer-top-up-store.vercel.app` (first origin)
- **Removed: `backfillIndiaCheckMapping()`** — the original's boot-time
  backfill that stamped Avardo's MLBB India packs (game id `mlbb-in`)
  with generic-Busan check + fulfilment mappings. It was Avardo
  catalogue data, not generic logic, and auto-enabling fulfilment on a
  new store's packs would be unsafe. The new store's admin must map
  packs deliberately (via the saved store data's `busanProductId` /
  `busanCheckProductId` fields) after prices are verified against live
  Busan costs.

## What was kept generic but still needs attention

- **Region-check probes** (`POST /api/region-check`): the Busan product
  IDs probed per MLBB route (Philippines, Global, Brazil, Russia,
  Turkey, US, SG/MY, Indonesia, Generic) are kept verbatim — they are
  Busan product IDs, not Avardo data, and the live Busan API is the
  authority. The recommendation names (`Mobile Legends — India`, etc.)
  must match the new storefront's game names exactly, or the
  recommendation will not prefill a game. Unverified against the new
  storefront's catalogue (it has no backend data yet).
- **Busan catalogue file NOT copied**: the original never reads
  `busan-catalogue.json` from disk — `GET /api/admin/busan/products`
  calls the live Busan API (10-minute cache). So no catalogue file is
  needed here; the first admin catalogue load requires a live
  `BUSAN_API_KEY` and Busan availability.
- **PaySafe default kept**: `XTRA_BASE_URL` still defaults to
  `https://paysafe.mlbbstore.in`. Set it explicitly if the customer
  uses a different gateway host.
- **Google OAuth is a different flow from the storefront's current
  button**: this backend uses the server-side flow
  (`GET /api/auth/google` → callback at
  `<backend>/api/auth/google/callback`). The storefront currently uses
  Google Identity Services with a JS-origin client. A backend Google
  login needs its OWN OAuth client with the backend callback as the
  redirect URI — the existing GIS client cannot be reused for it, and
  the storefront must be pointed at this backend's `/api/auth/google`
  to use it. Also note the consent screen: while it is in Testing
  mode, only listed test users can sign in.
- **No storefront wiring yet**: the Vercel store still points at its
  own local/static login. Pointing it at this backend (API base URL +
  token handling + admin gating) is a separate storefront change, not
  done here.
- **No database yet**: `DATABASE_URL` must be a FRESH database for
  this store. Reusing Avardo's would merge the two stores' users,
  orders, wallets and store data.
- **No keys set**: every secret above is unset in this code. The
  customer must supply their own Busan key and PaySafe token if they
  want auto-fulfilment and UPI — never copy Avardo's keys.
