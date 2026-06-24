# Echo Invoice

> Invoicing & billing platform for ECHO Prime. Clients, invoices, estimates,
> products, expenses, credits, payments, and AI insights — multi-tenant with
> Stripe. A Hono app on Cloudflare Workers.

Private to Echo Prime Technologies.

## What it does

Manage **clients** and **products**, send **estimates** that convert to
**invoices**, collect **payments** (Stripe), track **expenses** (by category) and
**credits**, and use AI for **invoice-optimization** and **late-payment-risk**
scoring. An **activity** log records changes.

## API (auth: `X-Echo-API-Key`)

| Resource | Routes |
|---|---|
| Clients | `/clients`, `/clients/:id` |
| Invoices | `/invoices`, `/invoices/:id` |
| Estimates | `/estimates`, `/estimates/:id` |
| Products | `/products`, `/products/:id` |
| Expenses | `/expenses`, `/expenses/categories` |
| Credits & payments | `/credits`, `/payments` |
| AI | `/ai/invoice-optimization`, `/ai/late-payment-risk` |
| Billing | `/admin/migrate-stripe` (Stripe) |
| Meta | `/health`, `/activity` |

`GET` lists/reads, `POST` creates, `PUT`/`DELETE` on `/:id` where applicable.

## Develop

```bash
npm install
npm run dev       # wrangler dev (local Worker)
npm run deploy    # wrangler deploy
```

Stripe keys and the D1 binding live in `wrangler.toml` / the Cloudflare dashboard.
`.gitignore` excludes `node_modules`. Never commit secrets.

## License

Proprietary — © Echo Prime Technologies. All rights reserved.
