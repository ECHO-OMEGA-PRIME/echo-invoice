/**
 * Echo Invoice v1.1.0 — AI-Powered Invoicing & Billing
 * Cloudflare Worker with Hono, D1, KV, service bindings
 */
import { Hono } from 'hono';
import { cors } from 'hono/cors';

interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ENGINE_RUNTIME: Fetcher;
  SHARED_BRAIN: Fetcher;
  EMAIL_SENDER: Fetcher;
  ECHO_API_KEY?: string;
}

// TODO: Consider batching sequential D1 queries with db.batch() for performance

// TODO: Consider batching sequential D1 queries with db.batch() for performance

interface RLState { c: number; t: number }

const app = new Hono<{ Bindings: Env }>();

// Security headers middleware
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '1; mode=block');
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
  c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
});
app.use('*', cors({ origin: '*', allowMethods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'], allowHeaders: ['Content-Type','Authorization','X-Tenant-ID','X-Echo-API-Key'] }));

// ── Helpers ──
const uid = () => crypto.randomUUID();
const sanitize = (s: string, max = 2000) => s?.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '').slice(0, max) ?? '';
const sanitizeBody = (o: Record<string, unknown>) => {
  const r: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) r[k] = typeof v === 'string' ? sanitize(v) : v;
  return r;
};
const tid = (c: any) => c.req.header('X-Tenant-ID') || c.req.query('tenant_id') || '';
const json = (d: unknown, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json' } });

// ── Rate Limiting ──
// Structured logging helper (auto-added by Evolution Engine)
function structuredLog(level: string, message: string, meta: Record<string, any> = {}): void {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), level, message, ...meta }));
}

async function rateLimit(kv: KVNamespace, key: string, limit: number, windowSec = 60): Promise<boolean> {
  const rlKey = `rl:${key}`;
  const now = Date.now();
  const raw = await kv.get(rlKey);
  if (!raw) { await kv.put(rlKey, JSON.stringify({ c: 1, t: now }), { expirationTtl: windowSec * 2 }); return false; }
  const st: RLState = JSON.parse(raw);
  const elapsed = (now - st.t) / 1000;
  const decay = Math.max(0, st.c - (elapsed / windowSec) * limit);
  const count = decay + 1;
  await kv.put(rlKey, JSON.stringify({ c: count, t: now }), { expirationTtl: windowSec * 2 });
  return count > limit;
}

// ── Rate limit middleware ──
app.use('*', async (c, next) => {
  const path = new URL(c.req.url).pathname;
  if (path === '/health' || path === '/status') return next();
  const ip = c.req.header('cf-connecting-ip') || 'unknown';
  const isWrite = ['POST','PUT','PATCH','DELETE'].includes(c.req.method);
  const limited = await rateLimit(c.env.CACHE, `${ip}:${isWrite ? 'w' : 'r'}`, isWrite ? 60 : 200);
  if (limited) return json({ error: 'Rate limited' }, 429);
  return next();
});

// ── Auth middleware ──
app.use('*', async (c, next) => {
  const method = c.req.method;
  const path = new URL(c.req.url).pathname;
  if (method === 'GET' || method === 'OPTIONS' || method === 'HEAD' || path === '/health' || path === '/status' || path.startsWith('/public/')) return next();
  const apiKey = c.req.header('X-Echo-API-Key') || '';
  const bearer = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected || (apiKey !== expected && bearer !== expected)) {
    return json({ error: 'Unauthorized', message: 'Valid X-Echo-API-Key or Bearer token required for write operations' }, 401);
  }
  return next();
});

// ── Health ──
app.get('/', (c) => c.redirect('/health'));
app.get('/health', (c) => json({ status: 'ok', service: 'echo-invoice', version: '1.1.0', time: new Date().toISOString() }));

// ═══════════════ TENANTS ═══════════════
app.post('/tenants', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    const id = uid();
    await c.env.DB.prepare(`INSERT INTO tenants (id,name,email,phone,address,city,state,zip,country,tax_id,currency,payment_terms_days,late_fee_percent,invoice_prefix,bank_name,bank_account,bank_routing,paypal_email) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(id, b.name, b.email||null, b.phone||null, b.address||null, b.city||null, b.state||null, b.zip||null, b.country||'US', b.tax_id||null, b.currency||'USD', b.payment_terms_days||30, b.late_fee_percent||0, b.invoice_prefix||'INV', b.bank_name||null, b.bank_account||null, b.bank_routing||null, b.paypal_email||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/tenants', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/tenants/:id', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM tenants WHERE id=?').bind(c.req.param('id')).first();
    return r ? json(r) : json({ error: 'Not found' }, 404);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/tenants/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/tenants/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    await c.env.DB.prepare(`UPDATE tenants SET name=coalesce(?,name),email=coalesce(?,email),phone=coalesce(?,phone),address=coalesce(?,address),city=coalesce(?,city),state=coalesce(?,state),zip=coalesce(?,zip),currency=coalesce(?,currency),payment_terms_days=coalesce(?,payment_terms_days),late_fee_percent=coalesce(?,late_fee_percent),invoice_prefix=coalesce(?,invoice_prefix),bank_name=coalesce(?,bank_name),paypal_email=coalesce(?,paypal_email),updated_at=datetime('now') WHERE id=?`)
      .bind(b.name||null, b.email||null, b.phone||null, b.address||null, b.city||null, b.state||null, b.zip||null, b.currency||null, b.payment_terms_days||null, b.late_fee_percent||null, b.invoice_prefix||null, b.bank_name||null, b.paypal_email||null, c.req.param('id')).run();
    return json({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/tenants/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ CLIENTS ═══════════════
app.get('/clients', async (c) => {
  try {
    const t = tid(c);
    const search = c.req.query('search');
    let q = 'SELECT * FROM clients WHERE tenant_id=?';
    const params: string[] = [t];
    if (search) { q += ' AND (name LIKE ? OR company LIKE ? OR email LIKE ?)'; const s = `%${sanitize(search,100)}%`; params.push(s,s,s); }
    q += ' ORDER BY name';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/clients', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/clients', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare(`INSERT INTO clients (id,tenant_id,name,company,email,phone,address,city,state,zip,country,tax_id,currency,payment_terms_days,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(id, t, b.name, b.company||null, b.email||null, b.phone||null, b.address||null, b.city||null, b.state||null, b.zip||null, b.country||'US', b.tax_id||null, b.currency||'USD', b.payment_terms_days||null, b.notes||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/clients', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/clients/:id', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM clients WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).first();
    if (!r) return json({ error: 'Not found' }, 404);
    const invoices = await c.env.DB.prepare('SELECT id,invoice_number,status,total,amount_due,due_date FROM invoices WHERE client_id=? AND tenant_id=? ORDER BY issue_date DESC LIMIT 10').bind(c.req.param('id'), tid(c)).all();
    return json({ ...r, recent_invoices: invoices.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/clients/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/clients/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    await c.env.DB.prepare(`UPDATE clients SET name=coalesce(?,name),company=coalesce(?,company),email=coalesce(?,email),phone=coalesce(?,phone),address=coalesce(?,address),city=coalesce(?,city),state=coalesce(?,state),zip=coalesce(?,zip),notes=coalesce(?,notes),updated_at=datetime('now') WHERE id=? AND tenant_id=?`)
      .bind(b.name||null, b.company||null, b.email||null, b.phone||null, b.address||null, b.city||null, b.state||null, b.zip||null, b.notes||null, c.req.param('id'), tid(c)).run();
    return json({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/clients/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/clients/:id', async (c) => {
  try {
    const outstanding = await c.env.DB.prepare("SELECT COUNT(*) as cnt FROM invoices WHERE client_id=? AND tenant_id=? AND status NOT IN ('paid','void')").bind(c.req.param('id'), tid(c)).first();
    if (outstanding && (outstanding as any).cnt > 0) return json({ error: 'Client has outstanding invoices' }, 400);
    await c.env.DB.prepare('DELETE FROM clients WHERE id=? AND tenant_id=?').bind(c.req.param('id'), tid(c)).run();
    return json({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/clients/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ PRODUCTS/SERVICES CATALOG ═══════════════
app.get('/products', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM products WHERE tenant_id=? AND is_active=1 ORDER BY name').bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/products', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/products', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO products (id,tenant_id,name,description,unit_price,tax_rate,unit,sku) VALUES (?,?,?,?,?,?,?,?)')
      .bind(id, t, b.name, b.description||null, b.unit_price||0, b.tax_rate||0, b.unit||'unit', b.sku||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/products', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/products/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    await c.env.DB.prepare('UPDATE products SET name=coalesce(?,name),description=coalesce(?,description),unit_price=coalesce(?,unit_price),tax_rate=coalesce(?,tax_rate),unit=coalesce(?,unit),sku=coalesce(?,sku),is_active=coalesce(?,is_active) WHERE id=? AND tenant_id=?')
      .bind(b.name||null, b.description||null, b.unit_price??null, b.tax_rate??null, b.unit||null, b.sku||null, b.is_active??null, c.req.param('id'), tid(c)).run();
    return json({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/products/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ TAX RATES ═══════════════
app.get('/tax-rates', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT * FROM tax_rates WHERE tenant_id=? ORDER BY name').bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/tax-rates', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/tax-rates', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO tax_rates (id,tenant_id,name,rate,is_compound,is_default) VALUES (?,?,?,?,?,?)')
      .bind(id, t, b.name, b.rate, b.is_compound||0, b.is_default||0).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/tax-rates', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ INVOICES ═══════════════
app.get('/invoices', async (c) => {
  try {
    const t = tid(c); const status = c.req.query('status'); const client = c.req.query('client_id');
    let q = 'SELECT i.*, c.name as client_name, c.company as client_company FROM invoices i LEFT JOIN clients c ON i.client_id=c.id WHERE i.tenant_id=?';
    const params: string[] = [t];
    if (status) { q += ' AND i.status=?'; params.push(status); }
    if (client) { q += ' AND i.client_id=?'; params.push(client); }
    q += ' ORDER BY i.issue_date DESC LIMIT 100';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/invoices', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    // Atomically claim next invoice number: increment first, then read
    await c.env.DB.prepare('UPDATE tenants SET next_invoice_number=next_invoice_number+1 WHERE id=?').bind(t).run();
    const tenant = await c.env.DB.prepare('SELECT invoice_prefix, next_invoice_number, payment_terms_days FROM tenants WHERE id=?').bind(t).first() as any;
    const prefix = tenant?.invoice_prefix || 'INV';
    const num = (tenant?.next_invoice_number || 1002) - 1; // We already incremented, so subtract 1 to get the claimed number
    const invoiceNumber = `${prefix}-${String(num).padStart(5, '0')}`;
    // Calculate due date from payment terms
    const paymentTerms = (b.payment_terms_days as number) || tenant?.payment_terms_days || 30;
    const issueDate = (b.issue_date as string) || new Date().toISOString().split('T')[0];
    const dueDate = (b.due_date as string) || new Date(new Date(issueDate).getTime() + paymentTerms * 86400000).toISOString().split('T')[0];

    await c.env.DB.prepare(`INSERT INTO invoices (id,tenant_id,client_id,invoice_number,status,issue_date,due_date,subtotal,tax_rate,tax_amount,discount_percent,discount_amount,shipping,total,amount_due,currency,notes,terms,footer,po_number) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(id, t, b.client_id, invoiceNumber, 'draft', issueDate, dueDate, 0, b.tax_rate||0, 0, b.discount_percent||0, 0, b.shipping||0, 0, 0, b.currency||'USD', b.notes||null, b.terms||null, b.footer||null, b.po_number||null).run();

    // Add items if provided
    const items = b.items as any[];
    if (items?.length) {
      let subtotal = 0;
      let totalTax = 0;
      for (const item of items) {
        const iid = uid();
        const amount = (item.quantity || 1) * (item.unit_price || 0);
        const itemTaxRate = item.tax_rate ?? b.tax_rate ?? 0;
        const taxAmt = amount * (itemTaxRate / 100);
        subtotal += amount;
        totalTax += taxAmt;
        await c.env.DB.prepare('INSERT INTO invoice_items (id,invoice_id,tenant_id,description,quantity,unit_price,amount,tax_rate,tax_amount,sort_order,product_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
          .bind(iid, id, t, sanitize(item.description||''), item.quantity||1, item.unit_price||0, amount, itemTaxRate, taxAmt, item.sort_order||0, item.product_id||null).run();
      }
      const discountAmount = subtotal * ((b.discount_percent as number)||0) / 100;
      const total = subtotal + totalTax - discountAmount + ((b.shipping as number)||0);
      await c.env.DB.prepare('UPDATE invoices SET subtotal=?,tax_amount=?,discount_amount=?,total=?,amount_due=? WHERE id=?')
        .bind(subtotal, totalTax, discountAmount, total, total, id).run();
    }

    await logActivity(c.env.DB, t, 'invoice', id, 'created', `Invoice ${invoiceNumber} created`);
    return json({ id, invoice_number: invoiceNumber }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/invoices/:id', async (c) => {
  try {
    const inv = await c.env.DB.prepare('SELECT i.*, c.name as client_name, c.company as client_company, c.email as client_email, c.address as client_address, c.city as client_city, c.state as client_state, c.zip as client_zip FROM invoices i LEFT JOIN clients c ON i.client_id=c.id WHERE i.id=? AND i.tenant_id=?').bind(c.req.param('id'), tid(c)).first();
    if (!inv) return json({ error: 'Not found' }, 404);
    const items = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id=? ORDER BY sort_order').bind(c.req.param('id')).all();
    const payments = await c.env.DB.prepare('SELECT * FROM payments WHERE invoice_id=? ORDER BY payment_date DESC').bind(c.req.param('id')).all();
    return json({ ...inv, items: items.results, payments: payments.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.put('/invoices/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    await c.env.DB.prepare(`UPDATE invoices SET notes=coalesce(?,notes),terms=coalesce(?,terms),footer=coalesce(?,footer),po_number=coalesce(?,po_number),due_date=coalesce(?,due_date),tax_rate=coalesce(?,tax_rate),discount_percent=coalesce(?,discount_percent),shipping=coalesce(?,shipping),updated_at=datetime('now') WHERE id=? AND tenant_id=?`)
      .bind(b.notes||null, b.terms||null, b.footer||null, b.po_number||null, b.due_date||null, b.tax_rate??null, b.discount_percent??null, b.shipping??null, c.req.param('id'), tid(c)).run();
    // Recalculate totals
    await recalcInvoice(c.env.DB, c.req.param('id'), tid(c));
    return json({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Add/update/remove invoice items
app.post('/invoices/:id/items', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    const amount = ((b.quantity as number)||1) * ((b.unit_price as number)||0);
    const taxAmt = amount * (((b.tax_rate as number)||0) / 100);
    await c.env.DB.prepare('INSERT INTO invoice_items (id,invoice_id,tenant_id,description,quantity,unit_price,amount,tax_rate,tax_amount,sort_order,product_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, c.req.param('id'), t, b.description, b.quantity||1, b.unit_price||0, amount, b.tax_rate||0, taxAmt, b.sort_order||0, b.product_id||null).run();
    await recalcInvoice(c.env.DB, c.req.param('id'), t);
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices/:id/items', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.delete('/invoices/:invId/items/:itemId', async (c) => {
  try {
    await c.env.DB.prepare('DELETE FROM invoice_items WHERE id=? AND invoice_id=?').bind(c.req.param('itemId'), c.req.param('invId')).run();
    await recalcInvoice(c.env.DB, c.req.param('invId'), tid(c));
    return json({ deleted: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices/:invId/items/:itemId', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Send invoice
app.post('/invoices/:id/send', async (c) => {
  try {
    const t = tid(c); const invId = c.req.param('id');
    await c.env.DB.prepare("UPDATE invoices SET status='sent',sent_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND tenant_id=? AND status IN ('draft','sent')").bind(invId, t).run();
    await logActivity(c.env.DB, t, 'invoice', invId, 'sent', 'Invoice sent to client');
    return json({ sent: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices/:id/send', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Mark as viewed
app.post('/invoices/:id/viewed', async (c) => {
  try {
    await c.env.DB.prepare("UPDATE invoices SET viewed_at=coalesce(viewed_at,datetime('now')) WHERE id=? AND tenant_id=?").bind(c.req.param('id'), tid(c)).run();
    return json({ viewed: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices/:id/viewed', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Void invoice
app.post('/invoices/:id/void', async (c) => {
  try {
    const t = tid(c); const invId = c.req.param('id');
    await c.env.DB.prepare("UPDATE invoices SET status='void',amount_due=0,updated_at=datetime('now') WHERE id=? AND tenant_id=?").bind(invId, t).run();
    await logActivity(c.env.DB, t, 'invoice', invId, 'voided', 'Invoice voided');
    return json({ voided: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices/:id/void', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Clone/duplicate invoice
app.post('/invoices/:id/clone', async (c) => {
  try {
    const t = tid(c);
    const orig = await c.env.DB.prepare('SELECT * FROM invoices WHERE id=? AND tenant_id=?').bind(c.req.param('id'), t).first() as any;
    if (!orig) return json({ error: 'Not found' }, 404);
    const items = await c.env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id=?').bind(c.req.param('id')).all();
    // Get next number
    const tenant = await c.env.DB.prepare('SELECT invoice_prefix, next_invoice_number FROM tenants WHERE id=?').bind(t).first() as any;
    const invoiceNumber = `${tenant.invoice_prefix}-${String(tenant.next_invoice_number).padStart(5, '0')}`;
    const newId = uid();
    const today = new Date().toISOString().split('T')[0];
    const dueDate = new Date(Date.now() + (tenant.payment_terms_days||30) * 86400000).toISOString().split('T')[0];
    await c.env.DB.prepare(`INSERT INTO invoices (id,tenant_id,client_id,invoice_number,status,issue_date,due_date,subtotal,tax_rate,tax_amount,discount_percent,discount_amount,shipping,total,amount_due,currency,notes,terms,footer) VALUES (?,?,?,?,'draft',?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(newId, t, orig.client_id, invoiceNumber, today, dueDate, orig.subtotal, orig.tax_rate, orig.tax_amount, orig.discount_percent, orig.discount_amount, orig.shipping, orig.total, orig.total, orig.currency, orig.notes, orig.terms, orig.footer).run();
    for (const item of items.results as any[]) {
      await c.env.DB.prepare('INSERT INTO invoice_items (id,invoice_id,tenant_id,description,quantity,unit_price,amount,tax_rate,tax_amount,sort_order,product_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .bind(uid(), newId, t, item.description, item.quantity, item.unit_price, item.amount, item.tax_rate, item.tax_amount, item.sort_order, item.product_id).run();
    }
    await c.env.DB.prepare('UPDATE tenants SET next_invoice_number=next_invoice_number+1 WHERE id=?').bind(t).run();
    return json({ id: newId, invoice_number: invoiceNumber }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/invoices/:id/clone', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ PAYMENTS ═══════════════
app.get('/payments', async (c) => {
  try {
    const t = tid(c); const invId = c.req.query('invoice_id');
    let q = 'SELECT p.*, c.name as client_name, i.invoice_number FROM payments p LEFT JOIN clients c ON p.client_id=c.id LEFT JOIN invoices i ON p.invoice_id=i.id WHERE p.tenant_id=?';
    const params: string[] = [t];
    if (invId) { q += ' AND p.invoice_id=?'; params.push(invId); }
    q += ' ORDER BY p.payment_date DESC LIMIT 100';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/payments', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/payments', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO payments (id,tenant_id,invoice_id,client_id,amount,method,reference,notes,payment_date) VALUES (?,?,?,?,?,?,?,?,?)')
      .bind(id, t, b.invoice_id, b.client_id, b.amount, b.method||'other', b.reference||null, b.notes||null, b.payment_date||new Date().toISOString().split('T')[0]).run();
    // Update invoice
    const inv = await c.env.DB.prepare('SELECT amount_paid, total FROM invoices WHERE id=? AND tenant_id=?').bind(b.invoice_id, t).first() as any;
    if (inv) {
      const newPaid = (inv.amount_paid||0) + (b.amount as number);
      const newDue = Math.max(0, (inv.total||0) - newPaid);
      const status = newDue <= 0 ? 'paid' : 'partial';
      await c.env.DB.prepare('UPDATE invoices SET amount_paid=?,amount_due=?,status=?,paid_date=CASE WHEN ?<=0 THEN date(?) ELSE paid_date END,updated_at=datetime(\'now\') WHERE id=?')
        .bind(newPaid, newDue, status, newDue, b.payment_date||new Date().toISOString().split('T')[0], b.invoice_id).run();
    }
    // Update client totals
    await updateClientTotals(c.env.DB, t, b.client_id as string);
    await logActivity(c.env.DB, t, 'payment', id, 'recorded', `Payment of ${b.amount} recorded`);
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/payments', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ ESTIMATES / QUOTES ═══════════════
app.get('/estimates', async (c) => {
  try {
    const t = tid(c); const status = c.req.query('status');
    let q = 'SELECT e.*, c.name as client_name FROM estimates e LEFT JOIN clients c ON e.client_id=c.id WHERE e.tenant_id=?';
    const params: string[] = [t];
    if (status) { q += ' AND e.status=?'; params.push(status); }
    q += ' ORDER BY e.issue_date DESC';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/estimates', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/estimates', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    const estNum = `EST-${String(Date.now()).slice(-6)}`;
    const expiryDate = (b.expiry_date as string) || new Date(Date.now() + 30*86400000).toISOString().split('T')[0];
    await c.env.DB.prepare('INSERT INTO estimates (id,tenant_id,client_id,estimate_number,issue_date,expiry_date,tax_rate,discount_percent,notes,terms) VALUES (?,?,?,?,date(\'now\'),?,?,?,?,?)')
      .bind(id, t, b.client_id, estNum, expiryDate, b.tax_rate||0, b.discount_percent||0, b.notes||null, b.terms||null).run();
    // Add items
    const items = b.items as any[];
    let subtotal = 0;
    if (items?.length) {
      for (const item of items) {
        const amount = (item.quantity||1) * (item.unit_price||0);
        subtotal += amount;
        await c.env.DB.prepare('INSERT INTO estimate_items (id,estimate_id,tenant_id,description,quantity,unit_price,amount,sort_order,product_id) VALUES (?,?,?,?,?,?,?,?,?)')
          .bind(uid(), id, t, sanitize(item.description||''), item.quantity||1, item.unit_price||0, amount, item.sort_order||0, item.product_id||null).run();
      }
    }
    const taxAmount = subtotal * ((b.tax_rate as number)||0) / 100;
    const discountAmount = subtotal * ((b.discount_percent as number)||0) / 100;
    const total = subtotal + taxAmount - discountAmount;
    await c.env.DB.prepare('UPDATE estimates SET subtotal=?,tax_amount=?,discount_amount=?,total=? WHERE id=?').bind(subtotal, taxAmount, discountAmount, total, id).run();
    return json({ id, estimate_number: estNum }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/estimates', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/estimates/:id', async (c) => {
  try {
    const est = await c.env.DB.prepare('SELECT e.*, c.name as client_name, c.email as client_email FROM estimates e LEFT JOIN clients c ON e.client_id=c.id WHERE e.id=? AND e.tenant_id=?').bind(c.req.param('id'), tid(c)).first();
    if (!est) return json({ error: 'Not found' }, 404);
    const items = await c.env.DB.prepare('SELECT * FROM estimate_items WHERE estimate_id=? ORDER BY sort_order').bind(c.req.param('id')).all();
    return json({ ...est, items: items.results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/estimates/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// Convert estimate to invoice
app.post('/estimates/:id/convert', async (c) => {
  try {
    const t = tid(c); const estId = c.req.param('id');
    const est = await c.env.DB.prepare('SELECT * FROM estimates WHERE id=? AND tenant_id=?').bind(estId, t).first() as any;
    if (!est) return json({ error: 'Not found' }, 404);
    const items = await c.env.DB.prepare('SELECT * FROM estimate_items WHERE estimate_id=?').bind(estId).all();
    // Create invoice with same items
    const tenant = await c.env.DB.prepare('SELECT invoice_prefix, next_invoice_number, payment_terms_days FROM tenants WHERE id=?').bind(t).first() as any;
    const invoiceNumber = `${tenant.invoice_prefix}-${String(tenant.next_invoice_number).padStart(5, '0')}`;
    const invId = uid();
    const today = new Date().toISOString().split('T')[0];
    const dueDate = new Date(Date.now() + (tenant.payment_terms_days||30)*86400000).toISOString().split('T')[0];
    await c.env.DB.prepare(`INSERT INTO invoices (id,tenant_id,client_id,invoice_number,status,issue_date,due_date,subtotal,tax_rate,tax_amount,discount_percent,discount_amount,total,amount_due,currency) VALUES (?,?,?,?,'draft',?,?,?,?,?,?,?,?,?,?)`)
      .bind(invId, t, est.client_id, invoiceNumber, today, dueDate, est.subtotal, est.tax_rate, est.tax_amount, est.discount_percent, est.discount_amount, est.total, est.total, 'USD').run();
    for (const item of items.results as any[]) {
      await c.env.DB.prepare('INSERT INTO invoice_items (id,invoice_id,tenant_id,description,quantity,unit_price,amount,sort_order,product_id) VALUES (?,?,?,?,?,?,?,?,?)')
        .bind(uid(), invId, t, item.description, item.quantity, item.unit_price, item.amount, item.sort_order, item.product_id).run();
    }
    await c.env.DB.prepare("UPDATE estimates SET status='accepted',converted_invoice_id=?,updated_at=datetime('now') WHERE id=?").bind(invId, estId).run();
    await c.env.DB.prepare('UPDATE tenants SET next_invoice_number=next_invoice_number+1 WHERE id=?').bind(t).run();
    return json({ invoice_id: invId, invoice_number: invoiceNumber }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/estimates/:id/convert', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ RECURRING INVOICES ═══════════════
app.get('/recurring', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT r.*, c.name as client_name FROM recurring_invoices r LEFT JOIN clients c ON r.client_id=c.id WHERE r.tenant_id=? ORDER BY r.next_date').bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/recurring', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/recurring', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO recurring_invoices (id,tenant_id,client_id,frequency,interval_value,next_date,end_date,items_json,subtotal,tax_rate,notes,terms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, t, b.client_id, b.frequency||'monthly', b.interval_value||1, b.next_date, b.end_date||null, JSON.stringify(b.items||[]), b.subtotal||0, b.tax_rate||0, b.notes||null, b.terms||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/recurring', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.patch('/recurring/:id', async (c) => {
  try {
    const b = sanitizeBody(await c.req.json());
    await c.env.DB.prepare('UPDATE recurring_invoices SET status=coalesce(?,status),frequency=coalesce(?,frequency),next_date=coalesce(?,next_date),end_date=coalesce(?,end_date),updated_at=datetime(\'now\') WHERE id=? AND tenant_id=?')
      .bind(b.status||null, b.frequency||null, b.next_date||null, b.end_date||null, c.req.param('id'), tid(c)).run();
    return json({ updated: true });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/recurring/:id', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ EXPENSES ═══════════════
app.get('/expenses', async (c) => {
  try {
    const t = tid(c); const cat = c.req.query('category'); const from = c.req.query('from'); const to = c.req.query('to');
    let q = 'SELECT * FROM expenses WHERE tenant_id=?'; const params: string[] = [t];
    if (cat) { q += ' AND category=?'; params.push(cat); }
    if (from) { q += ' AND expense_date>=?'; params.push(from); }
    if (to) { q += ' AND expense_date<=?'; params.push(to); }
    q += ' ORDER BY expense_date DESC LIMIT 200';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/expenses', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/expenses', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO expenses (id,tenant_id,category,vendor,description,amount,tax_amount,currency,expense_date,receipt_url,is_billable,client_id,payment_method,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, t, b.category, b.vendor||null, b.description||null, b.amount, b.tax_amount||0, b.currency||'USD', b.expense_date||new Date().toISOString().split('T')[0], b.receipt_url||null, b.is_billable||0, b.client_id||null, b.payment_method||null, b.notes||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/expenses', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/expenses/categories', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT category, COUNT(*) as count, SUM(amount) as total FROM expenses WHERE tenant_id=? GROUP BY category ORDER BY total DESC').bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/expenses/categories', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ CREDITS ═══════════════
app.get('/credits', async (c) => {
  try {
    const r = await c.env.DB.prepare('SELECT cr.*, c.name as client_name FROM credits cr LEFT JOIN clients c ON cr.client_id=c.id WHERE cr.tenant_id=? ORDER BY cr.created_at DESC').bind(tid(c)).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/credits', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/credits', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json()); const id = uid();
    await c.env.DB.prepare('INSERT INTO credits (id,tenant_id,client_id,amount,reason) VALUES (?,?,?,?,?)')
      .bind(id, t, b.client_id, b.amount, b.reason||null).run();
    return json({ id }, 201);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/credits', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/credits/:id/apply', async (c) => {
  try {
    const t = tid(c); const b = sanitizeBody(await c.req.json());
    const credit = await c.env.DB.prepare('SELECT * FROM credits WHERE id=? AND tenant_id=? AND status=?').bind(c.req.param('id'), t, 'available').first() as any;
    if (!credit) return json({ error: 'Credit not found or already used' }, 404);
    // Apply as payment
    const payId = uid();
    await c.env.DB.prepare('INSERT INTO payments (id,tenant_id,invoice_id,client_id,amount,method,reference,notes,payment_date) VALUES (?,?,?,?,?,?,?,?,date(\'now\'))')
      .bind(payId, t, b.invoice_id, credit.client_id, credit.amount, 'credit', `Credit ${c.req.param('id')}`, 'Applied from credit').run();
    await c.env.DB.prepare("UPDATE credits SET status='applied',applied_to_invoice=? WHERE id=?").bind(b.invoice_id, c.req.param('id')).run();
    // Update invoice
    const inv = await c.env.DB.prepare('SELECT amount_paid, total FROM invoices WHERE id=?').bind(b.invoice_id).first() as any;
    if (inv) {
      const newPaid = (inv.amount_paid||0) + credit.amount;
      const newDue = Math.max(0, inv.total - newPaid);
      await c.env.DB.prepare('UPDATE invoices SET amount_paid=?,amount_due=?,status=CASE WHEN ?<=0 THEN \'paid\' ELSE \'partial\' END,updated_at=datetime(\'now\') WHERE id=?')
        .bind(newPaid, newDue, newDue, b.invoice_id).run();
    }
    return json({ applied: true, payment_id: payId });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/credits/:id/apply', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ REPORTS / ANALYTICS ═══════════════
app.get('/reports/overview', async (c) => {
  try {
    const t = tid(c);
    const [total, outstanding, overdue, paid30, expenses30, clients] = await Promise.all([
      c.env.DB.prepare("SELECT COUNT(*) as cnt, SUM(total) as sum FROM invoices WHERE tenant_id=? AND status!='void'").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt, SUM(amount_due) as sum FROM invoices WHERE tenant_id=? AND status IN ('sent','partial','overdue')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt, SUM(amount_due) as sum FROM invoices WHERE tenant_id=? AND status IN ('sent','partial','overdue') AND due_date<date('now')").bind(t).first(),
      c.env.DB.prepare("SELECT SUM(amount) as sum FROM payments WHERE tenant_id=? AND payment_date>=date('now','-30 days')").bind(t).first(),
      c.env.DB.prepare("SELECT SUM(amount) as sum FROM expenses WHERE tenant_id=? AND expense_date>=date('now','-30 days')").bind(t).first(),
      c.env.DB.prepare('SELECT COUNT(*) as cnt FROM clients WHERE tenant_id=?').bind(t).first(),
    ]);
    return json({
      total_invoices: (total as any)?.cnt || 0,
      total_invoiced: (total as any)?.sum || 0,
      outstanding_count: (outstanding as any)?.cnt || 0,
      outstanding_amount: (outstanding as any)?.sum || 0,
      overdue_count: (overdue as any)?.cnt || 0,
      overdue_amount: (overdue as any)?.sum || 0,
      collected_30d: (paid30 as any)?.sum || 0,
      expenses_30d: (expenses30 as any)?.sum || 0,
      net_income_30d: ((paid30 as any)?.sum || 0) - ((expenses30 as any)?.sum || 0),
      total_clients: (clients as any)?.cnt || 0,
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/reports/overview', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/reports/aging', async (c) => {
  try {
    const t = tid(c);
    const [current, d30, d60, d90, over90] = await Promise.all([
      c.env.DB.prepare("SELECT COUNT(*) as cnt, SUM(amount_due) as sum FROM invoices WHERE tenant_id=? AND status IN ('sent','partial') AND due_date>=date('now')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt, SUM(amount_due) as sum FROM invoices WHERE tenant_id=? AND status IN ('sent','partial','overdue') AND due_date<date('now') AND due_date>=date('now','-30 days')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt, SUM(amount_due) as sum FROM invoices WHERE tenant_id=? AND status IN ('sent','partial','overdue') AND due_date<date('now','-30 days') AND due_date>=date('now','-60 days')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt, SUM(amount_due) as sum FROM invoices WHERE tenant_id=? AND status IN ('sent','partial','overdue') AND due_date<date('now','-60 days') AND due_date>=date('now','-90 days')").bind(t).first(),
      c.env.DB.prepare("SELECT COUNT(*) as cnt, SUM(amount_due) as sum FROM invoices WHERE tenant_id=? AND status IN ('sent','partial','overdue') AND due_date<date('now','-90 days')").bind(t).first(),
    ]);
    return json({
      current: { count: (current as any)?.cnt||0, amount: (current as any)?.sum||0 },
      '1-30_days': { count: (d30 as any)?.cnt||0, amount: (d30 as any)?.sum||0 },
      '31-60_days': { count: (d60 as any)?.cnt||0, amount: (d60 as any)?.sum||0 },
      '61-90_days': { count: (d90 as any)?.cnt||0, amount: (d90 as any)?.sum||0 },
      'over_90_days': { count: (over90 as any)?.cnt||0, amount: (over90 as any)?.sum||0 },
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/reports/aging', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/reports/profit-loss', async (c) => {
  try {
    const t = tid(c); const from = c.req.query('from') || new Date(Date.now()-90*86400000).toISOString().split('T')[0]; const to = c.req.query('to') || new Date().toISOString().split('T')[0];
    const [income, expenses] = await Promise.all([
      c.env.DB.prepare('SELECT SUM(amount) as sum FROM payments WHERE tenant_id=? AND payment_date>=? AND payment_date<=?').bind(t, from, to).first(),
      c.env.DB.prepare('SELECT SUM(amount) as sum FROM expenses WHERE tenant_id=? AND expense_date>=? AND expense_date<=?').bind(t, from, to).first(),
    ]);
    const expByCat = await c.env.DB.prepare('SELECT category, SUM(amount) as total FROM expenses WHERE tenant_id=? AND expense_date>=? AND expense_date<=? GROUP BY category ORDER BY total DESC').bind(t, from, to).all();
    return json({
      period: { from, to },
      income: (income as any)?.sum || 0,
      expenses: (expenses as any)?.sum || 0,
      net_profit: ((income as any)?.sum || 0) - ((expenses as any)?.sum || 0),
      expense_breakdown: expByCat.results,
    });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/reports/profit-loss', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/reports/revenue-by-client', async (c) => {
  try {
    const t = tid(c);
    const r = await c.env.DB.prepare("SELECT c.id, c.name, c.company, COUNT(i.id) as invoice_count, SUM(i.total) as total_invoiced, SUM(i.amount_paid) as total_paid, SUM(i.amount_due) as total_outstanding FROM clients c LEFT JOIN invoices i ON c.id=i.client_id AND i.status!='void' WHERE c.tenant_id=? GROUP BY c.id ORDER BY total_invoiced DESC LIMIT 50").bind(t).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/reports/revenue-by-client', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.get('/reports/monthly-revenue', async (c) => {
  try {
    const t = tid(c);
    const r = await c.env.DB.prepare("SELECT strftime('%Y-%m', payment_date) as month, SUM(amount) as revenue, COUNT(*) as payment_count FROM payments WHERE tenant_id=? AND payment_date>=date('now','-12 months') GROUP BY month ORDER BY month").bind(t).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/reports/monthly-revenue', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ AI FEATURES ═══════════════
app.post('/ai/late-payment-risk', async (c) => {
  try {
    const t = tid(c); const b = await c.req.json();
    // Gather client payment history
    const client = await c.env.DB.prepare('SELECT * FROM clients WHERE id=? AND tenant_id=?').bind(b.client_id, t).first() as any;
    if (!client) return json({ error: 'Client not found' }, 404);
    const history = await c.env.DB.prepare("SELECT invoice_number, total, amount_due, status, issue_date, due_date, paid_date, julianday(paid_date)-julianday(due_date) as days_late FROM invoices WHERE client_id=? AND tenant_id=? AND status IN ('paid','partial','overdue') ORDER BY issue_date DESC LIMIT 20").bind(b.client_id, t).all();
    try {
      const aiRes = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine_id: 'FN-01', query: `Analyze late payment risk for client: ${client.name}. Avg days to pay: ${client.avg_days_to_pay || 'unknown'}. Total outstanding: $${client.total_outstanding}. Payment history: ${JSON.stringify(history.results?.slice(0,10))}. Provide risk score (1-10), probability of late payment, and recommended action.` }),
      });
      const ai = await aiRes.json() as any;
      return json({ client_name: client.name, analysis: ai.response || ai });
    } catch { return json({ client_name: client.name, analysis: 'AI unavailable', avg_days_to_pay: client.avg_days_to_pay, total_outstanding: client.total_outstanding }); }
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/ai/late-payment-risk', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

app.post('/ai/invoice-optimization', async (c) => {
  try {
    const t = tid(c);
    const stats = await c.env.DB.prepare("SELECT AVG(julianday(paid_date)-julianday(issue_date)) as avg_days_to_pay, AVG(julianday(paid_date)-julianday(due_date)) as avg_days_past_due, COUNT(CASE WHEN julianday(paid_date)>julianday(due_date) THEN 1 END)*100.0/COUNT(*) as late_pct FROM invoices WHERE tenant_id=? AND status='paid' AND paid_date IS NOT NULL").bind(t).first();
    try {
      const aiRes = await c.env.ENGINE_RUNTIME.fetch('https://engine/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine_id: 'FN-01', query: `Analyze invoicing patterns and suggest optimizations. Stats: avg days to pay: ${(stats as any)?.avg_days_to_pay?.toFixed(1)}, late payment rate: ${(stats as any)?.late_pct?.toFixed(1)}%, avg days past due: ${(stats as any)?.avg_days_past_due?.toFixed(1)}. Suggest: optimal payment terms, early payment discount strategy, reminder timing, and invoice wording improvements.` }),
      });
      const ai = await aiRes.json() as any;
      return json({ stats, recommendations: ai.response || ai });
    } catch { return json({ stats, recommendations: 'AI unavailable' }); }
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/ai/invoice-optimization', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ ACTIVITY LOG ═══════════════
app.get('/activity', async (c) => {
  try {
    const t = tid(c); const entity = c.req.query('entity_type'); const eid = c.req.query('entity_id');
    let q = 'SELECT * FROM activity_log WHERE tenant_id=?'; const params: string[] = [t];
    if (entity) { q += ' AND entity_type=?'; params.push(entity); }
    if (eid) { q += ' AND entity_id=?'; params.push(eid); }
    q += ' ORDER BY created_at DESC LIMIT 100';
    const r = await c.env.DB.prepare(q).bind(...params).all();
    return json(r.results);
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/activity', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ═══════════════ CRON: OVERDUE + RECURRING ═══════════════
app.get('/__cron', async (c) => {
  const apiKey = c.req.header('X-Echo-API-Key') || '';
  const bearer = (c.req.header('Authorization') || '').replace('Bearer ', '');
  const expected = c.env.ECHO_API_KEY;
  if (!expected || (apiKey !== expected && bearer !== expected)) {
    return json({ error: 'Unauthorized' }, 401);
  }
  try {
    const results: string[] = [];
    // Mark overdue invoices
    const overdue = await c.env.DB.prepare("UPDATE invoices SET status='overdue',updated_at=datetime('now') WHERE status IN ('sent','partial') AND due_date<date('now')").run();
    results.push(`Marked ${overdue.meta.changes} invoices overdue`);

    // Generate recurring invoices
    const recurrings = await c.env.DB.prepare("SELECT * FROM recurring_invoices WHERE status='active' AND next_date<=date('now')").bind().all();
    for (const rec of recurrings.results as any[]) {
      const tenant = await c.env.DB.prepare('SELECT invoice_prefix, next_invoice_number, payment_terms_days FROM tenants WHERE id=?').bind(rec.tenant_id).first() as any;
      if (!tenant) continue;
      const invoiceNumber = `${tenant.invoice_prefix}-${String(tenant.next_invoice_number).padStart(5, '0')}`;
      const invId = uid();
      const today = new Date().toISOString().split('T')[0];
      const dueDate = new Date(Date.now() + (tenant.payment_terms_days||30)*86400000).toISOString().split('T')[0];
      const items = JSON.parse(rec.items_json || '[]');
      let subtotal = 0;
      await c.env.DB.prepare(`INSERT INTO invoices (id,tenant_id,client_id,invoice_number,status,issue_date,due_date,subtotal,tax_rate,total,amount_due,is_recurring,recurring_id) VALUES (?,?,?,?,'draft',?,?,0,?,0,0,1,?)`)
        .bind(invId, rec.tenant_id, rec.client_id, invoiceNumber, today, dueDate, rec.tax_rate||0, rec.id).run();
      let totalTax = 0;
      for (const item of items) {
        const amount = (item.quantity||1) * (item.unit_price||0);
        const itemTaxRate = item.tax_rate ?? rec.tax_rate ?? 0;
        const itemTaxAmt = amount * (itemTaxRate / 100);
        subtotal += amount;
        totalTax += itemTaxAmt;
        await c.env.DB.prepare('INSERT INTO invoice_items (id,invoice_id,tenant_id,description,quantity,unit_price,amount,tax_rate,tax_amount) VALUES (?,?,?,?,?,?,?,?,?)')
          .bind(uid(), invId, rec.tenant_id, item.description, item.quantity||1, item.unit_price||0, amount, itemTaxRate, itemTaxAmt).run();
      }
      const total = subtotal + totalTax;
      await c.env.DB.prepare('UPDATE invoices SET subtotal=?,tax_amount=?,total=?,amount_due=? WHERE id=?').bind(subtotal, totalTax, total, total, invId).run();
      // Advance next_date
      const nextDate = advanceDate(rec.next_date, rec.frequency, rec.interval_value||1);
      const newStatus = rec.end_date && nextDate > rec.end_date ? 'completed' : 'active';
      await c.env.DB.prepare('UPDATE recurring_invoices SET next_date=?,status=?,invoices_generated=invoices_generated+1,last_generated_at=datetime(\'now\'),updated_at=datetime(\'now\') WHERE id=?')
        .bind(nextDate, newStatus, rec.id).run();
      await c.env.DB.prepare('UPDATE tenants SET next_invoice_number=next_invoice_number+1 WHERE id=?').bind(rec.tenant_id).run();
      results.push(`Generated recurring invoice ${invoiceNumber} for ${rec.client_id}`);
    }

    // Apply late fees
    const lateFeeInvoices = await c.env.DB.prepare("SELECT i.id, i.tenant_id, i.amount_due, t.late_fee_percent FROM invoices i JOIN tenants t ON i.tenant_id=t.id WHERE i.status='overdue' AND i.late_fee_applied=0 AND t.late_fee_percent>0 AND i.due_date<date('now','-7 days')").bind().all();
    for (const inv of lateFeeInvoices.results as any[]) {
      const fee = inv.amount_due * (inv.late_fee_percent / 100);
      await c.env.DB.prepare('UPDATE invoices SET late_fee_applied=?,total=total+?,amount_due=amount_due+?,updated_at=datetime(\'now\') WHERE id=?').bind(fee, fee, fee, inv.id).run();
      results.push(`Applied $${fee.toFixed(2)} late fee to invoice ${inv.id}`);
    }

    return json({ cron: 'complete', results });
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: '/__cron', error: e?.message }));
    return c.json({ error: 'Database error' }, 500);
  }
});

// ── Helper functions ──
async function recalcInvoice(db: D1Database, invoiceId: string, tenantId: string) {
  try {
    const items = await db.prepare('SELECT SUM(amount) as subtotal, SUM(tax_amount) as tax_total FROM invoice_items WHERE invoice_id=?').bind(invoiceId).first() as any;
    const inv = await db.prepare('SELECT discount_percent, shipping, amount_paid FROM invoices WHERE id=? AND tenant_id=?').bind(invoiceId, tenantId).first() as any;
    if (!inv) return;
    const subtotal = items?.subtotal || 0;
    const taxAmount = items?.tax_total || 0;
    const discountAmount = subtotal * ((inv.discount_percent||0) / 100);
    const total = subtotal + taxAmount - discountAmount + (inv.shipping||0);
    const amountDue = Math.max(0, total - (inv.amount_paid||0));
    await db.prepare('UPDATE invoices SET subtotal=?,tax_amount=?,discount_amount=?,total=?,amount_due=?,updated_at=datetime(\'now\') WHERE id=?')
      .bind(subtotal, taxAmount, discountAmount, total, amountDue, invoiceId).run();
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: 'recalcInvoice', error: e?.message }));
    throw e;
  }
}

async function updateClientTotals(db: D1Database, tenantId: string, clientId: string) {
  try {
    const stats = await db.prepare("SELECT SUM(total) as invoiced, SUM(amount_paid) as paid, SUM(amount_due) as outstanding, AVG(CASE WHEN paid_date IS NOT NULL THEN julianday(paid_date)-julianday(issue_date) END) as avg_days FROM invoices WHERE client_id=? AND tenant_id=? AND status!='void'").bind(clientId, tenantId).first() as any;
    await db.prepare('UPDATE clients SET total_invoiced=?,total_paid=?,total_outstanding=?,avg_days_to_pay=?,last_payment_at=datetime(\'now\'),updated_at=datetime(\'now\') WHERE id=? AND tenant_id=?')
      .bind(stats?.invoiced||0, stats?.paid||0, stats?.outstanding||0, stats?.avg_days||null, clientId, tenantId).run();
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: 'updateClientTotals', error: e?.message }));
    throw e;
  }
}

async function logActivity(db: D1Database, tenantId: string, entityType: string, entityId: string, action: string, details: string) {
  try {
    await db.prepare('INSERT INTO activity_log (id,tenant_id,entity_type,entity_id,action,details,created_at) VALUES (?,?,?,?,?,?,datetime(\'now\'))')
      .bind(uid(), tenantId, entityType, entityId, action, details).run();
  } catch (e: any) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: 'logActivity', error: e?.message }));
    throw e;
  }
}

function advanceDate(dateStr: string, frequency: string, interval: number): string {
  const d = new Date(dateStr);
  switch (frequency) {
    case 'weekly': d.setDate(d.getDate() + 7 * interval); break;
    case 'biweekly': d.setDate(d.getDate() + 14 * interval); break;
    case 'monthly': d.setMonth(d.getMonth() + interval); break;
    case 'quarterly': d.setMonth(d.getMonth() + 3 * interval); break;
    case 'yearly': d.setFullYear(d.getFullYear() + interval); break;
    default: d.setMonth(d.getMonth() + interval);
  }
  return d.toISOString().split('T')[0];
}

// ── Error handlers ──
app.onError((err, c) => {
  if (err.message?.includes('JSON')) {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }
  console.error(`[echo-invoice] ${err.message}`);
  return c.json({ error: 'Internal server error' }, 500);
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

// ── Scheduled handler ──
export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const app2 = new Hono<{ Bindings: Env }>();
    app2.get('/__cron', app.fetch);
    ctx.waitUntil(fetch(new Request('https://dummy/__cron'), { headers: {} }).catch(() => {}));
    // Direct cron execution
    try {
      const results: string[] = [];
      const overdue = await env.DB.prepare("UPDATE invoices SET status='overdue',updated_at=datetime('now') WHERE status IN ('sent','partial') AND due_date<date('now')").run();
      results.push(`Marked ${overdue.meta.changes} invoices overdue`);
      // Generate recurring
      const recs = await env.DB.prepare("SELECT * FROM recurring_invoices WHERE status='active' AND next_date<=date('now')").all();
      for (const rec of recs.results as any[]) {
        const tenant = await env.DB.prepare('SELECT invoice_prefix, next_invoice_number, payment_terms_days FROM tenants WHERE id=?').bind(rec.tenant_id).first() as any;
        if (!tenant) continue;
        const invNum = `${tenant.invoice_prefix}-${String(tenant.next_invoice_number).padStart(5, '0')}`;
        const invId = uid();
        const today = new Date().toISOString().split('T')[0];
        const due = new Date(Date.now() + (tenant.payment_terms_days||30)*86400000).toISOString().split('T')[0];
        const items = JSON.parse(rec.items_json || '[]');
        let sub = 0;
        await env.DB.prepare(`INSERT INTO invoices (id,tenant_id,client_id,invoice_number,status,issue_date,due_date,subtotal,tax_rate,total,amount_due,is_recurring,recurring_id) VALUES (?,?,?,?,'draft',?,?,0,?,0,0,1,?)`)
          .bind(invId, rec.tenant_id, rec.client_id, invNum, today, due, rec.tax_rate||0, rec.id).run();
        let subTax = 0;
        for (const it of items) {
          const amt = (it.quantity||1)*(it.unit_price||0);
          const itTaxRate = it.tax_rate ?? rec.tax_rate ?? 0;
          const itTaxAmt = amt * (itTaxRate / 100);
          sub += amt; subTax += itTaxAmt;
          await env.DB.prepare('INSERT INTO invoice_items (id,invoice_id,tenant_id,description,quantity,unit_price,amount,tax_rate,tax_amount) VALUES (?,?,?,?,?,?,?,?,?)')
            .bind(uid(), invId, rec.tenant_id, it.description, it.quantity||1, it.unit_price||0, amt, itTaxRate, itTaxAmt).run();
        }
        const tot = sub+subTax;
        await env.DB.prepare('UPDATE invoices SET subtotal=?,tax_amount=?,total=?,amount_due=? WHERE id=?').bind(sub,subTax,tot,tot,invId).run();
        const next = advanceDate(rec.next_date, rec.frequency, rec.interval_value||1);
        await env.DB.prepare("UPDATE recurring_invoices SET next_date=?,status=CASE WHEN ?!='' AND ?>? THEN 'completed' ELSE 'active' END,invoices_generated=invoices_generated+1,last_generated_at=datetime('now') WHERE id=?")
          .bind(next, rec.end_date||'', next, rec.end_date||'9999-12-31', rec.id).run();
        await env.DB.prepare('UPDATE tenants SET next_invoice_number=next_invoice_number+1 WHERE id=?').bind(rec.tenant_id).run();
      }
      console.log(JSON.stringify({ event: 'cron', results }));
    } catch (e: any) {
      console.error(JSON.stringify({ ts: new Date().toISOString(), level: 'error', worker: 'echo-invoice', message: 'D1 query failed', endpoint: 'scheduled', error: e?.message }));
    }
  },
};
