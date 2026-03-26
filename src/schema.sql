-- Echo Invoice v1.0.0 Schema
-- AI-powered invoicing and billing system

CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  address TEXT,
  city TEXT,
  state TEXT,
  zip TEXT,
  country TEXT DEFAULT 'US',
  tax_id TEXT,
  logo_url TEXT,
  currency TEXT DEFAULT 'USD',
  payment_terms_days INTEGER DEFAULT 30,
  late_fee_percent REAL DEFAULT 0,
  invoice_prefix TEXT DEFAULT 'INV',
  next_invoice_number INTEGER DEFAULT 1001,
  bank_name TEXT,
  bank_account TEXT,
  bank_routing TEXT,
  paypal_email TEXT,
  stripe_account_id TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  company TEXT,
  email TEXT,
  phone TEXT,
  address TEXT,
  city TEXT,
  state TEXT,
  zip TEXT,
  country TEXT DEFAULT 'US',
  tax_id TEXT,
  currency TEXT DEFAULT 'USD',
  payment_terms_days INTEGER,
  notes TEXT,
  total_invoiced REAL DEFAULT 0,
  total_paid REAL DEFAULT 0,
  total_outstanding REAL DEFAULT 0,
  avg_days_to_pay REAL,
  last_invoice_at TEXT,
  last_payment_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_clients_tenant ON clients(tenant_id);
CREATE INDEX IF NOT EXISTS idx_clients_email ON clients(tenant_id, email);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  invoice_number TEXT NOT NULL,
  status TEXT DEFAULT 'draft',
  issue_date TEXT DEFAULT (date('now')),
  due_date TEXT,
  paid_date TEXT,
  subtotal REAL DEFAULT 0,
  tax_rate REAL DEFAULT 0,
  tax_amount REAL DEFAULT 0,
  discount_percent REAL DEFAULT 0,
  discount_amount REAL DEFAULT 0,
  shipping REAL DEFAULT 0,
  total REAL DEFAULT 0,
  amount_paid REAL DEFAULT 0,
  amount_due REAL DEFAULT 0,
  currency TEXT DEFAULT 'USD',
  notes TEXT,
  terms TEXT,
  footer TEXT,
  po_number TEXT,
  is_recurring INTEGER DEFAULT 0,
  recurring_id TEXT,
  sent_at TEXT,
  viewed_at TEXT,
  reminder_sent_at TEXT,
  reminder_count INTEGER DEFAULT 0,
  late_fee_applied REAL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE INDEX IF NOT EXISTS idx_invoices_tenant ON invoices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invoices_client ON invoices(tenant_id, client_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_invoices_due ON invoices(tenant_id, due_date);
CREATE INDEX IF NOT EXISTS idx_invoices_number ON invoices(tenant_id, invoice_number);

CREATE TABLE IF NOT EXISTS invoice_items (
  id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  description TEXT NOT NULL,
  quantity REAL DEFAULT 1,
  unit_price REAL DEFAULT 0,
  amount REAL DEFAULT 0,
  tax_rate REAL DEFAULT 0,
  tax_amount REAL DEFAULT 0,
  discount_percent REAL DEFAULT 0,
  sort_order INTEGER DEFAULT 0,
  product_id TEXT,
  FOREIGN KEY (invoice_id) REFERENCES invoices(id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_items_invoice ON invoice_items(invoice_id);

CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  amount REAL NOT NULL,
  method TEXT DEFAULT 'other',
  reference TEXT,
  notes TEXT,
  payment_date TEXT DEFAULT (date('now')),
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (invoice_id) REFERENCES invoices(id),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE INDEX IF NOT EXISTS idx_payments_tenant ON payments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_payments_invoice ON payments(invoice_id);
CREATE INDEX IF NOT EXISTS idx_payments_client ON payments(tenant_id, client_id);

CREATE TABLE IF NOT EXISTS recurring_invoices (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  frequency TEXT NOT NULL DEFAULT 'monthly',
  interval_value INTEGER DEFAULT 1,
  next_date TEXT NOT NULL,
  end_date TEXT,
  status TEXT DEFAULT 'active',
  items_json TEXT NOT NULL,
  subtotal REAL DEFAULT 0,
  tax_rate REAL DEFAULT 0,
  notes TEXT,
  terms TEXT,
  invoices_generated INTEGER DEFAULT 0,
  last_generated_at TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE INDEX IF NOT EXISTS idx_recurring_tenant ON recurring_invoices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_recurring_next ON recurring_invoices(status, next_date);

CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  category TEXT NOT NULL,
  vendor TEXT,
  description TEXT,
  amount REAL NOT NULL,
  tax_amount REAL DEFAULT 0,
  currency TEXT DEFAULT 'USD',
  expense_date TEXT DEFAULT (date('now')),
  receipt_url TEXT,
  is_billable INTEGER DEFAULT 0,
  client_id TEXT,
  invoice_id TEXT,
  payment_method TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_expenses_tenant ON expenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(tenant_id, expense_date);
CREATE INDEX IF NOT EXISTS idx_expenses_category ON expenses(tenant_id, category);
CREATE INDEX IF NOT EXISTS idx_expenses_client ON expenses(tenant_id, client_id);

CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  unit_price REAL DEFAULT 0,
  tax_rate REAL DEFAULT 0,
  unit TEXT DEFAULT 'unit',
  sku TEXT,
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_products_tenant ON products(tenant_id);

CREATE TABLE IF NOT EXISTS estimates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  estimate_number TEXT NOT NULL,
  status TEXT DEFAULT 'draft',
  issue_date TEXT DEFAULT (date('now')),
  expiry_date TEXT,
  subtotal REAL DEFAULT 0,
  tax_rate REAL DEFAULT 0,
  tax_amount REAL DEFAULT 0,
  discount_percent REAL DEFAULT 0,
  discount_amount REAL DEFAULT 0,
  total REAL DEFAULT 0,
  notes TEXT,
  terms TEXT,
  converted_invoice_id TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE INDEX IF NOT EXISTS idx_estimates_tenant ON estimates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_estimates_client ON estimates(tenant_id, client_id);
CREATE INDEX IF NOT EXISTS idx_estimates_status ON estimates(tenant_id, status);

CREATE TABLE IF NOT EXISTS estimate_items (
  id TEXT PRIMARY KEY,
  estimate_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  description TEXT NOT NULL,
  quantity REAL DEFAULT 1,
  unit_price REAL DEFAULT 0,
  amount REAL DEFAULT 0,
  sort_order INTEGER DEFAULT 0,
  product_id TEXT,
  FOREIGN KEY (estimate_id) REFERENCES estimates(id)
);
CREATE INDEX IF NOT EXISTS idx_est_items_est ON estimate_items(estimate_id);

CREATE TABLE IF NOT EXISTS tax_rates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  rate REAL NOT NULL,
  is_compound INTEGER DEFAULT 0,
  is_default INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_tax_rates_tenant ON tax_rates(tenant_id);

CREATE TABLE IF NOT EXISTS credits (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  amount REAL NOT NULL,
  reason TEXT,
  applied_to_invoice TEXT,
  status TEXT DEFAULT 'available',
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id),
  FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE INDEX IF NOT EXISTS idx_credits_tenant ON credits(tenant_id);
CREATE INDEX IF NOT EXISTS idx_credits_client ON credits(tenant_id, client_id);

CREATE TABLE IF NOT EXISTS activity_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_activity_tenant ON activity_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_activity_entity ON activity_log(tenant_id, entity_type, entity_id);
