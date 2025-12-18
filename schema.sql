-- customers
CREATE TABLE IF NOT EXISTS customers (
  id BIGSERIAL PRIMARY KEY,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  email TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- services
CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price_eur NUMERIC(10,2) NOT NULL,
  duration_minutes INT NOT NULL
);

-- bookings
CREATE TABLE IF NOT EXISTS bookings (
  id TEXT PRIMARY KEY,
  salon_id TEXT NOT NULL,
  salon_name TEXT NOT NULL,
  salon_address TEXT NOT NULL,

  customer_id BIGINT NOT NULL REFERENCES customers(id),

  service_id TEXT NOT NULL REFERENCES services(id),
  service_name TEXT NOT NULL,
  total_price_eur NUMERIC(10,2) NOT NULL,
  deposit_required_eur NUMERIC(10,2) NOT NULL,

  appointment_at TIMESTAMPTZ NOT NULL,

  payment_method TEXT NOT NULL,
  status TEXT NOT NULL,
  deposit_paid BOOLEAN NOT NULL DEFAULT false,

  paypal_order_id TEXT,
  stripe_session_id TEXT,

  notes_for_stylist TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- sms jobs
CREATE TABLE IF NOT EXISTS sms_jobs (
  id BIGSERIAL PRIMARY KEY,
  booking_id TEXT NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
  phone TEXT NOT NULL,
  message TEXT NOT NULL,
  send_at TIMESTAMPTZ NOT NULL,
  sent_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'PENDING'
);

CREATE INDEX IF NOT EXISTS idx_sms_jobs_send_at ON sms_jobs(send_at);
