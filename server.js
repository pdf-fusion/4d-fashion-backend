import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import Stripe from "stripe";
import pg from "pg";
import cron from "node-cron";
import Twilio from "twilio";
import { DateTime } from "luxon";

dotenv.config();

const app = express();

/** =========================================================
 *  0) Stripe webhook RAW (important)
 *  ========================================================= */
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

/** =========================================================
 *  1) Postgres
 *  ========================================================= */
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("render.com") ? { rejectUnauthorized: false } : undefined,
});

/** =========================================================
 *  2) Twilio
 *  ========================================================= */
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || "";
const TWILIO_FROM_NUMBER = process.env.TWILIO_FROM_NUMBER || "";
const twilio =
  TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN ? Twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;

/** =========================================================
 *  3) Config
 *  ========================================================= */
const PORT = process.env.PORT || 4000;

const API_BASE = (process.env.API_BASE || "").replace(/\/+$/, "");
const FRONTEND_SUCCESS_URL = (process.env.FRONTEND_SUCCESS_URL || "").replace(/\/+$/, "");
const FRONTEND_CANCEL_URL = (process.env.FRONTEND_CANCEL_URL || "").replace(/\/+$/, "");

// PayPal
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || "";
const PAYPAL_API_BASE = (process.env.PAYPAL_API_BASE || "https://api-m.sandbox.paypal.com").replace(
  /\/+$/,
  ""
);

// Admin API token
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

// Deep link scheme
const APP_DEEP_LINK_SCHEME = "4dfashion://booking?bookingId=";

// Play Store fallback
const PLAY_STORE_URL =
  process.env.PLAY_STORE_URL ||
  "https://play.google.com/store/apps/details?id=com.debeng.a4dfashionservices";

// ✅ Numéro du salon (notification instantanée)
const SALON_NOTIFY_PHONE = process.env.SALON_NOTIFY_PHONE || "+32465136027";

const BookingStatus = {
  PENDING_DEPOSIT: "PENDING_DEPOSIT",
  CONFIRMED: "CONFIRMED",
  CANCELLED: "CANCELLED",
  NO_SHOW: "NO_SHOW",
};

/** =========================================================
 *  4) Stripe webhook endpoint (raw body BEFORE json middleware)
 *  ========================================================= */
app.post("/payments/webhook/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    if (!stripe) return res.status(500).send("Stripe not configured");
    const sig = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) return res.status(500).send("Missing STRIPE_WEBHOOK_SECRET");

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
      console.error("❌ Stripe signature failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const bookingId = session.metadata?.bookingId;
      if (bookingId) await markBookingConfirmed(bookingId, { stripeSessionId: session.id });
    }

    return res.json({ received: true });
  } catch (e) {
    console.error("Stripe webhook error:", e);
    return res.status(500).json({ error: "Stripe webhook internal error" });
  }
});

// JSON for all other routes
app.use(express.json());

/** =========================================================
 *  5) Utils
 *  ========================================================= */
function round2(n) {
  return Math.round(Number(n) * 100) / 100;
}

function assertValidUrl(u, name) {
  try {
    new URL(u);
  } catch {
    throw new Error(`${name} is not a valid URL`);
  }
}

// ✅ Normalise BE phone to E.164
function normalizeBePhone(phoneRaw) {
  const p = String(phoneRaw || "").trim().replace(/\s+/g, "");
  if (!p) return "";
  if (p.startsWith("+")) return p;
  if (p.startsWith("00")) return "+" + p.slice(2);
  if (p.startsWith("0")) return "+32" + p.slice(1);
  return p;
}

function escapeHtml(str = "") {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatBrusselsFromDate(dateObj) {
  try {
    const dt = DateTime.fromJSDate(dateObj, { zone: "Europe/Brussels" });
    return dt.isValid ? dt.toFormat("dd/LL/yyyy 'à' HH:mm") : String(dateObj);
  } catch {
    return String(dateObj);
  }
}

function moneyEUR(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "-";
  return n.toFixed(2) + " €";
}

function applyTemplate(tpl, vars) {
  return String(tpl || "").replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? ""));
}

/** =========================================================
 *  6) Services seed
 *  ========================================================= */
const SERVICE_SEED = [
  { id: "DREADLOCKS", name: "Dreadlocks", category: "Coiffure", priceEur: 120.0, durationMinutes: 180 },
  { id: "HAIR_STRAIGHTENING", name: "Lissage de cheveux", category: "Soins capillaires", priceEur: 90.0, durationMinutes: 120 },
  { id: "HAIR_COLORING", name: "Coloration capillaire", category: "Coloration", priceEur: 85.0, durationMinutes: 120 },
  { id: "SHAMPOO", name: "Shampoing", category: "Soins capillaires", priceEur: 15.0, durationMinutes: 30 },

  { id: "BRAIDS_SMALL", name: "Tresses Small", category: "Coiffure femme africaine", priceEur: 120.0, durationMinutes: 180 },
  { id: "BRAIDS_MEDIUM", name: "Tresses Medium", category: "Coiffure femme africaine", priceEur: 80.0, durationMinutes: 150 },
  { id: "BRAIDS_LARGE", name: "Tresses Large", category: "Coiffure femme africaine", priceEur: 60.0, durationMinutes: 120 },
  { id: "WIG_INSTALL", name: "Pose Perruque", category: "Coiffure", priceEur: 70.0, durationMinutes: 90 },
  { id: "LOCKS_RETOUCH", name: "Retouche Locks", category: "Coiffure", priceEur: 65.0, durationMinutes: 90 },

  { id: "BRAIDS_RETOUCH_MEN", name: "Retouche tresse homme", category: "Coiffure", priceEur: 2.5, durationMinutes: 15 },
];

async function ensureDbColumns() {
  await pool.query("ALTER TABLE services ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;");
  await pool.query("ALTER TABLE sms_jobs ADD COLUMN IF NOT EXISTS error TEXT;");
  await pool.query("ALTER TABLE sms_jobs ADD COLUMN IF NOT EXISTS kind TEXT;");
  await pool.query("CREATE INDEX IF NOT EXISTS idx_sms_jobs_kind ON sms_jobs(kind);");
}

async function upsertServices() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const s of SERVICE_SEED) {
      await client.query(
        `INSERT INTO services (id, name, category, price_eur, duration_minutes, is_active)
         VALUES ($1,$2,$3,$4,$5, TRUE)
         ON CONFLICT (id) DO UPDATE SET
           name=EXCLUDED.name,
           category=EXCLUDED.category,
           price_eur=EXCLUDED.price_eur,
           duration_minutes=EXCLUDED.duration_minutes`,
        [s.id, s.name, s.category, s.priceEur, s.durationMinutes]
      );
    }
    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("upsertServices failed:", e);
  } finally {
    client.release();
  }
}

/** =========================================================
 *  7) PayPal helpers
 *  ========================================================= */
async function getPayPalAccessToken() {
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64");
  const res = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  if (!res.ok) throw new Error("PayPal token error: " + (await res.text()));
  return (await res.json()).access_token;
}

async function createPayPalOrder({ bookingId, amount, currency }) {
  if (!API_BASE) throw new Error("API_BASE missing");
  const accessToken = await getPayPalAccessToken();

  const returnUrl = `${API_BASE}/payments/paypal/return?bookingId=${encodeURIComponent(bookingId)}`;
  const cancelUrl = `${API_BASE}/payments/paypal/cancel?bookingId=${encodeURIComponent(bookingId)}`;

  const res = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      intent: "CAPTURE",
      purchase_units: [
        { reference_id: bookingId, amount: { currency_code: currency, value: Number(amount).toFixed(2) } },
      ],
      application_context: {
        brand_name: "4D FASHION SERVICES SRL",
        return_url: returnUrl,
        cancel_url: cancelUrl,
        user_action: "PAY_NOW",
      },
    }),
  });

  if (!res.ok) throw new Error("PayPal create order error: " + (await res.text()));
  const data = await res.json();
  const approve = data.links?.find((l) => l.rel === "approve")?.href;
  if (!approve) throw new Error("PayPal approve link not found");
  return { orderId: data.id, approveUrl: approve };
}

async function capturePayPalOrder(orderId) {
  const accessToken = await getPayPalAccessToken();
  const res = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders/${orderId}/capture`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error("PayPal capture error: " + (await res.text()));
  return res.json();
}

/** =========================================================
 *  8) Stripe Bancontact
 *  ========================================================= */
async function createBancontactCheckout({ bookingId, amount }) {
  if (!stripe) throw new Error("Stripe not configured");
  assertValidUrl(FRONTEND_SUCCESS_URL, "FRONTEND_SUCCESS_URL");
  assertValidUrl(FRONTEND_CANCEL_URL, "FRONTEND_CANCEL_URL");

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["bancontact"],
    mode: "payment",
    line_items: [
      {
        quantity: 1,
        price_data: {
          currency: "eur",
          unit_amount: Math.round(Number(amount) * 100),
          product_data: { name: "Acompte rendez-vous 4D Fashion (20%)" },
        },
      },
    ],
    metadata: { bookingId },
    success_url: `${FRONTEND_SUCCESS_URL}?bookingId=${encodeURIComponent(bookingId)}`,
    cancel_url: `${FRONTEND_CANCEL_URL}?bookingId=${encodeURIComponent(bookingId)}`,
  });

  return { sessionId: session.id, url: session.url };
}

/** =========================================================
 *  9) Core DB actions
 *  ========================================================= */
async function getOrCreateCustomer({ firstName, lastName, phoneNumber, email }) {
  const phone = normalizeBePhone(phoneNumber);

  const client = await pool.connect();
  try {
    const existing = await client.query(
      "SELECT id, phone FROM customers WHERE phone=$1 OR phone=$2 LIMIT 1",
      [phone, phoneNumber]
    );

    if (existing.rowCount > 0) {
      const id = existing.rows[0].id;
      const storedPhone = existing.rows[0].phone;
      if (storedPhone !== phone) {
        await client.query("UPDATE customers SET phone=$2 WHERE id=$1", [id, phone]);
      }
      return id;
    }

    const ins = await client.query(
      `INSERT INTO customers (first_name, last_name, phone, email)
       VALUES ($1,$2,$3,$4) RETURNING id`,
      [firstName, lastName, phone, email || null]
    );
    return ins.rows[0].id;
  } finally {
    client.release();
  }
}

async function getService(serviceId) {
  const { rows } = await pool.query("SELECT * FROM services WHERE id=$1", [serviceId]);
  return rows[0] || null;
}

async function createBookingRow({ bookingId, salonId, customerId, service, appointmentAtUtcIso, paymentMethod, notes }) {
  const total = round2(service.price_eur);
  const deposit = round2(total * 0.2);

  await pool.query(
    `INSERT INTO bookings (
      id, salon_id, salon_name, salon_address,
      customer_id, service_id, service_name,
      total_price_eur, deposit_required_eur, appointment_at,
      payment_method, status, deposit_paid, notes_for_stylist
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,false,$13)`,
    [
      bookingId,
      salonId || "4D-FASHION-SERVICES-SRL",
      "4D FASHION SERVICES SRL",
      "RUE DES CAPUCINS 64, 7000 MONS, BELGIQUE",
      customerId,
      service.id,
      service.name,
      total,
      deposit,
      appointmentAtUtcIso,
      paymentMethod,
      BookingStatus.PENDING_DEPOSIT,
      notes || null,
    ]
  );

  return { totalPriceEur: total, depositRequiredEur: deposit };
}

/** =========================================================
 *  10) SMS logic
 *  ========================================================= */
async function sendSmsNow(to, body) {
  if (!twilio || !TWILIO_FROM_NUMBER) return;
  const toNorm = normalizeBePhone(to);
  if (!toNorm) return;

  if (normalizeBePhone(TWILIO_FROM_NUMBER) === toNorm) {
    throw new Error("'To' and 'From' number cannot be the same");
  }

  await twilio.messages.create({
    from: TWILIO_FROM_NUMBER,
    to: toNorm,
    body,
  });
}

async function scheduleSmsJobs(bookingId) {
  const { rows } = await pool.query(
    `SELECT b.id, b.appointment_at, c.phone, c.first_name, c.last_name, b.service_name
     FROM bookings b
     JOIN customers c ON c.id=b.customer_id
     WHERE b.id=$1`,
    [bookingId]
  );
  if (!rows[0]) return;

  const appointmentAt = rows[0].appointment_at;
  const phone = normalizeBePhone(rows[0].phone);
  const firstName = rows[0].first_name || "";
  const serviceName = rows[0].service_name || "Rendez-vous";

  const appt = DateTime.fromJSDate(appointmentAt, { zone: "Europe/Brussels" });
  const remind1 = appt.minus({ hours: 24 }).toUTC().toISO();
  const remind2 = appt.minus({ hours: 5 }).toUTC().toISO();

  const vars = {
    firstName,
    service: serviceName,
    date: appt.toFormat("dd/LL/yyyy"),
    time: appt.toFormat("HH:mm"),
    address: "Rue des Capucins 64, 7000 Mons",
  };

  const tplJ1 = process.env.SMS_TEMPLATE_J1 || "4D FASHION – Rappel J-1 : {service} le {date} à {time}. Adresse : {address}.";
  const tplH5 = process.env.SMS_TEMPLATE_H5 || "4D FASHION – Rappel H-5 : {service} le {date} à {time}. Adresse : {address}.";

  const msgJ1 = applyTemplate(tplJ1, vars);
  const msgH5 = applyTemplate(tplH5, vars);

  await pool.query(
    `INSERT INTO sms_jobs (booking_id, phone, message, send_at, status, kind)
     VALUES ($1,$2,$3,$4,'PENDING','REMINDER_J1')`,
    [bookingId, phone, msgJ1, remind1]
  );
  await pool.query(
    `INSERT INTO sms_jobs (booking_id, phone, message, send_at, status, kind)
     VALUES ($1,$2,$3,$4,'PENDING','REMINDER_H5')`,
    [bookingId, phone, msgH5, remind2]
  );
}

async function sendInstantConfirmationSms(bookingId) {
  const already = await pool.query(
    "SELECT 1 FROM sms_jobs WHERE booking_id=$1 AND kind IN ('CONFIRM_CUSTOMER','CONFIRM_SALON') LIMIT 1",
    [bookingId]
  );
  if (already.rowCount > 0) return;

  const { rows } = await pool.query(
    `SELECT b.id, b.appointment_at, b.service_name, b.deposit_required_eur,
            c.first_name, c.last_name, c.phone
     FROM bookings b
     JOIN customers c ON c.id=b.customer_id
     WHERE b.id=$1
     LIMIT 1`,
    [bookingId]
  );
  if (!rows[0]) return;

  const r = rows[0];
  const appt = DateTime.fromJSDate(r.appointment_at, { zone: "Europe/Brussels" });

  const vars = {
    bookingId: r.id,
    firstName: r.first_name || "",
    lastName: r.last_name || "",
    phone: normalizeBePhone(r.phone || ""),
    service: r.service_name || "Rendez-vous",
    date: appt.toFormat("dd/LL/yyyy"),
    time: appt.toFormat("HH:mm"),
    address: "Rue des Capucins 64, 7000 Mons",
    deposit: moneyEUR(r.deposit_required_eur),
  };

  const tplCustomer =
    process.env.SMS_TEMPLATE_CONFIRM_CUSTOMER ||
    "4D FASHION SERVICES SRL ✅ Réservation confirmée : {service} le {date} à {time}. Adresse : {address}. Merci {firstName} !";

  const tplSalon =
    process.env.SMS_TEMPLATE_CONFIRM_SALON ||
    "📌 NOUVELLE RÉSERVATION : {firstName} {lastName} ({phone}) • {service} • {date} {time} • Acompte : {deposit} • Booking: {bookingId}";

  const msgCustomer = applyTemplate(tplCustomer, vars);
  const msgSalon = applyTemplate(tplSalon, vars);

  let customerError = null;
  try {
    await sendSmsNow(vars.phone, msgCustomer);
  } catch (e) {
    customerError = e?.message || String(e);
  }

  let salonError = null;
  try {
    await sendSmsNow(SALON_NOTIFY_PHONE, msgSalon);
  } catch (e) {
    salonError = e?.message || String(e);
  }

  await pool.query(
    `INSERT INTO sms_jobs (booking_id, phone, message, send_at, status, sent_at, kind, error)
     VALUES ($1,$2,$3, now(), $4, CASE WHEN $4='SENT' THEN now() ELSE NULL END, 'CONFIRM_CUSTOMER', $5)`,
    [bookingId, vars.phone, msgCustomer, customerError ? "FAILED" : "SENT", customerError]
  );

  await pool.query(
    `INSERT INTO sms_jobs (booking_id, phone, message, send_at, status, sent_at, kind, error)
     VALUES ($1,$2,$3, now(), $4, CASE WHEN $4='SENT' THEN now() ELSE NULL END, 'CONFIRM_SALON', $5)`,
    [bookingId, normalizeBePhone(SALON_NOTIFY_PHONE), msgSalon, salonError ? "FAILED" : "SENT", salonError]
  );
}

async function markBookingConfirmed(bookingId, { stripeSessionId } = {}) {
  await pool.query(
    `UPDATE bookings
     SET status=$2, deposit_paid=true,
         stripe_session_id=COALESCE($3, stripe_session_id),
         updated_at=now()
     WHERE id=$1`,
    [bookingId, BookingStatus.CONFIRMED, stripeSessionId || null]
  );

  const check = await pool.query(
    "SELECT 1 FROM sms_jobs WHERE booking_id=$1 AND kind IN ('REMINDER_J1','REMINDER_H5') LIMIT 1",
    [bookingId]
  );
  if (check.rowCount === 0) await scheduleSmsJobs(bookingId);

  await sendInstantConfirmationSms(bookingId);
}

/** =========================================================
 *  11) SMS worker (cron every minute) for PENDING
 *  ========================================================= */
async function sendPendingSmsJobs() {
  if (!twilio || !TWILIO_FROM_NUMBER) return;

  const { rows } = await pool.query(
    `SELECT id, phone, message
     FROM sms_jobs
     WHERE sent_at IS NULL AND status='PENDING' AND send_at <= now()
     ORDER BY send_at ASC
     LIMIT 20`
  );

  for (const job of rows) {
    try {
      await twilio.messages.create({
        from: TWILIO_FROM_NUMBER,
        to: normalizeBePhone(job.phone),
        body: job.message,
      });
      await pool.query("UPDATE sms_jobs SET sent_at=now(), status='SENT', error=NULL WHERE id=$1", [job.id]);
    } catch (e) {
      const errMsg = e?.message || String(e);
      await pool.query("UPDATE sms_jobs SET status='FAILED', error=$2 WHERE id=$1", [job.id, errMsg]);
    }
  }
}
cron.schedule("* * * * *", () => {
  sendPendingSmsJobs().catch((e) => console.error("SMS worker error:", e));
});

/** =========================================================
 *  12) Routes
 *  ========================================================= */
app.get("/health", async (req, res) => {
  const dbOk = await pool.query("SELECT 1").then(() => true).catch(() => false);
  res.json({
    status: "ok",
    apiBase: API_BASE || null,
    dbOk,
    twilioConfigured: Boolean(TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_FROM_NUMBER),
  });
});

app.get("/api/services", async (req, res) => {
  const { rows } = await pool.query(`
    SELECT id, name, category,
           price_eur::float8 AS "priceEur",
           duration_minutes AS "durationMinutes"
    FROM services
    WHERE COALESCE(is_active, TRUE) = TRUE
    ORDER BY name ASC
  `);
  res.json(rows);
});

app.post("/api/bookings", async (req, res) => {
  try {
    const body = req.body;
    if (!body.customer?.firstName || !body.customer?.phoneNumber) return res.status(400).json({ error: "customer requis" });
    if (!body.appointmentDateTime) return res.status(400).json({ error: "appointmentDateTime requis" });
    if (!body.paymentMethod) return res.status(400).json({ error: "paymentMethod requis" });
    if (!body.serviceId) return res.status(400).json({ error: "serviceId requis" });

    const service = await getService(body.serviceId);
    if (!service) return res.status(400).json({ error: "Service invalide" });

    const customerId = await getOrCreateCustomer(body.customer);

    const appointmentAtUtcIso = DateTime.fromISO(String(body.appointmentDateTime), { zone: "Europe/Brussels" })
      .toUTC()
      .toISO();
    if (!appointmentAtUtcIso) return res.status(400).json({ error: "appointmentDateTime invalide" });

    const bookingId = `BKG-${Date.now()}`;
    const { totalPriceEur, depositRequiredEur } = await createBookingRow({
      bookingId,
      salonId: body.salonId,
      customerId,
      service,
      appointmentAtUtcIso,
      paymentMethod: body.paymentMethod,
      notes: body.notesForStylist,
    });

    let paymentUrl = null;

    if (body.paymentMethod === "PAYPAL") {
      const order = await createPayPalOrder({ bookingId, amount: depositRequiredEur, currency: "EUR" });
      await pool.query("UPDATE bookings SET paypal_order_id=$2 WHERE id=$1", [bookingId, order.orderId]);
      paymentUrl = order.approveUrl;
    } else if (body.paymentMethod === "BANCONTACT") {
      const session = await createBancontactCheckout({ bookingId, amount: depositRequiredEur });
      await pool.query("UPDATE bookings SET stripe_session_id=$2 WHERE id=$1", [bookingId, session.sessionId]);
      paymentUrl = session.url;
    } else {
      return res.status(400).json({ error: "paymentMethod invalide" });
    }

    res.status(201).json({
      bookingId,
      status: BookingStatus.PENDING_DEPOSIT,
      paymentUrl,
      totalPriceEur: Number(totalPriceEur),
      depositRequiredEur: Number(depositRequiredEur),
    });
  } catch (e) {
    res.status(500).json({ error: "server error", details: e.message });
  }
});

app.get("/api/bookings/:id", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT b.id, b.status, b.deposit_paid AS "depositPaid",
            b.total_price_eur::float8 AS "totalPriceEur",
            b.deposit_required_eur::float8 AS "depositRequiredEur",
            b.payment_method AS "paymentMethod",
            b.appointment_at AS "appointmentAt"
     FROM bookings b WHERE b.id=$1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ error: "Booking introuvable" });
  res.json(rows[0]);
});

// PayPal return/cancel
app.get("/payments/paypal/return", async (req, res) => {
  try {
    const bookingId = req.query.bookingId;
    const token = req.query.token;
    if (!bookingId || !token) return res.status(400).send("Paramètres manquants");

    const capture = await capturePayPalOrder(token);
    if (capture.status === "COMPLETED") {
      await pool.query("UPDATE bookings SET deposit_paid=true, status=$2, updated_at=now() WHERE id=$1", [
        bookingId,
        BookingStatus.CONFIRMED,
      ]);

      const check = await pool.query(
        "SELECT 1 FROM sms_jobs WHERE booking_id=$1 AND kind IN ('REMINDER_J1','REMINDER_H5') LIMIT 1",
        [bookingId]
      );
      if (check.rowCount === 0) await scheduleSmsJobs(bookingId);

      await sendInstantConfirmationSms(bookingId);

      const redirectUrl = `${FRONTEND_SUCCESS_URL || API_BASE + "/success"}?bookingId=${encodeURIComponent(bookingId)}`;
      return res.redirect(302, redirectUrl);
    }

    await pool.query("UPDATE bookings SET status=$2, updated_at=now() WHERE id=$1", [bookingId, BookingStatus.CANCELLED]);
    const redirectUrl = `${FRONTEND_CANCEL_URL || API_BASE + "/cancel"}?bookingId=${encodeURIComponent(bookingId)}`;
    return res.redirect(302, redirectUrl);
  } catch (e) {
    res.status(500).send("Erreur PayPal");
  }
});

app.get("/payments/paypal/cancel", async (req, res) => {
  const bookingId = req.query.bookingId;
  if (bookingId) {
    await pool.query("UPDATE bookings SET status=$2, updated_at=now() WHERE id=$1", [bookingId, BookingStatus.CANCELLED]);
  }
  const redirectUrl = `${FRONTEND_CANCEL_URL || API_BASE + "/cancel"}?bookingId=${encodeURIComponent(bookingId || "")}`;
  return res.redirect(302, redirectUrl);
});

// Success/Cancel pages (simple, deep link)
app.get("/success", (req, res) => {
  const bookingId = (req.query.bookingId || "").toString().trim();
  const deepLink = bookingId ? `${APP_DEEP_LINK_SCHEME}${encodeURIComponent(bookingId)}` : "4dfashion://booking";
  res.status(200).send(`
    <html><body style="font-family:Arial;background:#070A12;color:#EAFBFF;padding:24px">
      <h2>Paiement confirmé ✅</h2>
      <p>Votre réservation est enregistrée.</p>
      <a href="${deepLink}">Retour à l’application</a>
      <script>
        setTimeout(function(){ window.location.href=${JSON.stringify(PLAY_STORE_URL)}; }, 1400);
      </script>
    </body></html>
  `);
});

app.get("/cancel", (req, res) => {
  const bookingId = (req.query.bookingId || "").toString().trim();
  const deepLink = bookingId ? `${APP_DEEP_LINK_SCHEME}${encodeURIComponent(bookingId)}` : "4dfashion://booking";
  res.status(200).send(`
    <html><body style="font-family:Arial;background:#070A12;color:#EAFBFF;padding:24px">
      <h2>Paiement annulé ❌</h2>
      <p>Votre réservation n’est pas confirmée.</p>
      <a href="${deepLink}">Retour à l’application</a>
      <script>
        setTimeout(function(){ window.location.href=${JSON.stringify(PLAY_STORE_URL)}; }, 1400);
      </script>
    </body></html>
  `);
});

/** =========================================================
 *  13) ADMIN routes (TEST WITHOUT PAYMENT)
 *  ========================================================= */
function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  next();
}

// Create TEST booking + confirm + send SMS
app.post("/api/admin/test-booking", requireAdmin, async (req, res) => {
  try {
    const body = req.body || {};
    const phone = normalizeBePhone(body.phone || "");
    const firstName = body.firstName || "Test";
    const lastName = body.lastName || "Client";
    const serviceId = body.serviceId || "BRAIDS_RETOUCH_MEN";
    const appointmentDateTime = body.appointmentDateTime || DateTime.now().plus({ days: 2 }).toISO();

    if (!phone) return res.status(400).json({ error: "phone requis (format +32...)" });

    const service = await getService(serviceId);
    if (!service) return res.status(400).json({ error: "serviceId invalide" });

    const customerId = await getOrCreateCustomer({
      firstName,
      lastName,
      phoneNumber: phone,
      email: body.email || null
    });

    const appointmentAtUtcIso = DateTime.fromISO(String(appointmentDateTime), { zone: "Europe/Brussels" })
      .toUTC()
      .toISO();
    if (!appointmentAtUtcIso) return res.status(400).json({ error: "appointmentDateTime invalide" });

    const bookingId = `BKG-TEST-${Date.now()}`;
    const { totalPriceEur, depositRequiredEur } = await createBookingRow({
      bookingId,
      salonId: "4D-FASHION-SERVICES-SRL",
      customerId,
      service,
      appointmentAtUtcIso,
      paymentMethod: "TEST",
      notes: "TEST BOOKING (no payment)"
    });

    await pool.query(
      "UPDATE bookings SET status=$2, deposit_paid=true, updated_at=now() WHERE id=$1",
      [bookingId, "CONFIRMED"]
    );

    await scheduleSmsJobs(bookingId);
    await sendInstantConfirmationSms(bookingId);

    return res.json({
      ok: true,
      bookingId,
      status: "CONFIRMED",
      totalPriceEur: Number(totalPriceEur),
      depositRequiredEur: Number(depositRequiredEur)
    });
  } catch (e) {
    console.error("admin test-booking error:", e);
    return res.status(500).json({ error: "Server error", details: e.message });
  }
});

// Confirm existing booking + send SMS
app.post("/api/admin/confirm-booking/:id", requireAdmin, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const exists = await pool.query("SELECT id FROM bookings WHERE id=$1 LIMIT 1", [bookingId]);
    if (exists.rowCount === 0) return res.status(404).json({ error: "Booking introuvable" });

    await pool.query(
      "UPDATE bookings SET status=$2, deposit_paid=true, updated_at=now() WHERE id=$1",
      [bookingId, "CONFIRMED"]
    );

    const check = await pool.query(
      "SELECT 1 FROM sms_jobs WHERE booking_id=$1 AND kind IN ('REMINDER_J1','REMINDER_H5') LIMIT 1",
      [bookingId]
    );
    if (check.rowCount === 0) await scheduleSmsJobs(bookingId);

    await sendInstantConfirmationSms(bookingId);

    return res.json({ ok: true, bookingId, status: "CONFIRMED" });
  } catch (e) {
    console.error("admin confirm-booking error:", e);
    return res.status(500).json({ error: "Server error", details: e.message });
  }
});

/** =========================================================
 *  14) Startup
 *  ========================================================= */
(async () => {
  await ensureDbColumns();
  await upsertServices();
  app.listen(PORT, () => console.log(`4D Fashion Booking API running on port ${PORT}`));
})();

