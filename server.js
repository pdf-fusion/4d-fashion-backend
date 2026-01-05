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

// Admin API token (optional)
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

// Deep link scheme
const APP_DEEP_LINK_SCHEME = "4dfashion://booking?bookingId=";

// Play Store fallback (optional)
const PLAY_STORE_URL =
  process.env.PLAY_STORE_URL ||
  "https://play.google.com/store/apps/details?id=com.debeng.a4dfashionservices";

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

// ✅ Normalise BE phone to E.164 for Twilio (0486... -> +32486...)
function normalizeBePhone(phoneRaw) {
  const p = String(phoneRaw || "").trim().replace(/\s+/g, "");
  if (!p) return "";
  if (p.startsWith("+")) return p; // already E.164
  if (p.startsWith("00")) return "+" + p.slice(2); // 00xx -> +xx
  if (p.startsWith("0")) return "+32" + p.slice(1); // 0xxxx -> +32xxxx
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

/** =========================================================
 *  6) Services seed (optional – upsert on start)
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
  // services.is_active
  await pool.query("ALTER TABLE services ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;");
  // sms_jobs.error
  await pool.query("ALTER TABLE sms_jobs ADD COLUMN IF NOT EXISTS error TEXT;");
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
    // cherche avec phone normalisé OU ancien format (si déjà en DB)
    const existing = await client.query("SELECT id, phone FROM customers WHERE phone=$1 OR phone=$2 LIMIT 1", [
      phone,
      phoneNumber,
    ]);

    if (existing.rowCount > 0) {
      const id = existing.rows[0].id;
      const storedPhone = existing.rows[0].phone;
      // si l’ancien format est stocké, on le corrige
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

// SMS templates
function applyTemplate(tpl, vars) {
  return String(tpl || "").replace(/\{(\w+)\}/g, (_, k) => (vars[k] ?? ""));
}

async function scheduleSmsJobs(bookingId) {
  const { rows } = await pool.query(
    `SELECT b.id, b.appointment_at, c.phone, c.first_name, b.service_name
     FROM bookings b
     JOIN customers c ON c.id=b.customer_id
     WHERE b.id=$1`,
    [bookingId]
  );
  if (!rows[0]) return;

  const appointmentAt = rows[0].appointment_at; // JS Date (pg)
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

  const tplJ1 =
    process.env.SMS_TEMPLATE_J1 ||
    "4D FASHION – Rappel J-1 : {service} le {date} à {time}. Adresse : {address}.";
  const tplH5 =
    process.env.SMS_TEMPLATE_H5 ||
    "4D FASHION – Rappel H-5 : {service} le {date} à {time}. Adresse : {address}.";

  const msgJ1 = applyTemplate(tplJ1, vars);
  const msgH5 = applyTemplate(tplH5, vars);

  await pool.query(
    `INSERT INTO sms_jobs (booking_id, phone, message, send_at, status)
     VALUES ($1,$2,$3,$4,'PENDING')`,
    [bookingId, phone, msgJ1, remind1]
  );
  await pool.query(
    `INSERT INTO sms_jobs (booking_id, phone, message, send_at, status)
     VALUES ($1,$2,$3,$4,'PENDING')`,
    [bookingId, phone, msgH5, remind2]
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

  const check = await pool.query("SELECT 1 FROM sms_jobs WHERE booking_id=$1 LIMIT 1", [bookingId]);
  if (check.rowCount === 0) {
    await scheduleSmsJobs(bookingId);
  }
}

/** =========================================================
 *  10) SMS worker (cron every minute)
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

      await pool.query("UPDATE sms_jobs SET sent_at=now(), status='SENT', error=NULL WHERE id=$1", [
        job.id,
      ]);
    } catch (e) {
      const errMsg = e?.message || String(e);
      console.error("Twilio send failed:", errMsg);

      await pool.query("UPDATE sms_jobs SET status='FAILED', error=$2 WHERE id=$1", [
        job.id,
        errMsg,
      ]);
    }
  }
}
cron.schedule("* * * * *", () => {
  sendPendingSmsJobs().catch((e) => console.error("SMS worker error:", e));
});

/** =========================================================
 *  11) Routes
 *  ========================================================= */
app.get("/", (req, res) => res.send("4D Fashion Booking API en ligne 🚀"));

app.get("/health", async (req, res) => {
  const dbOk = await pool.query("SELECT 1 AS ok").then(() => true).catch(() => false);
  res.json({
    status: "ok",
    apiBase: API_BASE || null,
    dbOk,
    paypalConfigured: Boolean(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET && PAYPAL_API_BASE),
    stripeConfigured: Boolean(STRIPE_SECRET_KEY),
    webhookConfigured: Boolean(process.env.STRIPE_WEBHOOK_SECRET),
    twilioConfigured: Boolean(TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_FROM_NUMBER),
  });
});

// Services list (only active)
app.get("/api/services", async (req, res) => {
  const { rows } = await pool.query(`
    SELECT 
      id, name, category,
      price_eur::float8 AS "priceEur",
      duration_minutes AS "durationMinutes"
    FROM services
    WHERE COALESCE(is_active, TRUE) = TRUE
    ORDER BY name ASC
  `);
  res.json(rows);
});

// Create booking
app.post("/api/bookings", async (req, res) => {
  try {
    const body = req.body;

    if (!body.customer?.firstName || !body.customer?.phoneNumber) {
      return res.status(400).json({ error: "Customer (prénom + téléphone) requis" });
    }
    if (!body.appointmentDateTime) return res.status(400).json({ error: "appointmentDateTime requis" });
    if (!body.paymentMethod) return res.status(400).json({ error: "paymentMethod requis (PAYPAL ou BANCONTACT)" });
    if (!body.serviceId) return res.status(400).json({ error: "serviceId requis" });

    const service = await getService(body.serviceId);
    if (!service) return res.status(400).json({ error: "Service invalide" });

    const customerId = await getOrCreateCustomer(body.customer);

    const appointmentAtUtcIso = DateTime.fromISO(String(body.appointmentDateTime), {
      zone: "Europe/Brussels",
    })
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
      return res.status(400).json({ error: "paymentMethod invalide. Utilise PAYPAL ou BANCONTACT." });
    }

    return res.status(201).json({
      bookingId,
      status: BookingStatus.PENDING_DEPOSIT,
      paymentUrl,
      totalPriceEur: Number(totalPriceEur),
      depositRequiredEur: Number(depositRequiredEur),
      message: "Booking créé, acompte en attente de paiement",
    });
  } catch (e) {
    console.error("create booking error:", e);
    res.status(500).json({ error: "Erreur serveur", details: e.message });
  }
});

// Get booking
app.get("/api/bookings/:id", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT 
        b.id,
        b.status,
        b.deposit_paid AS "depositPaid",
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

      const check = await pool.query("SELECT 1 FROM sms_jobs WHERE booking_id=$1 LIMIT 1", [bookingId]);
      if (check.rowCount === 0) await scheduleSmsJobs(bookingId);

      const redirectUrl = `${FRONTEND_SUCCESS_URL || API_BASE + "/success"}?bookingId=${encodeURIComponent(bookingId)}`;
      return res.redirect(302, redirectUrl);
    }

    await pool.query("UPDATE bookings SET status=$2, updated_at=now() WHERE id=$1", [bookingId, BookingStatus.CANCELLED]);
    const redirectUrl = `${FRONTEND_CANCEL_URL || API_BASE + "/cancel"}?bookingId=${encodeURIComponent(bookingId)}`;
    return res.redirect(302, redirectUrl);
  } catch (e) {
    console.error("paypal return error:", e);
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

/** =========================================================
 *  12) Success / Cancel HTML pages (deep link only)
 *  ========================================================= */
app.get("/success", async (req, res) => {
  const bookingId = (req.query.bookingId || "").toString().trim();
  if (!bookingId) return res.status(200).send("<h2>Paiement confirmé ✅</h2>");

  try {
    const { rows } = await pool.query(
      `SELECT 
          b.id,
          b.status,
          b.deposit_paid AS "depositPaid",
          b.payment_method AS "paymentMethod",
          b.service_name AS "serviceName",
          b.total_price_eur::float8 AS "totalPriceEur",
          b.deposit_required_eur::float8 AS "depositRequiredEur",
          b.appointment_at AS "appointmentAt",
          c.first_name AS "firstName",
          c.last_name AS "lastName",
          c.phone AS "phone"
       FROM bookings b
       JOIN customers c ON c.id = b.customer_id
       WHERE b.id = $1
       LIMIT 1`,
      [bookingId]
    );
    return res.status(200).send(renderSuccessHtml({ bookingId, booking: rows[0] || null }));
  } catch (e) {
    console.error("success page error:", e);
    return res.status(200).send(renderSuccessHtml({ bookingId, booking: null, error: "Impossible de charger la réservation." }));
  }
});

app.get("/cancel", async (req, res) => {
  const bookingId = (req.query.bookingId || "").toString().trim();
  if (!bookingId) return res.status(200).send("<h2>Paiement annulé ❌</h2>");

  try {
    const { rows } = await pool.query(
      `SELECT 
          b.id,
          b.status,
          b.deposit_paid AS "depositPaid",
          b.payment_method AS "paymentMethod",
          b.service_name AS "serviceName",
          b.total_price_eur::float8 AS "totalPriceEur",
          b.deposit_required_eur::float8 AS "depositRequiredEur",
          b.appointment_at AS "appointmentAt",
          c.first_name AS "firstName",
          c.last_name AS "lastName",
          c.phone AS "phone"
       FROM bookings b
       JOIN customers c ON c.id = b.customer_id
       WHERE b.id = $1
       LIMIT 1`,
      [bookingId]
    );
    return res.status(200).send(renderCancelHtml({ bookingId, booking: rows[0] || null }));
  } catch (e) {
    console.error("cancel page error:", e);
    return res.status(200).send(renderCancelHtml({ bookingId, booking: null, error: "Impossible de charger la réservation." }));
  }
});

function renderSuccessHtml({ bookingId, booking, error }) {
  const salonName = "4D FASHION SERVICES SRL";
  const address = "Rue des Capucins 64, 7000 Mons, Belgique";

  const b = booking || {};
  const fullName = b.firstName ? `${b.firstName} ${b.lastName || ""}`.trim() : "";
  const appointment = b.appointmentAt ? formatBrusselsFromDate(b.appointmentAt) : "-";
  const serviceName = b.serviceName ? escapeHtml(b.serviceName) : "-";
  const total = b.totalPriceEur != null ? moneyEUR(b.totalPriceEur) : "-";
  const deposit = b.depositRequiredEur != null ? moneyEUR(b.depositRequiredEur) : "-";
  const paid = b.depositPaid === true ? "Oui ✅" : "En attente ⏳";
  const method = b.paymentMethod ? escapeHtml(b.paymentMethod) : "-";
  const safeId = bookingId ? escapeHtml(bookingId) : "-";

  const deepLink = bookingId ? `${APP_DEEP_LINK_SCHEME}${encodeURIComponent(bookingId)}` : "4dfashion://booking";

  return `<!doctype html><html lang="fr"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${salonName} — Paiement confirmé</title>
<style>
:root{--bg:#070A12;--card:#0D1224;--cyan:#00FFF0;--purple:#8B5CF6;--pink:#FF4ECD;--text:#EAFBFF;--muted:#9AA4BF;--ok:#27F7A3;}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;
background:radial-gradient(900px 600px at 20% 15%, rgba(0,255,240,.18), transparent 60%),
radial-gradient(900px 600px at 75% 25%, rgba(139,92,246,.18), transparent 60%),
radial-gradient(900px 600px at 55% 90%, rgba(255,78,205,.14), transparent 60%), var(--bg);}
.wrap{max-width:980px;margin:0 auto;padding:28px 16px 40px;}
.brand h1{margin:0;font-size:18px;letter-spacing:.4px;color:var(--cyan);text-transform:uppercase;}
.brand p{margin:6px 0 0;color:var(--muted);font-size:14px;}
.hero{margin-top:14px;background:rgba(13,18,36,.96);border:1px solid rgba(0,255,240,.22);border-radius:18px;padding:16px;}
.row{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.06);}
.row:last-child{border-bottom:0}
.k{color:var(--muted)} .v{font-weight:650}
.btn{margin-top:14px;display:inline-block;padding:12px 14px;border-radius:14px;
background:linear-gradient(90deg,var(--cyan),var(--purple),var(--pink));
color:var(--bg);font-weight:800;text-decoration:none;}
.err{margin-top:10px;color:#ffb0c0;font-size:13px;}
</style></head>
<body><div class="wrap">
  <div class="brand"><h1>${salonName}</h1><p>${address}</p></div>
  <div class="hero">
    <h2 style="margin:0;">Paiement confirmé ✅</h2>
    <p style="color:var(--muted);margin:8px 0 0;">Merci <b>${escapeHtml(fullName || "cliente")}</b> — rendez-vous enregistré.</p>
    ${error ? `<div class="err">${escapeHtml(error)}</div>` : ""}
    <div class="row"><div class="k">Réservation</div><div class="v">${safeId}</div></div>
    <div class="row"><div class="k">Prestation</div><div class="v">${serviceName}</div></div>
    <div class="row"><div class="k">Date & heure</div><div class="v">${escapeHtml(appointment)}</div></div>
    <div class="row"><div class="k">Acompte payé</div><div class="v" style="color:${b.depositPaid ? "var(--ok)" : "var(--text)"}">${paid}</div></div>
    <div class="row"><div class="k">Total</div><div class="v">${escapeHtml(total)}</div></div>
    <div class="row"><div class="k">Acompte</div><div class="v">${escapeHtml(deposit)}</div></div>
    <div class="row"><div class="k">Paiement</div><div class="v">${method}</div></div>

    <a class="btn" href="${deepLink}" onclick="openApp(event)">Retour à l’application</a>
  </div>
</div>

<script>
function openApp(e){
  e.preventDefault();
  const deep = ${JSON.stringify(deepLink)};
  window.location.href = deep;
  setTimeout(function(){ window.location.href = ${JSON.stringify(PLAY_STORE_URL)}; }, 1400);
}
</script>
</body></html>`;
}

function renderCancelHtml({ bookingId, booking, error }) {
  const salonName = "4D FASHION SERVICES SRL";
  const address = "Rue des Capucins 64, 7000 Mons, Belgique";

  const b = booking || {};
  const appointment = b.appointmentAt ? formatBrusselsFromDate(b.appointmentAt) : "-";
  const serviceName = b.serviceName ? escapeHtml(b.serviceName) : "-";
  const safeId = bookingId ? escapeHtml(bookingId) : "-";
  const deepLink = bookingId ? `${APP_DEEP_LINK_SCHEME}${encodeURIComponent(bookingId)}` : "4dfashion://booking";

  return `<!doctype html><html lang="fr"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${salonName} — Paiement annulé</title>
<style>
:root{--bg:#070A12;--card:#0D1224;--cyan:#00FFF0;--purple:#8B5CF6;--pink:#FF4ECD;--text:#EAFBFF;--muted:#9AA4BF;}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial;
background:radial-gradient(900px 600px at 20% 15%, rgba(0,255,240,.14), transparent 60%),
radial-gradient(900px 600px at 75% 25%, rgba(139,92,246,.14), transparent 60%),
radial-gradient(900px 600px at 55% 90%, rgba(255,78,205,.10), transparent 60%), var(--bg);}
.wrap{max-width:980px;margin:0 auto;padding:28px 16px 40px;}
.brand h1{margin:0;font-size:18px;color:var(--cyan);text-transform:uppercase;}
.brand p{margin:6px 0 0;color:var(--muted);font-size:14px;}
.hero{margin-top:14px;background:rgba(13,18,36,.96);border:1px solid rgba(255,78,205,.22);border-radius:18px;padding:16px;}
.row{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.06);}
.row:last-child{border-bottom:0}
.k{color:var(--muted)} .v{font-weight:650}
.btn{margin-top:14px;display:inline-block;padding:12px 14px;border-radius:14px;
background:linear-gradient(90deg,var(--cyan),var(--purple),var(--pink));
color:var(--bg);font-weight:800;text-decoration:none;}
.err{margin-top:10px;color:#ffb0c0;font-size:13px;}
</style></head>
<body><div class="wrap">
  <div class="brand"><h1>${salonName}</h1><p>${address}</p></div>
  <div class="hero">
    <h2 style="margin:0;">Paiement annulé ❌</h2>
    <p style="color:var(--muted);margin:8px 0 0;">Votre rendez-vous n’est pas confirmé.</p>
    ${error ? `<div class="err">${escapeHtml(error)}</div>` : ""}
    <div class="row"><div class="k">Réservation</div><div class="v">${safeId}</div></div>
    <div class="row"><div class="k">Prestation</div><div class="v">${serviceName}</div></div>
    <div class="row"><div class="k">Date & heure</div><div class="v">${escapeHtml(appointment)}</div></div>

    <a class="btn" href="${deepLink}" onclick="openApp(event)">Retour à l’application</a>
  </div>
</div>

<script>
function openApp(e){
  e.preventDefault();
  const deep = ${JSON.stringify(deepLink)};
  window.location.href = deep;
  setTimeout(function(){ window.location.href = ${JSON.stringify(PLAY_STORE_URL)}; }, 1400);
}
</script>
</body></html>`;
}

/** =========================================================
 *  13) Admin endpoint example (optional)
 *  ========================================================= */
function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  next();
}
app.get("/api/admin/bookings", requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT b.id, b.status, b.deposit_paid AS "depositPaid",
            b.service_name AS "serviceName",
            b.appointment_at AS "appointmentAt"
     FROM bookings b
     ORDER BY b.appointment_at DESC
     LIMIT 200`
  );
  res.json(rows);
});

/** =========================================================
 *  14) Startup
 *  ========================================================= */
(async () => {
  await ensureDbColumns();
  await upsertServices();
  app.listen(PORT, () => console.log(`4D Fashion Booking API running on port ${PORT}`));
})();

