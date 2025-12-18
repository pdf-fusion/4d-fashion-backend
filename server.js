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

// ---------- Stripe webhook RAW (important) ----------
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// ---------- Postgres ----------
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
});

// ---------- Twilio ----------
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID || "";
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN || "";
const TWILIO_FROM_NUMBER = process.env.TWILIO_FROM_NUMBER || "";
const twilio =
  TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN ? Twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;

// ---------- Config ----------
const PORT = process.env.PORT || 4000;
const API_BASE = (process.env.API_BASE || "").replace(/\/+$/, "");
const FRONTEND_SUCCESS_URL = (process.env.FRONTEND_SUCCESS_URL || "").replace(/\/+$/, "");
const FRONTEND_CANCEL_URL = (process.env.FRONTEND_CANCEL_URL || "").replace(/\/+$/, "");

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || "";
const PAYPAL_API_BASE = (process.env.PAYPAL_API_BASE || "https://api-m.sandbox.paypal.com").replace(
  /\/+$/,
  ""
);

const BookingStatus = {
  PENDING_DEPOSIT: "PENDING_DEPOSIT",
  CONFIRMED: "CONFIRMED",
  CANCELLED: "CANCELLED",
  NO_SHOW: "NO_SHOW",
};

function round2(n) {
  return Math.round(n * 100) / 100;
}
function assertValidUrl(u, name) {
  try {
    new URL(u);
  } catch {
    throw new Error(`${name} is not a valid URL`);
  }
}
function fmtBrussels(dtIso) {
  const dt = DateTime.fromISO(dtIso, { zone: "Europe/Brussels" });
  return dt.toFormat("dd/LL/yyyy 'à' HH:mm");
}

// ---------- Stripe webhook endpoint ----------
app.post(
  "/payments/webhook/stripe",
  express.raw({ type: "application/json" }),
  async (req, res) => {
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
        if (bookingId) {
          await markBookingConfirmed(bookingId, { stripeSessionId: session.id });
        }
      }

      return res.json({ received: true });
    } catch (err) {
      console.error("Stripe webhook error:", err);
      return res.status(500).json({ error: "Stripe webhook internal error" });
    }
  }
);

// JSON for other routes
app.use(express.json());

// ---------- Services seed (one-time upsert at startup) ----------
const SERVICE_SEED = [
  { id: "DREADLOCKS", name: "Dreadlocks", category: "Coiffure", priceEur: 120, durationMinutes: 180 },
  { id: "HAIR_STRAIGHTENING", name: "Lissage de cheveux", category: "Soins capillaires", priceEur: 90, durationMinutes: 120 }, // ajuste
  { id: "KIDS_CUT", name: "Coupe enfants", category: "Coupe", priceEur: 10, durationMinutes: 30 },
  { id: "MEN_CUT", name: "Coupe hommes", category: "Coupe", priceEur: 15, durationMinutes: 30 },
  { id: "HAIR_COLORING", name: "Coloration capillaire", category: "Coloration", priceEur: 85, durationMinutes: 120 }, // ajuste
  { id: "SHAMPOO", name: "Shampoing", category: "Soins capillaires", priceEur: 15, durationMinutes: 30 }, // ajuste

  { id: "BRAIDS_SMALL", name: "Tresses Small", category: "Coiffure femme africaine", priceEur: 120, durationMinutes: 180 },
  { id: "BRAIDS_MEDIUM", name: "Tresses Medium", category: "Coiffure femme africaine", priceEur: 80, durationMinutes: 150 },
  { id: "BRAIDS_LARGE", name: "Tresses Large", category: "Coiffure femme africaine", priceEur: 60, durationMinutes: 120 },
  { id: "WIG_INSTALL", name: "Pose Perruque", category: "Coiffure", priceEur: 70, durationMinutes: 90 },
  { id: "LOCKS_RETOUCH", name: "Retouche Locks", category: "Coiffure", priceEur: 65, durationMinutes: 90 },
  { id: "SILK_PRESS", name: "Brushing / Silk Press", category: "Brushing", priceEur: 50, durationMinutes: 60 }
];

async function upsertServices() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const s of SERVICE_SEED) {
      await client.query(
        `INSERT INTO services (id, name, category, price_eur, duration_minutes)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (id) DO UPDATE
         SET name=EXCLUDED.name, category=EXCLUDED.category, price_eur=EXCLUDED.price_eur, duration_minutes=EXCLUDED.duration_minutes`,
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

// ---------- PayPal helpers ----------
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
      purchase_units: [{ reference_id: bookingId, amount: { currency_code: currency, value: amount.toFixed(2) } }],
      application_context: { brand_name: "4D FASHION SERVICES SRL", return_url: returnUrl, cancel_url: cancelUrl, user_action: "PAY_NOW" },
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

// ---------- Stripe Bancontact ----------
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
          unit_amount: Math.round(amount * 100),
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

// ---------- Core DB actions ----------
async function getOrCreateCustomer({ firstName, lastName, phoneNumber, email }) {
  const client = await pool.connect();
  try {
    const existing = await client.query("SELECT id FROM customers WHERE phone=$1", [phoneNumber]);
    if (existing.rowCount > 0) return existing.rows[0].id;

    const ins = await client.query(
      `INSERT INTO customers (first_name, last_name, phone, email)
       VALUES ($1,$2,$3,$4) RETURNING id`,
      [firstName, lastName, phoneNumber, email || null]
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

async function createBookingRow({ bookingId, salonId, customerId, service, appointmentAt, paymentMethod, notes }) {
  const total = round2(Number(service.price_eur));
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
      appointmentAt,
      paymentMethod,
      BookingStatus.PENDING_DEPOSIT,
      notes || null,
    ]
  );

  return { totalPriceEur: total, depositRequiredEur: deposit };
}

async function scheduleSmsJobs(bookingId) {
  // Load booking + phone + appointment
  const { rows } = await pool.query(
    `SELECT b.id, b.appointment_at, c.phone
     FROM bookings b
     JOIN customers c ON c.id=b.customer_id
     WHERE b.id=$1`,
    [bookingId]
  );
  if (!rows[0]) return;

  const appointmentAt = rows[0].appointment_at; // timestamptz
  const phone = rows[0].phone;

  // Compute reminders (Europe/Brussels)
  const appt = DateTime.fromISO(appointmentAt.toISOString(), { zone: "Europe/Brussels" });
  const remind1 = appt.minus({ hours: 24 });
  const remind2 = appt.minus({ hours: 5 });

  const msgBase = `4D FASHION SERVICES – Rappel : RDV le ${appt.toFormat("dd/LL/yyyy")} à ${appt.toFormat("HH:mm")} (Rue des Capucins 64, 7000 Mons).`;

  // Insert jobs (avoid duplicates)
  await pool.query(
    `INSERT INTO sms_jobs (booking_id, phone, message, send_at)
     VALUES ($1,$2,$3,$4)`,
    [bookingId, phone, `J-1. ${msgBase}`, remind1.toUTC().toISO()]
  );
  await pool.query(
    `INSERT INTO sms_jobs (booking_id, phone, message, send_at)
     VALUES ($1,$2,$3,$4)`,
    [bookingId, phone, `H-5. ${msgBase}`, remind2.toUTC().toISO()]
  );
}

async function markBookingConfirmed(bookingId, { stripeSessionId } = {}) {
  // Update booking
  const { rows } = await pool.query(
    `UPDATE bookings
     SET status=$2, deposit_paid=true,
         stripe_session_id=COALESCE($3, stripe_session_id),
         updated_at=now()
     WHERE id=$1
     RETURNING id`,
    [bookingId, BookingStatus.CONFIRMED, stripeSessionId || null]
  );

  if (rows.length > 0) {
    // schedule sms jobs only once: simplest guard => check if any sms job already exists
    const check = await pool.query("SELECT 1 FROM sms_jobs WHERE booking_id=$1 LIMIT 1", [bookingId]);
    if (check.rowCount === 0) {
      await scheduleSmsJobs(bookingId);
    }
  }
}

// ---------- SMS worker ----------
async function sendPendingSmsJobs() {
  if (!twilio || !TWILIO_FROM_NUMBER) return;

  // jobs whose send_at <= now AND not sent
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
        to: job.phone,
        body: job.message,
      });

      await pool.query("UPDATE sms_jobs SET sent_at=now(), status='SENT' WHERE id=$1", [job.id]);
    } catch (e) {
      console.error("Twilio send failed:", e?.message || e);
      await pool.query("UPDATE sms_jobs SET status='FAILED' WHERE id=$1", [job.id]);
    }
  }
}

// Run every minute
cron.schedule("* * * * *", () => {
  sendPendingSmsJobs().catch((e) => console.error("SMS worker error:", e));
});

// ---------- Routes ----------
app.get("/", (req, res) => res.send("4D Fashion Booking API en ligne 🚀"));
app.get("/success", (req, res) => res.send("Paiement OK ✅"));
app.get("/cancel", (req, res) => res.send("Paiement annulé ❌"));

app.get("/health", async (req, res) => {
  const dbOk = await pool
    .query("SELECT 1 AS ok")
    .then(() => true)
    .catch(() => false);

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

// services list
app.get("/api/services", async (req, res) => {
  const { rows } = await pool.query("SELECT id, name, category, price_eur AS \"priceEur\", duration_minutes AS \"durationMinutes\" FROM services ORDER BY name ASC");
  res.json(rows);
});

// create booking
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

    // appointmentDateTime comes from Android; store as timestamptz
    const appointmentAt = DateTime.fromISO(body.appointmentDateTime, { zone: "Europe/Brussels" }).toUTC().toISO();
    if (!appointmentAt) return res.status(400).json({ error: "appointmentDateTime invalide" });

    const bookingId = `BKG-${Date.now()}`;
    const { totalPriceEur, depositRequiredEur } = await createBookingRow({
      bookingId,
      salonId: body.salonId,
      customerId,
      service,
      appointmentAt,
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
      totalPriceEur,
      depositRequiredEur,
      message: "Booking créé, acompte en attente de paiement",
    });
  } catch (e) {
    console.error("create booking error:", e);
    res.status(500).json({ error: "Erreur serveur", details: e.message });
  }
});

// get booking
app.get("/api/bookings/:id", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT b.id, b.status, b.deposit_paid AS "depositPaid",
            b.total_price_eur AS "totalPriceEur", b.deposit_required_eur AS "depositRequiredEur",
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
      // schedule sms
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

// Startup
(async () => {
  await upsertServices();
  app.listen(PORT, () => console.log(`4D Fashion Booking API running on port ${PORT}`));
})();

