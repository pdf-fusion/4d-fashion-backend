import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import Stripe from "stripe";

dotenv.config();

const app = express();

/** =========================================================
 *  0) Stripe webhook MUST use raw body BEFORE express.json()
 *  ========================================================= */
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const bookings = new Map();

const BookingStatus = {
  PENDING_DEPOSIT: "PENDING_DEPOSIT",
  CONFIRMED: "CONFIRMED",
  CANCELLED: "CANCELLED",
  NO_SHOW: "NO_SHOW",
};

app.post(
  "/payments/webhook/stripe",
  express.raw({ type: "application/json" }),
  (req, res) => {
    try {
      if (!stripe) return res.status(500).send("Stripe not configured");

      const sig = req.headers["stripe-signature"];
      const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

      if (!webhookSecret) return res.status(500).send("Missing STRIPE_WEBHOOK_SECRET");

      let event;
      try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
      } catch (err) {
        console.error("❌ Stripe webhook signature verification failed:", err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
      }

      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const bookingId = session.metadata?.bookingId;

        if (bookingId && bookings.has(bookingId)) {
          const booking = bookings.get(bookingId);
          booking.depositPaid = true;
          booking.status = BookingStatus.CONFIRMED;
          booking.updatedAt = new Date().toISOString();
          bookings.set(bookingId, booking);
          console.log("✅ Booking confirmé via Stripe (Bancontact):", bookingId);
        } else {
          console.warn("⚠️ BookingId introuvable dans webhook:", bookingId);
        }
      }

      return res.json({ received: true });
    } catch (err) {
      console.error("Erreur webhook Stripe:", err);
      return res.status(500).json({ error: "Erreur interne webhook Stripe" });
    }
  }
);

// JSON pour toutes les autres routes
app.use(express.json());

/** =========================================================
 *  1) Config générale
 *  ========================================================= */
const PORT = process.env.PORT || 4000;

const API_BASE = (process.env.API_BASE || "").replace(/\/+$/, "");

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || "";
const PAYPAL_API_BASE = (process.env.PAYPAL_API_BASE || "https://api-m.sandbox.paypal.com").replace(
  /\/+$/,
  ""
);

const FRONTEND_SUCCESS_URL = (process.env.FRONTEND_SUCCESS_URL || "").replace(/\/+$/, "");
const FRONTEND_CANCEL_URL = (process.env.FRONTEND_CANCEL_URL || "").replace(/\/+$/, "");

/** =========================================================
 *  2) Services salon + prix (PRO)
 *  - ici tu mets ta vraie carte de services
 *  ========================================================= */
const services = [
  // Tresses / Braids
  { id: "BRAIDS_SMALL", name: "Tresses Small", category: "Coiffure femme africaine", priceEur: 120, durationMinutes: 180 },
  { id: "BRAIDS_MEDIUM", name: "Tresses Medium", category: "Coiffure femme africaine", priceEur: 80, durationMinutes: 150 },
  { id: "BRAIDS_LARGE", name: "Tresses Large", category: "Coiffure femme africaine", priceEur: 60, durationMinutes: 120 },

  // Dreadlocks
  { id: "DREADLOCKS", name: "Dreadlocks", category: "Coiffure", priceEur: 120, durationMinutes: 180 },

  // Perruques / Locks
  { id: "WIG_INSTALL", name: "Pose Perruque", category: "Coiffure", priceEur: 70, durationMinutes: 90 },
  { id: "LOCKS_RETOUCH", name: "Retouche Locks", category: "Coiffure", priceEur: 65, durationMinutes: 90 },

  // Lissage / Coloration / Soins
  { id: "HAIR_STRAIGHTENING", name: "Lissage de cheveux", category: "Soins capillaires", priceEur: 90, durationMinutes: 120 }, // À CONFIRMER
  { id: "HAIR_COLORING", name: "Coloration capillaire", category: "Coloration", priceEur: 85, durationMinutes: 120 }, // À CONFIRMER
  { id: "SHAMPOO", name: "Shampoing", category: "Soins capillaires", priceEur: 15, durationMinutes: 30 }, // À CONFIRMER

  // Coupes
  { id: "KIDS_CUT", name: "Coupe enfants", category: "Coupe", priceEur: 10, durationMinutes: 30 },
  { id: "MEN_CUT", name: "Coupe hommes", category: "Coupe", priceEur: 15, durationMinutes: 30 },

  // Brushing
  { id: "SILK_PRESS", name: "Brushing / Silk Press", category: "Brushing", priceEur: 50, durationMinutes: 60 }
];   

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

/** =========================================================
 *  3) PayPal helpers
 *  ========================================================= */
async function getPayPalAccessToken() {
  if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
    throw new Error("PayPal not configured (missing client id/secret)");
  }

  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64");

  const res = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  if (!res.ok) {
    console.error("PayPal token error:", await res.text());
    throw new Error("PayPal: impossible d'obtenir le token");
  }

  const data = await res.json();
  return data.access_token;
}

async function createPayPalOrder({ bookingId, amount, currency }) {
  if (!API_BASE) throw new Error("API_BASE missing (Render env var)");

  const accessToken = await getPayPalAccessToken();

  const returnUrlBase = `${API_BASE}/payments/paypal/return`;
  const cancelUrlBase = `${API_BASE}/payments/paypal/cancel`;

  const res = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      intent: "CAPTURE",
      purchase_units: [
        {
          reference_id: bookingId,
          amount: { currency_code: currency, value: amount.toFixed(2) },
        },
      ],
      application_context: {
        brand_name: "4D FASHION SERVICES SRL",
        return_url: `${returnUrlBase}?bookingId=${encodeURIComponent(bookingId)}`,
        cancel_url: `${cancelUrlBase}?bookingId=${encodeURIComponent(bookingId)}`,
        user_action: "PAY_NOW",
      },
    }),
  });

  if (!res.ok) {
    console.error("PayPal create order error:", await res.text());
    throw new Error("PayPal: erreur création commande");
  }

  const data = await res.json();
  const approveLink = data.links?.find((l) => l.rel === "approve")?.href;
  if (!approveLink) throw new Error("PayPal: lien approve introuvable");

  return { orderId: data.id, approveUrl: approveLink };
}

async function capturePayPalOrder(orderId) {
  const accessToken = await getPayPalAccessToken();

  const res = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders/${orderId}/capture`, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
  });

  if (!res.ok) {
    console.error("PayPal capture error:", await res.text());
    throw new Error("PayPal: erreur capture paiement");
  }

  return res.json();
}

/** =========================================================
 *  4) Stripe Bancontact helper
 *  ========================================================= */
async function createBancontactCheckout({ bookingId, amount, currency, description }) {
  if (!stripe) throw new Error("Stripe not configured (missing STRIPE_SECRET_KEY)");

  assertValidUrl(FRONTEND_SUCCESS_URL, "FRONTEND_SUCCESS_URL");
  assertValidUrl(FRONTEND_CANCEL_URL, "FRONTEND_CANCEL_URL");

  const successUrl = `${FRONTEND_SUCCESS_URL}?bookingId=${encodeURIComponent(bookingId)}`;
  const cancelUrl = `${FRONTEND_CANCEL_URL}?bookingId=${encodeURIComponent(bookingId)}`;

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["bancontact"],
    mode: "payment",
    line_items: [
      {
        quantity: 1,
        price_data: {
          currency: currency.toLowerCase(),
          unit_amount: Math.round(amount * 100),
          product_data: { name: description || "Acompte RDV - 4D Fashion" },
        },
      },
    ],
    metadata: { bookingId },
    success_url: successUrl,
    cancel_url: cancelUrl,
  });

  return { sessionId: session.id, url: session.url };
}

/** =========================================================
 *  5) Routes UI/diagnostic
 *  ========================================================= */
app.get("/", (req, res) => res.send("4D Fashion Booking API en ligne 🚀"));

app.get("/success", (req, res) => res.send("Paiement OK ✅"));
app.get("/cancel", (req, res) => res.send("Paiement annulé ❌"));

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    apiBase: API_BASE || null,
    paypalConfigured: Boolean(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET && PAYPAL_API_BASE),
    stripeConfigured: Boolean(STRIPE_SECRET_KEY),
    webhookConfigured: Boolean(process.env.STRIPE_WEBHOOK_SECRET),
    frontendSuccessUrl: FRONTEND_SUCCESS_URL || null,
    frontendCancelUrl: FRONTEND_CANCEL_URL || null,
    servicesCount: services.length,
  });
});

/** =========================================================
 *  6) API services
 *  ========================================================= */
app.get("/api/services", (req, res) => {
  res.json(services);
});

/** =========================================================
 *  7) API booking (acompte = 20% du service)
 *  - PRO: backend impose prix + acompte, pas l'app
 *  ========================================================= */
app.post("/api/bookings", async (req, res) => {
  try {
    const body = req.body;

    if (!body.customer?.firstName || !body.customer?.phoneNumber) {
      return res.status(400).json({ error: "Customer (prénom + téléphone) requis" });
    }
    if (!body.appointmentDateTime) {
      return res.status(400).json({ error: "appointmentDateTime requis" });
    }
    if (!body.paymentMethod) {
      return res.status(400).json({ error: "paymentMethod requis (PAYPAL ou BANCONTACT)" });
    }
    if (!body.serviceId) {
      return res.status(400).json({ error: "serviceId requis" });
    }

    const service = services.find((s) => s.id === body.serviceId);
    if (!service) {
      return res.status(400).json({ error: "Service invalide" });
    }

    const totalPriceEur = round2(service.priceEur);
    const depositRequiredEur = round2(totalPriceEur * 0.20); // ✅ 20%

    const bookingId = `BKG-${Date.now()}`;

    const booking = {
      id: bookingId,
      salonName: "4D FASHION SERVICES SRL",
      salonAddress: "RUE DES CAPUCINS 64, 7000 MONS, BELGIQUE",
      salonId: body.salonId || "4D-FASHION-SERVICES-SRL",

      customer: body.customer,
      serviceId: service.id,
      serviceName: service.name,
      servicePriceEur: totalPriceEur,
      serviceDurationMinutes: service.durationMinutes,

      hairProfile: body.hairProfile || null,
      appointmentDateTime: body.appointmentDateTime,

      totalPriceEur,
      depositRequiredEur,

      depositPaid: false,
      status: BookingStatus.PENDING_DEPOSIT,
      paymentMethod: body.paymentMethod,
      notesForStylist: body.notesForStylist ?? null,

      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    bookings.set(bookingId, booking);

    let paymentUrl = null;

    if (body.paymentMethod === "PAYPAL") {
      const order = await createPayPalOrder({
        bookingId,
        amount: depositRequiredEur,
        currency: "EUR",
      });

      booking.paypalOrderId = order.orderId;
      bookings.set(bookingId, booking);
      paymentUrl = order.approveUrl;

    } else if (body.paymentMethod === "BANCONTACT") {
      const session = await createBancontactCheckout({
        bookingId,
        amount: depositRequiredEur,
        currency: "EUR",
        description: `Acompte (20%) - ${service.name}`,
      });

      booking.bancontactSessionId = session.sessionId;
      bookings.set(bookingId, booking);
      paymentUrl = session.url;

    } else {
      return res.status(400).json({ error: "paymentMethod invalide. Utilise PAYPAL ou BANCONTACT." });
    }

    return res.status(201).json({
      bookingId,
      status: booking.status,
      paymentUrl,
      message: "Booking créé, acompte en attente de paiement",
      totalPriceEur,
      depositRequiredEur
    });
  } catch (err) {
    console.error("Erreur /api/bookings:", err);
    return res.status(500).json({
      error: "Erreur serveur lors de la création du booking",
      details: err.message,
    });
  }
});

app.get("/api/bookings/:id", (req, res) => {
  const booking = bookings.get(req.params.id);
  if (!booking) return res.status(404).json({ error: "Booking introuvable" });
  return res.json(booking);
});

/** =========================================================
 *  8) PayPal return/cancel
 *  ========================================================= */
app.get("/payments/paypal/return", async (req, res) => {
  try {
    const bookingId = req.query.bookingId;
    const token = req.query.token;

    if (!bookingId || !token) return res.status(400).send("Paramètres manquants");
    const booking = bookings.get(bookingId);
    if (!booking) return res.status(404).send("Booking introuvable");

    const captureResult = await capturePayPalOrder(token);

    if (captureResult.status === "COMPLETED") {
      booking.depositPaid = true;
      booking.status = BookingStatus.CONFIRMED;
      booking.updatedAt = new Date().toISOString();
      bookings.set(bookingId, booking);

      const redirectUrl = `${FRONTEND_SUCCESS_URL || API_BASE + "/success"}?bookingId=${encodeURIComponent(bookingId)}`;
      return res.redirect(302, redirectUrl);
    }

    booking.status = BookingStatus.CANCELLED;
    booking.updatedAt = new Date().toISOString();
    bookings.set(bookingId, booking);

    const redirectUrl = `${FRONTEND_CANCEL_URL || API_BASE + "/cancel"}?bookingId=${encodeURIComponent(bookingId)}`;
    return res.redirect(302, redirectUrl);
  } catch (err) {
    console.error("Erreur /payments/paypal/return:", err);
    return res.status(500).send("Erreur lors de la validation PayPal");
  }
});

app.get("/payments/paypal/cancel", (req, res) => {
  const bookingId = req.query.bookingId;

  if (bookingId && bookings.has(bookingId)) {
    const booking = bookings.get(bookingId);
    booking.status = BookingStatus.CANCELLED;
    booking.updatedAt = new Date().toISOString();
    bookings.set(bookingId, booking);
  }

  const redirectUrl = `${FRONTEND_CANCEL_URL || API_BASE + "/cancel"}?bookingId=${encodeURIComponent(bookingId || "")}`;
  return res.redirect(302, redirectUrl);
});

app.listen(PORT, () => {
  console.log(`4D Fashion Booking API running on port ${PORT}`);
});

