import express from "express";
import dotenv from "dotenv";
import fetch from "node-fetch";
import Stripe from "stripe";

dotenv.config();

const app = express();
app.use(express.json()); // JSON pour l'API

// --- Config & clients externes ---

const PORT = process.env.PORT || 4000;
const API_BASE = process.env.API_BASE?.replace(/\/+$/, "") || "";

// PayPal
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_API_BASE = process.env.PAYPAL_API_BASE || "https://api-m.sandbox.paypal.com";

// Stripe (Bancontact)
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// --- "Base de données" en mémoire (à remplacer par une vraie DB plus tard) ---

const bookings = new Map(); // key: bookingId, value: booking object

const BookingStatus = {
  PENDING_DEPOSIT: "PENDING_DEPOSIT",
  CONFIRMED: "CONFIRMED",
  CANCELLED: "CANCELLED",
  NO_SHOW: "NO_SHOW",
};

// --- Helpers PayPal ---

async function getPayPalAccessToken() {
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
    throw new Error("Impossible d'obtenir le token PayPal");
  }

  const data = await res.json();
  return data.access_token;
}

async function createPayPalOrder({ bookingId, amount, currency }) {
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
          amount: {
            currency_code: currency,
            value: amount.toFixed(2),
          },
        },
      ],
      application_context: {
        brand_name: "4D FASHION SERVICES SRL",
        return_url: `${returnUrlBase}?bookingId=${bookingId}`,
        cancel_url: `${cancelUrlBase}?bookingId=${bookingId}`,
        user_action: "PAY_NOW",
      },
    }),
  });

  if (!res.ok) {
    console.error("PayPal create order error:", await res.text());
    throw new Error("Erreur lors de la création de la commande PayPal");
  }

  const data = await res.json();
  const approveLink = data.links?.find((l) => l.rel === "approve")?.href;

  if (!approveLink) {
    throw new Error("Lien de redirection PayPal introuvable");
  }

  return {
    orderId: data.id,
    approveUrl: approveLink,
  };
}

async function capturePayPalOrder(orderId) {
  const accessToken = await getPayPalAccessToken();

  const res = await fetch(
    `${PAYPAL_API_BASE}/v2/checkout/orders/${orderId}/capture`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    }
  );

  if (!res.ok) {
    console.error("PayPal capture error:", await res.text());
    throw new Error("Erreur lors de la capture du paiement PayPal");
  }

  const data = await res.json();
  return data;
}

// --- Helper Stripe / Bancontact ---

async function createBancontactCheckout({ bookingId, amount, currency, description }) {
  if (!stripe) {
    throw new Error("Stripe non configuré (STRIPE_SECRET_KEY manquant)");
  }

  const successUrl = `${process.env.FRONTEND_SUCCESS_URL}?bookingId=${bookingId}`;
  const cancelUrl = `${process.env.FRONTEND_CANCEL_URL}?bookingId=${bookingId}`;

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["bancontact"],
    mode: "payment",
    line_items: [
      {
        quantity: 1,
        price_data: {
          currency: currency.toLowerCase(),
          unit_amount: Math.round(amount * 100), // en cents
          product_data: {
            name: description || "Acompte Rendez-vous 4D Fashion",
          },
        },
      },
    ],
    metadata: {
      bookingId,
    },
    success_url: successUrl,
    cancel_url: cancelUrl,
  });

  return {
    sessionId: session.id,
    url: session.url,
  };
}

// --- Routes ---

// Route simple de test
app.get("/", (req, res) => {
  res.send("4D Fashion Services Booking API en ligne 🚀");
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    apiBase: API_BASE || null,
    paypalConfigured: Boolean(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET && PAYPAL_API_BASE),
    stripeConfigured: Boolean(STRIPE_SECRET_KEY),
  });
});

// 1) Création de booking + génération URL de paiement
app.post("/api/bookings", async (req, res) => {
  try {
    const body = req.body; // BookingCreateRequest

    if (!body.customer || !body.customer.firstName || !body.customer.phoneNumber) {
      return res.status(400).json({ error: "Customer (nom + téléphone) requis" });
    }

    if (!body.appointmentDateTime) {
      return res.status(400).json({ error: "appointmentDateTime requis" });
    }

    if (!body.paymentMethod) {
      return res.status(400).json({ error: "paymentMethod requis (PAYPAL ou BANCONTACT)" });
    }

    const bookingId = `BKG-${Date.now()}`;

    const booking = {
      id: bookingId,
      salonName: "4D FASHION SERVICES SRL",
      salonAddress: "RUE DES CAPUCINS 64, 7000 MONS, BELGIQUE",
      salonId: body.salonId || "4D-FASHION-SERVICES-SRL",
      customer: body.customer,
      serviceId: body.serviceId,
      hairProfile: body.hairProfile,
      appointmentDateTime: body.appointmentDateTime,
      totalPriceEur: body.totalPriceEur,
      depositRequiredEur: body.depositRequiredEur,
      depositPaid: false,
      status: BookingStatus.PENDING_DEPOSIT,
      createdAt: new Date().toISOString(),
      paymentMethod: body.paymentMethod,
      notesForStylist: body.notesForStylist ?? null,
    };

    bookings.set(bookingId, booking);

    let paymentUrl = null;

    if (body.paymentMethod === "PAYPAL") {
      const paypalOrder = await createPayPalOrder({
        bookingId,
        amount: body.depositRequiredEur,
        currency: "EUR",
      });
      booking.paypalOrderId = paypalOrder.orderId;
      bookings.set(bookingId, booking);
      paymentUrl = paypalOrder.approveUrl;
    } else if (body.paymentMethod === "BANCONTACT") {
      const bancontactSession = await createBancontactCheckout({
        bookingId,
        amount: body.depositRequiredEur,
        currency: "EUR",
        description: "Acompte rendez-vous 4D Fashion Services",
      });
      booking.bancontactSessionId = bancontactSession.sessionId;
      bookings.set(bookingId, booking);
      paymentUrl = bancontactSession.url;
    } else {
      return res.status(400).json({
        error: "paymentMethod invalide. Utilise PAYPAL ou BANCONTACT.",
      });
    }

    res.status(201).json({
      bookingId: bookingId,
      status: booking.status,
      paymentUrl: paymentUrl,
      message: "Booking créé, acompte en attente de paiement",
    });
  } catch (err) {
    console.error("Erreur /api/bookings:", err);
    res.status(500).json({
      error: "Erreur serveur lors de la création du booking",
      details: err.message,
    });
  }
});

// 2) Retour PayPal après paiement (success)
app.get("/payments/paypal/return", async (req, res) => {
  try {
    const bookingId = req.query.bookingId;
    const token = req.query.token; // orderId PayPal

    if (!bookingId || !token) {
      return res.status(400).send("Paramètres manquants");
    }

    const booking = bookings.get(bookingId);
    if (!booking) {
      return res.status(404).send("Booking introuvable");
    }

    const captureResult = await capturePayPalOrder(token);
    const status = captureResult.status;

    if (status === "COMPLETED") {
      booking.depositPaid = true;
      booking.status = BookingStatus.CONFIRMED;
      bookings.set(bookingId, booking);

      const redirectUrl = `${process.env.FRONTEND_SUCCESS_URL}?bookingId=${bookingId}`;
      return res.redirect(302, redirectUrl);
    } else {
      booking.status = BookingStatus.CANCELLED;
      bookings.set(bookingId, booking);
      const redirectUrl = `${process.env.FRONTEND_CANCEL_URL}?bookingId=${bookingId}`;
      return res.redirect(302, redirectUrl);
    }
  } catch (err) {
    console.error("Erreur /payments/paypal/return:", err);
    return res.status(500).send("Erreur lors de la validation du paiement");
  }
});

// 3) Retour PayPal annulation
app.get("/payments/paypal/cancel", (req, res) => {
  const bookingId = req.query.bookingId;
  if (bookingId && bookings.has(bookingId)) {
    const booking = bookings.get(bookingId);
    booking.status = BookingStatus.CANCELLED;
    bookings.set(bookingId, booking);
  }
  const redirectUrl = `${process.env.FRONTEND_CANCEL_URL}?bookingId=${bookingId}`;
  return res.redirect(302, redirectUrl);
});

// 4) Webhook Stripe (Bancontact) - simplifié (sans vérification de signature)
app.post("/payments/webhook/stripe", (req, res) => {
  try {
    const event = req.body;

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const bookingId = session.metadata?.bookingId;

      if (bookingId && bookings.has(bookingId)) {
        const booking = bookings.get(bookingId);
        booking.depositPaid = true;
        booking.status = BookingStatus.CONFIRMED;
        bookings.set(bookingId, booking);
        console.log("Booking confirmé via Bancontact pour", bookingId);
      }
    }

    res.status(200).json({ received: true });
  } catch (err) {
    console.error("Erreur webhook Stripe:", err);
    res.status(500).json({ error: "Erreur interne" });
  }
});

// --- Démarrage serveur ---
app.listen(PORT, () => {
  console.log(`4D Fashion Booking API running on port ${PORT}`);
});
