/**
 * backend/routes/stripeRoutes.js
 *
 * Stripe integration — Checkout sessions + Webhook handler.
 *
 * Routes:
 *   POST /api/stripe/create-checkout-session  (authenticated)
 *   POST /api/stripe/webhook                  (raw body — Stripe signature)
 *   GET  /api/stripe/subscription             (authenticated)
 *   POST /api/stripe/cancel-subscription      (authenticated)
 *
 * DB is the source of truth. Stripe is only used to initiate payment and
 * confirm completion. User plan fields are ONLY updated inside the webhook.
 */

const express = require('express');
const router = express.Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const auth = require('../middleware/auth');
const User = require('../models/User');
const Organization = require('../models/Organization');
const StripeEvent = require('../models/StripeEvent');

// ─── Stripe price ID mapping ──────────────────────────────────────────────────
// Create these products/prices in your Stripe dashboard and set the env vars.
// Fallback values are placeholders — replace with real price IDs.
const PRICE_IDS = {
  light_monthly:  process.env.STRIPE_PRICE_LIGHT_MONTHLY  || 'price_light_monthly',
  basic_monthly:  process.env.STRIPE_PRICE_BASIC_MONTHLY  || 'price_basic_monthly',
  pro_monthly:    process.env.STRIPE_PRICE_PRO_MONTHLY    || 'price_pro_monthly',
  light_annual:   process.env.STRIPE_PRICE_LIGHT_ANNUAL   || 'price_light_annual',
  basic_annual:   process.env.STRIPE_PRICE_BASIC_ANNUAL   || 'price_basic_annual',
  pro_annual:     process.env.STRIPE_PRICE_PRO_ANNUAL     || 'price_pro_annual',
  trial1_onetime: process.env.STRIPE_PRICE_TRIAL1         || 'price_trial1',
  trial2_onetime: process.env.STRIPE_PRICE_TRIAL2         || 'price_trial2',
};

// One-time plan scan allocations
const ONETIME_SCANS = {
  trial1_onetime: 1,
  trial2_onetime: 2,
};

// ─── POST /api/stripe/create-checkout-session ─────────────────────────────────
router.post('/create-checkout-session', auth, async (req, res) => {
  try {
    const { planType, billingCycle } = req.body;

    if (!planType || !billingCycle) {
      return res.status(400).json({ error: 'planType and billingCycle are required' });
    }

    const key = `${planType}_${billingCycle}`;
    const priceId = PRICE_IDS[key];

    if (!priceId || priceId.startsWith('price_') && priceId.length < 20) {
      return res.status(400).json({ error: `Unknown plan: ${key}` });
    }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Reuse existing Stripe customer or create a new one
    let customerId = user.stripeCustomerId;
    const isOnetime = billingCycle === 'onetime';
    const frontendBase = process.env.CLIENT_URL || 'http://localhost:3000';

    // Verify existing customer
    if (customerId) {
      try {
        const existingCustomer = await stripe.customers.retrieve(customerId);
        if (existingCustomer.deleted) {
          customerId = null;
        }
      } catch (err) {
        if (err.code === 'resource_missing' || err.statusCode === 404) {
          customerId = null; // Recreate if not found on Stripe
        } else {
          throw err;
        }
      }
    }

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        name: user.name,
        metadata: { userId: user._id.toString() }
      });
      customerId = customer.id;
      user.stripeCustomerId = customerId;
      await user.save();
    }

    const sessionParams = {
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      mode: isOnetime ? 'payment' : 'subscription',
      success_url: `${frontendBase}/profile?payment=success&plan=${key}`,
      cancel_url:  `${frontendBase}/profile?payment=cancelled`,
      metadata: {
        userId:       user._id.toString(),
        planType:     planType,
        billingCycle: billingCycle
      }
    };

    // For subscriptions, allow promotion codes
    if (!isOnetime) {
      sessionParams.allow_promotion_codes = true;
    }

    const session = await stripe.checkout.sessions.create(sessionParams);

    console.log(`💳 Checkout session created: ${session.id} for user ${user._id} (${key})`);

    res.json({ url: session.url, sessionId: session.id });
  } catch (err) {
    console.error('❌ Stripe checkout error:', err);
    // Send the exact Stripe error to the frontend so the user can see what's wrong
    res.status(500).json({ error: err.message, details: err.stack });
  }
});

// ─── GET /api/stripe/subscription ─────────────────────────────────────────────
router.get('/subscription', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      'planType billingCycle subscriptionStatus stripeSubscriptionId oneTimeRemainingScans proExpiresAt organizationId'
    );
    if (!user) return res.status(404).json({ error: 'User not found' });

    let org = null;
    if (user.organizationId) {
      org = await Organization.findById(user.organizationId);
    }

    res.json({
      success: true,
      plan: {
        planType:              user.planType,
        billingCycle:          user.billingCycle,
        subscriptionStatus:    user.subscriptionStatus,
        stripeSubscriptionId:  user.stripeSubscriptionId,
        oneTimeRemainingScans: user.oneTimeRemainingScans,
        monthlyScansUsed:      org ? org.scansUsed : 0,
        proExpiresAt:          user.proExpiresAt
      }
    });
  } catch (err) {
    console.error('❌ Subscription fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch subscription' });
  }
});

// ─── POST /api/stripe/cancel-subscription ────────────────────────────────────
router.post('/cancel-subscription', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (!user.stripeSubscriptionId) {
      return res.status(400).json({ error: 'No active subscription found' });
    }

    // Cancel at period end (user keeps access until expiry)
    const subscription = await stripe.subscriptions.update(user.stripeSubscriptionId, {
      cancel_at_period_end: true
    });

    console.log(`🚫 Subscription cancel_at_period_end set for user ${user.id}`);

    res.json({
      success: true,
      message: 'Subscription will be cancelled at the end of the billing period',
      cancelAt: new Date(subscription.cancel_at * 1000)
    });
  } catch (err) {
    console.error('❌ Cancel subscription error:', err.message);
    res.status(500).json({ error: 'Failed to cancel subscription', details: err.message });
  }
});

// ─── POST /api/stripe/webhook ─────────────────────────────────────────────────
// IMPORTANT: This route is mounted with express.raw() — not express.json()
// That mounting happens in server.js BEFORE the global express.json() middleware.
router.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (webhookSecret) {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      // Dev mode: no webhook secret configured — parse raw body manually
      console.warn('⚠️  STRIPE_WEBHOOK_SECRET not set — skipping signature verification (dev only)');
      event = JSON.parse(req.body.toString());
    }
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: `Webhook Error: ${err.message}` });
  }

  try {
    const existingEvent = await StripeEvent.findOne({ eventId: event.id });
    if (existingEvent) {
      console.log(`♻️  [webhook] Event ${event.id} already processed. Skipping.`);
      return res.json({ received: true });
    }

    switch (event.type) {

      // ── Checkout completed (both subscription and one-time) ──────────────────
      case 'checkout.session.completed': {
        const session = event.data.object;
        await handleCheckoutComplete(session);
        break;
      }

      // ── Subscription invoice paid (renewal) ──────────────────────────────────
      case 'invoice.paid': {
        const invoice = event.data.object;
        await handleInvoicePaid(invoice);
        break;
      }

      // ── Subscription cancelled / expired ─────────────────────────────────────
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        await handleSubscriptionDeleted(subscription);
        break;
      }

      // ── Subscription updated (e.g. plan change, trial end) ───────────────────
      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        await handleSubscriptionUpdated(subscription);
        break;
      }

      // ── Payment failed ────────────────────────────────────────────────────────
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        await handlePaymentFailed(invoice);
        break;
      }

      default:
        console.log(`ℹ️  Unhandled Stripe event: ${event.type}`);
    }

    await StripeEvent.create({ eventId: event.id });
  } catch (err) {
    console.error(`❌ Error processing webhook ${event.type}:`, err.message);
    // Still return 200 so Stripe does not retry — log for manual review
  }

  res.json({ received: true });
});

// ─── WEBHOOK HANDLERS ─────────────────────────────────────────────────────────

async function handleCheckoutComplete(session) {
  const { userId, planType, billingCycle } = session.metadata || {};
  if (!userId) { console.error('❌ [webhook] checkout.session.completed missing userId in metadata'); return; }

  const user = await User.findById(userId);
  if (!user) { console.error(`❌ [webhook] User ${userId} not found`); return; }

  const key = `${planType}_${billingCycle}`;
  console.log(`✅ [webhook] Checkout complete for user ${userId}: plan=${key}`);

  let org;
  if (user.organizationId) {
    org = await Organization.findById(user.organizationId);
  }

  if (!org) {
    org = new Organization({
      name: `${user.name}'s Organization`,
      ownerId: user._id,
      seatsUsed: 1
    });
    user.organizationId = org._id;
    user.role = 'owner';
    await user.save();
  }

  org.planType = planType || null;
  org.billingCycle = billingCycle || null;
  org.subscriptionStatus = 'active';

  if (billingCycle === 'onetime') {
    org.seatsAllowed = 1;
    org.oneTimeRemainingScans = ONETIME_SCANS[key] || 1;
    org.stripeSubscriptionId = null;
    org.expiresAt = null;
  } else {
    const PLAN_CONFIGS = {
      light: { seatsAllowed: 1, scanLimit: 3 },
      basic: { seatsAllowed: 3, scanLimit: 5 },
      pro: { seatsAllowed: 5, scanLimit: 10 },
      trial1: { seatsAllowed: 1, scanLimit: 0 },
      trial2: { seatsAllowed: 1, scanLimit: 0 }
    };
    const config = PLAN_CONFIGS[planType] || { seatsAllowed: 1, scanLimit: 0 };
    org.seatsAllowed = config.seatsAllowed;
    org.scanLimit = config.scanLimit;
    org.stripeSubscriptionId = session.subscription || null;
    const months = billingCycle === 'annual' ? 12 : 1;
    org.expiresAt = new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000);
  }

  org.scansUsed = 0;
  org.lastScanReset = new Date();
  await org.save();

  // Legacy fallback for UI logic
  user.planType = planType || null;
  user.billingCycle = billingCycle || null;
  user.subscriptionStatus = 'active';
  if (billingCycle === 'onetime') {
    user.oneTimeRemainingScans = ONETIME_SCANS[key] || 1;
    user.proExpiresAt = null;
  } else {
    user.stripeSubscriptionId = session.subscription || null;
    const months = billingCycle === 'annual' ? 12 : 1;
    user.proExpiresAt = new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000);
  }
  if (['pro', 'basic', 'light'].includes(planType)) {
    user.accountType = planType === 'pro' ? 'pro' : 'free';
  }
  await user.save();
  console.log(`✅ [webhook] User ${userId} plan set to ${key} on Org ${org._id}`);
}

async function handleInvoicePaid(invoice) {
  if (!invoice.subscription) return; // one-time payment, skip

  const subscription = await stripe.subscriptions.retrieve(invoice.subscription);
  const customerId = invoice.customer;

  const user = await User.findOne({ stripeCustomerId: customerId });
  if (!user) { console.warn(`⚠️  [webhook] No user for customer ${customerId}`); return; }

  let org;
  if (user.organizationId) {
    org = await Organization.findById(user.organizationId);
  }

  if (org) {
    org.subscriptionStatus = 'active';
    org.stripeSubscriptionId = invoice.subscription;
    org.scansUsed = 0;
    org.lastScanReset = new Date();
    const months = org.billingCycle === 'annual' ? 12 : 1;
    org.expiresAt = new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000);
    await org.save();
  }

  // Renew: reset monthly counters and extend expiry
  user.subscriptionStatus  = 'active';
  user.stripeSubscriptionId = invoice.subscription;
  user.totalTargetsUsed    = 0;
  user.scanUsagePerTarget  = {};
  user.lastResetDate       = new Date();

  const months = user.billingCycle === 'annual' ? 12 : 1;
  user.proExpiresAt = new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000);

  await user.save();
  console.log(`♻️  [webhook] Invoice paid — user ${user.id} plan renewed`);
}

async function handleSubscriptionDeleted(subscription) {
  const customerId = subscription.customer;
  const user = await User.findOne({ stripeCustomerId: customerId });
  if (!user) return;

  let org;
  if (user.organizationId) {
    org = await Organization.findById(user.organizationId);
  }
  if (org) {
    org.subscriptionStatus = 'canceled';
    org.planType = null;
    org.billingCycle = null;
    org.stripeSubscriptionId = null;
    org.expiresAt = null;
    await org.save();
  }

  user.subscriptionStatus   = 'canceled';
  user.planType             = null;
  user.billingCycle         = null;
  user.stripeSubscriptionId = null;
  user.accountType          = 'free';
  user.proExpiresAt         = null;
  await user.save();
  console.log(`🚫 [webhook] Subscription deleted — user ${user.id} downgraded to free`);
}

async function handleSubscriptionUpdated(subscription) {
  const customerId = subscription.customer;
  const user = await User.findOne({ stripeCustomerId: customerId });
  if (!user) return;

  let org;
  if (user.organizationId) {
    org = await Organization.findById(user.organizationId);
  }
  if (org) {
    org.subscriptionStatus = subscription.status;
    if (subscription.status === 'active' || subscription.status === 'trialing') {
      const periodEnd = subscription.current_period_end;
      if (periodEnd) org.expiresAt = new Date(periodEnd * 1000);
    }
    await org.save();
  }

  user.subscriptionStatus = subscription.status; // active | past_due | canceled | trialing
  if (subscription.status === 'active' || subscription.status === 'trialing') {
    const periodEnd = subscription.current_period_end;
    if (periodEnd) user.proExpiresAt = new Date(periodEnd * 1000);
  }
  await user.save();
  console.log(`🔄 [webhook] Subscription updated — user ${user.id} status=${subscription.status}`);
}

async function handlePaymentFailed(invoice) {
  const customerId = invoice.customer;
  const user = await User.findOne({ stripeCustomerId: customerId });
  if (!user) return;

  let org;
  if (user.organizationId) {
    org = await Organization.findById(user.organizationId);
  }
  if (org) {
    org.subscriptionStatus = 'past_due';
    await org.save();
  }

  user.subscriptionStatus = 'past_due';
  await user.save();
  console.warn(`⚠️  [webhook] Payment failed — user ${user.id} marked past_due`);
}

module.exports = router;
