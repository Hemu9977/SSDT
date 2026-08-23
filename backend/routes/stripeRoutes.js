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
const requireOrg = require('../middleware/requireOrg');
const User = require('../models/User');
const Organization = require('../models/Organization');
const StripeEvent = require('../models/StripeEvent');

// ─── Stripe price ID mapping ──────────────────────────────────────────────────
// Create these products/prices in your Stripe dashboard and set the env vars.
// Fallback values are placeholders — replace with real price IDs.
const PRICE_IDS = {
  light_monthly: process.env.STRIPE_PRICE_LIGHT_MONTHLY || 'price_light_monthly',
  basic_monthly: process.env.STRIPE_PRICE_BASIC_MONTHLY || 'price_basic_monthly',
  pro_monthly: process.env.STRIPE_PRICE_PRO_MONTHLY || 'price_pro_monthly',
  light_annual: process.env.STRIPE_PRICE_LIGHT_ANNUAL || 'price_light_annual',
  basic_annual: process.env.STRIPE_PRICE_BASIC_ANNUAL || 'price_basic_annual',
  pro_annual: process.env.STRIPE_PRICE_PRO_ANNUAL || 'price_pro_annual',
  trial1_onetime: process.env.STRIPE_PRICE_TRIAL1 || 'price_trial1',
  trial2_onetime: process.env.STRIPE_PRICE_TRIAL2 || 'price_trial2',
};

// One-time plan scan allocations and subscription provisioning (seats + monthly
// scan allowance) both come from the plan catalog — see config/planCatalog.js.
const { ONETIME_SCANS, PLAN_PROVISIONING } = require('../config/planCatalog');

// Validity window for a purchased one-off scan credit batch, from purchase.
const CREDIT_VALIDITY_DAYS = 90;

// ─── Japanese consumption tax ─────────────────────────────────────────────────
// Every STRIPE_PRICE_* above is a TAX-EXCLUSIVE amount (e.g. Light monthly is
// ¥30,000). The plan cards show that figure plus a tax-inclusive total derived at
// TAX_RATE in frontend/src/pages/Profile.jsx, so Stripe must actually add the same
// tax or the customer is charged less than the total they were shown.
//
// This uses a FIXED Stripe Tax Rate rather than automatic_tax on purpose: the UI
// hardcodes 10%, whereas automatic_tax resolves by customer location and would
// charge a different total than the page promised for anyone outside Japan.
//
// Create the rate once in the Stripe dashboard (Products -> Tax rates): 10%,
// exclusive, region Japan. Put its id (txr_...) in STRIPE_TAX_RATE_ID.
// IMPORTANT: if you change the percentage here, change TAX_RATE in Profile.jsx to
// match — nothing enforces that at runtime.
const TAX_RATE_ID = process.env.STRIPE_TAX_RATE_ID || null;

if (!TAX_RATE_ID) {
  console.warn(
    '⚠️  [stripe] STRIPE_TAX_RATE_ID is not set. Checkout is DISABLED until it is: ' +
    'the pricing UI quotes a tax-inclusive total, so taking payment without the tax ' +
    'rate attached would charge customers less than they were shown.'
  );
}

// ─── POST /api/stripe/create-checkout-session ─────────────────────────────────
router.post('/create-checkout-session', auth, async (req, res) => {
  try {
    const { planType, billingCycle } = req.body;

    if (!planType || !billingCycle) {
      return res.status(400).json({ error: 'planType and billingCycle are required' });
    }

    // Refuse rather than undercharge. The plan cards quote a tax-inclusive total, so
    // creating a session without the tax rate attached would take LESS money than the
    // customer was shown. Failing here is loud and fixable; a silent shortfall is not.
    if (!TAX_RATE_ID) {
      console.error('❌ [stripe] Checkout blocked: STRIPE_TAX_RATE_ID is not configured.');
      return res.status(503).json({
        code: 'TAX_NOT_CONFIGURED',
        error: 'Billing is temporarily unavailable: tax configuration is missing.'
      });
    }

    const key = `${planType}_${billingCycle}`;
    const priceId = PRICE_IDS[key];

    if (!priceId || priceId.startsWith('price_') && priceId.length < 20) {
      return res.status(400).json({ error: `Unknown plan: ${key}` });
    }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isOnetime = billingCycle === 'onetime';

    if (user.organizationId) {
      const orgForGuard = await Organization.findById(user.organizationId);

      // Only an org owner/admin may purchase a plan or a top-up.
      if (orgForGuard && !['owner', 'admin'].includes(user.role)) {
        return res.status(403).json({
          code: 'INSUFFICIENT_ROLE',
          error: 'Only the organization owner or an admin can purchase a plan or top-up.'
        });
      }

      // Block a SECOND recurring subscription while one is already active —
      // that path would overwrite planType/billingCycle/stripeSubscriptionId
      // on the org (see handleCheckoutComplete). One-time top-ups are always
      // allowed through regardless of subscription state.
      if (!isOnetime && orgForGuard && orgForGuard.subscriptionStatus === 'active' && orgForGuard.billingCycle && orgForGuard.billingCycle !== 'onetime') {
        return res.status(409).json({
          code: 'ALREADY_SUBSCRIBED',
          error: 'You already have an active subscription. Cancel it before purchasing a different plan.'
        });
      }
    }

    // Reuse existing Stripe customer or create a new one
    let customerId = user.stripeCustomerId;
    const frontendBase = process.env.FRONTEND_URL || 'http://localhost:3000';

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
    }

    user.stripePending = true;
    await user.save();

    const sessionParams = {
      customer: customerId,
      // tax_rates attaches the fixed consumption-tax rate so Stripe collects the same
      // tax-inclusive total the plan card quoted. Works for both 'subscription' and
      // one-time 'payment' modes.
      line_items: [{ price: priceId, quantity: 1, tax_rates: [TAX_RATE_ID] }],
      mode: isOnetime ? 'payment' : 'subscription',
      success_url: `${frontendBase}/profile?payment=success&plan=${key}&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${frontendBase}/profile?payment=cancelled`,
      metadata: {
        userId: user._id.toString(),
        planType: planType,
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
    res.status(500).json({ error: 'Failed to create checkout session' });
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

    const now = new Date();
    const liveCreditBatches = org
      ? (org.scanCredits || []).filter(c => c.scansRemaining > 0 && c.expiresAt && c.expiresAt > now)
      : [];
    const extraScansRemaining = liveCreditBatches.reduce((sum, c) => sum + c.scansRemaining, 0);
    const extraScansExpiresAt = liveCreditBatches.length
      ? liveCreditBatches.reduce((earliest, c) => (c.expiresAt < earliest ? c.expiresAt : earliest), liveCreditBatches[0].expiresAt)
      : null;

    // Org is the source of truth; User fields are a legacy fallback for
    // pre-migration accounts that still have plan data on the User document.
    res.json({
      success: true,
      plan: {
        planType: org ? org.planType : user.planType,
        billingCycle: org ? org.billingCycle : user.billingCycle,
        subscriptionStatus: org ? org.subscriptionStatus : user.subscriptionStatus,
        stripeSubscriptionId: org ? org.stripeSubscriptionId : user.stripeSubscriptionId,
        oneTimeRemainingScans: org ? (org.oneTimeRemainingScans || 0) : (user.oneTimeRemainingScans || 0),
        extraScansRemaining,
        extraScansExpiresAt,
        monthlyScansUsed: org ? org.scansUsed : 0,
        proExpiresAt: org ? org.expiresAt : user.proExpiresAt
      }
    });
  } catch (err) {
    console.error('❌ Subscription fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch subscription' });
  }
});

// ─── POST /api/stripe/sync-checkout-session ──────────────────────────────────
// Lets the profile page confirm the just-completed Checkout session immediately
// after Stripe redirects back, instead of relying only on webhook timing.
router.post('/sync-checkout-session', auth, async (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId) {
      return res.status(400).json({ error: 'sessionId is required' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const metadataUserId = session.metadata?.userId;

    if (!metadataUserId || metadataUserId !== req.user.id) {
      return res.status(403).json({ error: 'Checkout session does not belong to this user' });
    }

    const isComplete = session.status === 'complete';
    const isPaid = session.payment_status === 'paid' || session.mode === 'subscription';

    if (!isComplete || !isPaid) {
      return res.status(409).json({
        error: 'Checkout session is not fully paid yet',
        status: session.status,
        paymentStatus: session.payment_status
      });
    }

    await handleCheckoutComplete(session);

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Checkout session sync error:', err.message);
    res.status(500).json({ error: 'Failed to sync checkout session' });
  }
});

// ─── POST /api/stripe/cancel-subscription ────────────────────────────────────
router.post('/cancel-subscription', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Plan state (including the subscription ID) lives on the Organization for the
    // org-based flow. Fall back to the User field only for legacy pre-migration
    // accounts that still carry stripeSubscriptionId on the user document.
    let org = null;
    if (user.organizationId) {
      org = await Organization.findById(user.organizationId);
    }
    const subscriptionId = (org && org.stripeSubscriptionId) || user.stripeSubscriptionId;

    if (!subscriptionId) {
      return res.status(400).json({ error: 'No active subscription found' });
    }

    // Cancel at period end (user keeps access until expiry)
    const subscription = await stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true
    });

    console.log(`🚫 Subscription cancel_at_period_end set for user ${user.id}`);

    res.json({
      success: true,
      message: 'Subscription will be cancelled at the end of the billing period',
      cancelAt: new Date(subscription.cancel_at * 1000)
    });
  } catch (err) {
    console.error('❌ Cancel subscription error:', err);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

// ─── POST /api/stripe/webhook ─────────────────────────────────────────────────
// IMPORTANT: This route is mounted with express.raw() — not express.json()
// That mounting happens in server.js BEFORE the global express.json() middleware.
router.post('/webhook', async (req, res) => {
  console.log("🔥 Webhook hit");
  console.log("Is Buffer:", req.body instanceof Buffer);
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    if (webhookSecret) {
      if (!Buffer.isBuffer(req.body)) {
        throw new Error('Webhook payload must be a Buffer for signature verification');
      }
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      // Hard-fail in production: an unsigned webhook is a critical misconfig
      // that would let anyone push fake billing events.
      if (process.env.NODE_ENV === 'production') {
        console.error('❌ STRIPE_WEBHOOK_SECRET not set in production — refusing unsigned webhook');
        return res.status(500).json({ error: 'Webhook misconfigured' });
      }

      console.warn('⚠️ STRIPE_WEBHOOK_SECRET not set — dev mode');

      if (Buffer.isBuffer(req.body)) {
        event = JSON.parse(req.body.toString());
      } else {
        event = req.body; // fallback if already parsed
      }
    }
  } catch (err) {
    console.error('❌ Webhook signature verification failed:', err.message);
    // FIX 1: Return 400 so Stripe knows signature verification failed and can retry
    return res.status(400).json({ error: 'Webhook signature verification failed' });
  }

  // ── Idempotency: claim the event BEFORE processing ──────────────────────────
  // The unique index on eventId makes this an atomic claim. Two concurrent
  // deliveries of the same event can't both win the insert, so processing runs
  // at most once. If processing later fails, we delete the claim (below) so
  // Stripe's retry can reprocess.
  try {
    await StripeEvent.create({ eventId: event.id });
  } catch (err) {
    if (err && err.code === 11000) {
      console.log(`♻️  [webhook] Event ${event.id} already claimed/processed. Skipping.`);
      return res.json({ received: true });
    }
    console.error('❌ [webhook] Failed to record event for idempotency:', err.message);
    return res.status(500).json({ error: 'Webhook idempotency store failed' });
  }

  try {
    console.log(`🔔 [webhook] Received event: ${event.type}`);
    switch (event.type) {

      // ── Checkout completed (both subscription and one-time) ──────────────────
      case 'checkout.session.completed': {
        const session = event.data.object;
        await handleCheckoutComplete(session);
        break;
      }

      // ── Checkout abandoned / expired (clears stripePending so the user
      //    isn't stuck behind ORG_CREATING on their next scan) ────────────────
      case 'checkout.session.expired': {
        const session = event.data.object;
        await handleCheckoutExpired(session);
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
  } catch (err) {
    console.error(`❌ Error processing webhook ${event?.type}:`, err.message, err.stack);
    // Processing failed — release the idempotency claim so Stripe's retry can
    // reprocess this event (otherwise the claim would block it forever).
    try {
      await StripeEvent.deleteOne({ eventId: event.id });
    } catch (cleanupErr) {
      console.error('⚠️  [webhook] Failed to release idempotency claim:', cleanupErr.message);
    }
    // Return 500 so Stripe retries delivery — DB update did NOT succeed
    return res.status(500).json({ error: 'Webhook processing failed' });
  }

  res.json({ received: true });
});

// ─── WEBHOOK HANDLERS ─────────────────────────────────────────────────────────

async function handleCheckoutComplete(session) {
  console.log(`🚀 [webhook] Starting checkout.session.completed for session ${session.id}`);
  const { userId, planType, billingCycle } = session.metadata || {};

  // FIX 3: Validate all required metadata fields up front before touching the DB
  if (!userId) {
    throw new Error('checkout.session.completed missing userId in metadata');
  }
  if (!planType || !billingCycle) {
    throw new Error(`checkout.session.completed missing planType or billingCycle in metadata for session ${session.id}`);
  }
  const key = `${planType}_${billingCycle}`;
  if (!PRICE_IDS[key]) {
    throw new Error(`checkout.session.completed unknown plan key: ${key} for session ${session.id}`);
  }

  console.log(`✅ [webhook] Checkout complete for user ${userId}: plan=${key}`);

  const user = await User.findById(userId);
  if (!user) { throw new Error(`User ${userId} not found`); }

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
    // FIX 5: Do NOT save user here — deferred to final Promise.all below
    // so org is fully configured before anything is written to DB
  }

  // A top-up is a one-time purchase by a user whose org already has a real,
  // active recurring subscription. It must add a scan credit batch WITHOUT
  // touching planType/billingCycle/subscriptionStatus/stripeSubscriptionId/
  // seatsAllowed/scanLimit/expiresAt/scansUsed — otherwise the subscription
  // would be silently clobbered by the generic plan-assignment logic below.
  // A legacy pure one-time org (billingCycle already 'onetime', no real
  // subscription) buying a second trial does NOT take this branch — it falls
  // through to the existing onetime logic further down, which now stacks
  // instead of overwriting.
  const isTopUp =
    billingCycle === 'onetime' &&
    org.subscriptionStatus === 'active' &&
    org.billingCycle && org.billingCycle !== 'onetime' &&
    !!org.planType;

  if (isTopUp) {
    return await handleTopUpPurchase(org, user, session, key);
  }

  if (org.stripeCheckoutSessionId === session.id && org.subscriptionStatus === 'active') {
    user.stripePending = false;
    await user.save();
    console.log(`♻️  [webhook] Checkout session ${session.id} already applied for Org ${org._id}.`);
    return;
  }

  org.planType = planType || null;
  org.billingCycle = billingCycle || null;
  org.subscriptionStatus = 'active';
  org.stripeCheckoutSessionId = session.id;

  if (billingCycle === 'onetime') {
    org.seatsAllowed = 1;
    // Additive, not overwrite — a legacy trial org buying a second trial
    // stacks its scans instead of losing the first batch's remainder.
    org.oneTimeRemainingScans = (org.oneTimeRemainingScans || 0) + (ONETIME_SCANS[key] || 1);
    org.scanCredits = org.scanCredits || [];
    org.scanCredits.push({
      source: key,
      scansTotal: ONETIME_SCANS[key] || 1,
      scansRemaining: ONETIME_SCANS[key] || 1,
      purchasedAt: new Date(),
      expiresAt: new Date(Date.now() + CREDIT_VALIDITY_DAYS * 24 * 60 * 60 * 1000),
      stripeCheckoutSessionId: session.id,
      vulnerabilityAccessLevel: key === 'trial2_onetime' ? 'all' : 'critical-high',
      source_type: 'stripe'
    });
    org.scanCredits.sort((a, b) => a.expiresAt - b.expiresAt);
    org.stripeSubscriptionId = null;
    org.expiresAt = new Date(Date.now() + CREDIT_VALIDITY_DAYS * 24 * 60 * 60 * 1000);
  } else {
    const config = PLAN_PROVISIONING[planType] || { seatsAllowed: 1, scanLimit: 0 };
    org.seatsAllowed = config.seatsAllowed;
    org.scanLimit = config.scanLimit;
    org.stripeSubscriptionId = session.subscription || null;
    const months = billingCycle === 'annual' ? 12 : 1;
    org.expiresAt = new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000);
  }

  org.scansUsed = 0;
  org.targetScanCounts = {};
  org.lastScanReset = new Date();

  // Organization is the source of truth for plan state.
  // User retains only `accountType` as a coarse legacy flag still consulted
  // by isPro() when no org is loaded.
  if (['pro', 'basic', 'light'].includes(planType)) {
    user.accountType = 'paid';
  }
  user.stripePending = false;

  // FIX 4 + 5: Run both saves in parallel — eliminates sequential write latency
  // and closes the partial-state window from the early user.save() that was here before
  await Promise.all([org.save(), user.save()]);
  console.log(`✅ [webhook] User ${userId} plan set to ${key} on Org ${org._id}. DB update complete.`);
}

// Appends a scan credit batch for a subscriber buying a one-off top-up.
// Deliberately does NOT touch planType/billingCycle/subscriptionStatus/
// stripeSubscriptionId/seatsAllowed/scanLimit/expiresAt/scansUsed/
// targetScanCounts/lastScanReset — those all describe the recurring
// subscription, which this purchase must leave completely untouched.
//
// Idempotency: `sync-checkout-session` calls handleCheckoutComplete() (and
// therefore this function) OUTSIDE the StripeEvent unique-claim guard that
// protects the /webhook route, so this needs its own guard against being
// invoked twice for the same session (once via sync, once via the real
// webhook delivery).
async function handleTopUpPurchase(org, user, session, key) {
  const alreadyGranted = (org.scanCredits || []).some(c => c.stripeCheckoutSessionId === session.id);
  if (alreadyGranted) {
    await User.updateOne({ _id: user._id }, { $set: { stripePending: false } });
    console.log(`♻️  [webhook] Top-up session ${session.id} already granted for Org ${org._id}. Skipping.`);
    return;
  }

  const scansGranted = ONETIME_SCANS[key] || 1;
  const batch = {
    source: key,
    scansTotal: scansGranted,
    scansRemaining: scansGranted,
    purchasedAt: new Date(),
    expiresAt: new Date(Date.now() + CREDIT_VALIDITY_DAYS * 24 * 60 * 60 * 1000),
    stripeCheckoutSessionId: session.id,
    vulnerabilityAccessLevel: key === 'trial2_onetime' ? 'all' : 'critical-high',
    source_type: 'stripe'
  };

  await Organization.updateOne(
    { _id: org._id, 'scanCredits.stripeCheckoutSessionId': { $ne: session.id } },
    {
      $push: { scanCredits: { $each: [batch], $sort: { expiresAt: 1 } } },
      $inc: { oneTimeRemainingScans: scansGranted }
    }
  );
  await User.updateOne({ _id: user._id }, { $set: { stripePending: false } });

  console.log(`✅ [webhook] Top-up granted: ${scansGranted} scans (${key}) to Org ${org._id}, session ${session.id}.`);
}

async function handleCheckoutExpired(session) {
  const userId = session.metadata?.userId;
  if (!userId) {
    console.warn(`⚠️  [webhook] checkout.session.expired missing userId metadata (session ${session.id})`);
    return;
  }
  await User.updateOne({ _id: userId }, { $set: { stripePending: false } });
  console.log(`⌛ [webhook] Checkout session ${session.id} expired — cleared stripePending for user ${userId}`);
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
    org.targetScanCounts = {};
    org.lastScanReset = new Date();
    const months = org.billingCycle === 'annual' ? 12 : 1;
    org.expiresAt = new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000);
    await org.save();
  }

  console.log(`♻️  [webhook] Invoice paid — user ${user.id} plan renewed (org=${org?._id || 'none'})`);
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

  // Keep accountType in sync — isPro() falls back to it when no org is loaded.
  user.accountType = 'free';
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

  console.warn(`⚠️  [webhook] Payment failed — user ${user.id} marked past_due`);
}

module.exports = router;
