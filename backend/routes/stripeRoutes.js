/**
 * backend/routes/stripeRoutes.js
 *
 * Stripe integration — Checkout sessions + Webhook handler.
 *
 * Routes:
 *   POST /api/stripe/create-checkout-session  (authenticated, org owner/admin)
 *   POST /api/stripe/sync-checkout-session    (authenticated)
 *   POST /api/stripe/cancel-subscription      (authenticated, org owner/admin)
 *   POST /api/stripe/webhook                  (Stripe-signed; exported as
 *        `webhookHandler` and mounted by server.js with express.raw(), outside
 *        the API rate limiter)
 *
 * Checkout grants the plan or credits (handleCheckoutComplete). Everything that
 * happens to a subscription afterwards — renewal, past_due, pending cancellation,
 * the downgrade to Free — is written only by services/subscriptionLifecycle.js.
 */

const express = require('express');
const router = express.Router();
const stripe = require('../config/stripe');
const auth = require('../middleware/auth');
const User = require('../models/User');
const Organization = require('../models/Organization');
const StripeEvent = require('../models/StripeEvent');
const {
  periodEndOf,
  subscriptionIdOf,
  isCancellationScheduled,
  hasLiveSubscription,
  applySubscription,
  reconcileById,
  refreshForPurchase
} = require('../services/subscriptionLifecycle');
const { isSubscriptionEntitled } = require('../utils/entitlement');

// ─── Stripe price IDs ─────────────────────────────────────────────────────────
// One env var per purchasable plan key (`${planType}_${billingCycle}`). The keys
// are the complete list of plans this backend sells; a plan whose env var is
// unset is refused at checkout (PLAN_NOT_CONFIGURED) instead of being sent to
// Stripe with a made-up price id.
const PRICE_ENV = {
  light_monthly: 'STRIPE_PRICE_LIGHT_MONTHLY',
  basic_monthly: 'STRIPE_PRICE_BASIC_MONTHLY',
  pro_monthly: 'STRIPE_PRICE_PRO_MONTHLY',
  light_annual: 'STRIPE_PRICE_LIGHT_ANNUAL',
  basic_annual: 'STRIPE_PRICE_BASIC_ANNUAL',
  pro_annual: 'STRIPE_PRICE_PRO_ANNUAL',
  trial1_onetime: 'STRIPE_PRICE_TRIAL1',
  trial2_onetime: 'STRIPE_PRICE_TRIAL2',
};
const PRICE_IDS = Object.fromEntries(
  Object.entries(PRICE_ENV).map(([key, env]) => [key, process.env[env] || null])
);
const isPlanKey = (key) => Object.prototype.hasOwnProperty.call(PRICE_ENV, key);

const missingPriceEnv = Object.entries(PRICE_ENV).filter(([key]) => !PRICE_IDS[key]).map(([, env]) => env);
if (missingPriceEnv.length) {
  console.warn(`⚠️  [stripe] Price ids not set — these plans cannot be purchased: ${missingPriceEnv.join(', ')}`);
}

// Stripe sends the customer back here after checkout. Without it the success page
// would point at localhost, so production must set it.
const FRONTEND_BASE = process.env.FRONTEND_URL || 'http://localhost:3000';
if (!process.env.FRONTEND_URL && process.env.NODE_ENV === 'production') {
  console.error('❌ [stripe] FRONTEND_URL is not set — checkout would return customers to localhost.');
}

// One-time plan scan allocations and subscription provisioning (seats + monthly
// scan allowance) both come from the plan catalog — see config/planCatalog.js.
const { ONETIME_SCANS, PLAN_PROVISIONING } = require('../config/planCatalog');

// Validity window for a purchased one-off scan credit batch, from purchase.
const CREDIT_VALIDITY_DAYS = 90;

// ─── Japanese consumption tax ─────────────────────────────────────────────────
// Every STRIPE_PRICE_* above is a TAX-EXCLUSIVE amount (e.g. Light monthly is
// ¥50,000). The plan cards show that figure plus a tax-inclusive total derived at
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
      return res.status(400).json({ code: 'INVALID_PLAN', error: 'planType and billingCycle are required' });
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
    if (!isPlanKey(key)) {
      return res.status(400).json({ code: 'INVALID_PLAN', error: `Unknown plan: ${key}` });
    }
    const priceId = PRICE_IDS[key];
    if (!priceId) {
      console.error(`❌ [stripe] Checkout blocked: ${PRICE_ENV[key]} is not configured.`);
      return res.status(503).json({ code: 'PLAN_NOT_CONFIGURED', error: 'This plan is temporarily unavailable.' });
    }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ code: 'USER_NOT_FOUND', error: 'User not found' });

    const isOnetime = billingCycle === 'onetime';

    if (user.organizationId) {
      // Re-read from Stripe when the stored state may be stale, so a subscription
      // that has really ended doesn't block buying a new one.
      const orgForGuard = await refreshForPurchase(await Organization.findById(user.organizationId));

      // Only an org owner/admin may purchase a plan or a top-up.
      if (orgForGuard && !['owner', 'admin'].includes(user.role)) {
        return res.status(403).json({
          code: 'INSUFFICIENT_ROLE',
          error: 'Only the organization owner or an admin can purchase a plan or top-up.'
        });
      }

      // Block a SECOND subscription while the org still has one that has not
      // ended — active, scheduled to cancel, or past_due/unpaid (Stripe is still
      // charging it). Replacing it would leave the old one billing the customer
      // with nothing attached to it. One-time top-ups are always allowed.
      if (!isOnetime && hasLiveSubscription(orgForGuard)) {
        return res.status(409).json({
          code: 'ALREADY_SUBSCRIBED',
          error: 'You already have an active subscription. Cancel it before purchasing a different plan.'
        });
      }
    }

    // Reuse existing Stripe customer or create a new one
    let customerId = user.stripeCustomerId;

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
      success_url: `${FRONTEND_BASE}/profile?payment=success&plan=${key}&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_BASE}/profile?payment=cancelled`,
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
    res.status(500).json({ code: 'CHECKOUT_FAILED', error: 'Failed to create checkout session' });
  }
});

// ─── POST /api/stripe/sync-checkout-session ──────────────────────────────────
// Lets the profile page confirm the just-completed Checkout session immediately
// after Stripe redirects back, instead of relying only on webhook timing.
router.post('/sync-checkout-session', auth, async (req, res) => {
  try {
    const { sessionId } = req.body;

    if (!sessionId || typeof sessionId !== 'string') {
      return res.status(400).json({ code: 'SESSION_ID_REQUIRED', error: 'sessionId is required' });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const metadataUserId = session.metadata?.userId;

    if (!metadataUserId || metadataUserId !== req.user.id) {
      return res.status(403).json({ code: 'CHECKOUT_SESSION_FORBIDDEN', error: 'Checkout session does not belong to this user' });
    }

    const isComplete = session.status === 'complete';
    const isPaid = session.payment_status === 'paid' || session.mode === 'subscription';

    if (!isComplete || !isPaid) {
      return res.status(409).json({
        code: 'CHECKOUT_NOT_PAID',
        error: 'Checkout session is not fully paid yet',
        status: session.status,
        paymentStatus: session.payment_status
      });
    }

    await applyCheckoutOnce(session);

    res.json({ success: true });
  } catch (err) {
    if (err && err.code === 'CHECKOUT_IN_PROGRESS') {
      // The webhook is applying this session right now. Non-2xx on purpose: the
      // profile page then polls until the plan shows up.
      return res.status(409).json({ code: 'CHECKOUT_PROCESSING', error: 'Checkout is still being applied' });
    }
    console.error('❌ Checkout session sync error:', err.message);
    res.status(500).json({ code: 'CHECKOUT_SYNC_FAILED', error: 'Failed to sync checkout session' });
  }
});

// ─── POST /api/stripe/cancel-subscription ────────────────────────────────────
// Turns auto-pay off. The subscription is cancelled at the END of the current
// billing period: the plan keeps working until then, and when Stripe ends it the
// org is downgraded to Free (services/subscriptionLifecycle.js). No refund, no
// proration, and no undo.
router.post('/cancel-subscription', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ code: 'USER_NOT_FOUND', error: 'User not found' });

    const org = user.organizationId ? await Organization.findById(user.organizationId) : null;
    if (!org || !org.stripeSubscriptionId) {
      return res.status(400).json({ code: 'NO_SUBSCRIPTION', error: 'No active subscription found' });
    }

    // Same rule as purchasing: billing decisions belong to the org owner/admin.
    if (!['owner', 'admin'].includes(user.role)) {
      return res.status(403).json({
        code: 'INSUFFICIENT_ROLE',
        error: 'Only the organization owner or an admin can cancel the subscription.'
      });
    }

    // Already scheduled — repeat clicks and retries are a no-op, not an error.
    if (org.cancelAtPeriodEnd) {
      return res.json({ success: true, alreadyScheduled: true, cancelAt: org.expiresAt });
    }

    const subscription = await stripe.subscriptions.update(org.stripeSubscriptionId, {
      cancel_at_period_end: true
    });

    // Record the pending cancellation now rather than waiting for the
    // customer.subscription.updated webhook, so the page shows it immediately.
    await applySubscription(org, subscription);

    const cancelAt = (isCancellationScheduled(subscription) && subscription.cancel_at)
      ? new Date(subscription.cancel_at * 1000)
      : periodEndOf(subscription);

    console.log(`🚫 Subscription ${subscription.id} set to cancel at period end (${cancelAt && cancelAt.toISOString()}) for org ${org._id} by user ${user.id}`);

    res.json({ success: true, cancelAt });
  } catch (err) {
    console.error('❌ Cancel subscription error:', err);
    res.status(500).json({ code: 'CANCEL_FAILED', error: 'Failed to cancel subscription' });
  }
});

// ─── POST /api/stripe/webhook ─────────────────────────────────────────────────
// Mounted by server.js (not by this router) with express.raw(), BEFORE the global
// express.json() — the signature is computed over the raw bytes — and outside
// the per-IP API rate limiter, which Stripe's delivery bursts (e.g. renewals at
// the start of a month) would trip. Authenticity comes from the signature.
async function webhookHandler(req, res) {
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
        return res.status(500).json({ code: 'WEBHOOK_MISCONFIGURED', error: 'Webhook misconfigured' });
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
    return res.status(400).json({ code: 'WEBHOOK_SIGNATURE_INVALID', error: 'Webhook signature verification failed' });
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
    return res.status(500).json({ code: 'WEBHOOK_FAILED', error: 'Webhook idempotency store failed' });
  }

  try {
    console.log(`🔔 [webhook] Received event: ${event.type}`);
    switch (event.type) {

      // ── Checkout completed (both subscription and one-time) ──────────────────
      case 'checkout.session.completed': {
        const session = event.data.object;
        await applyCheckoutOnce(session);
        break;
      }

      // ── Checkout abandoned / expired (clears stripePending so the user
      //    isn't stuck behind ORG_CREATING on their next scan) ────────────────
      case 'checkout.session.expired': {
        const session = event.data.object;
        await handleCheckoutExpired(session);
        break;
      }

      // ── Subscription lifecycle ───────────────────────────────────────────────
      // updated: renewal, past_due, or a cancellation being scheduled
      //          (cancel_at_period_end) — the plan keeps working until it ends.
      // deleted: the subscription has ended → the org is downgraded to Free.
      // invoice.paid / payment_failed: renewal succeeded / failed.
      //
      // All four are handled the same way: take only the subscription id from the
      // payload and apply Stripe's CURRENT state to the org that owns that id
      // (services/subscriptionLifecycle.js). Payload contents are never trusted, so
      // duplicate, late or out-of-order deliveries cannot write stale state.
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted':
      case 'invoice.paid':
      case 'invoice.payment_failed': {
        const subscriptionId = subscriptionIdOf(event.data.object);
        if (!subscriptionId) {
          // One-time (top-up / trial) invoices belong to no subscription.
          console.log(`ℹ️  [webhook] ${event.type} ${event.data.object.id} has no subscription — ignored.`);
          break;
        }
        const result = await reconcileById(subscriptionId);
        console.log(`🔄 [webhook] ${event.type} for ${subscriptionId}: ${result.applied ? (result.downgraded ? 'org downgraded to Free' : 'state applied') : `no change (${result.reason || 'not applied'})`}`);
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
    return res.status(500).json({ code: 'WEBHOOK_FAILED', error: 'Webhook processing failed' });
  }

  res.json({ received: true });
}

// ─── CHECKOUT FULFILMENT ──────────────────────────────────────────────────────

// A completed Checkout session reaches handleCheckoutComplete from two places that
// usually fire within the same second: the webhook, and the profile page's sync
// call right after Stripe's redirect. Run concurrently, both would see a user
// without an organization and create two, or grant one credit batch twice. A claim
// on `checkout:<session id>` in the StripeEvent store lets exactly one apply it.
const CHECKOUT_CLAIM_TTL_MS = 7 * 24 * 60 * 60 * 1000; // StripeEvent.expiresAt default
const CHECKOUT_CLAIM_STALE_MS = 5 * 60 * 1000;         // holder presumed crashed

function checkoutInProgress(sessionId) {
  return Object.assign(
    new Error(`Checkout session ${sessionId} is being applied by another request`),
    { code: 'CHECKOUT_IN_PROGRESS' }
  );
}

// Whether the session's purchase is already on the buyer's organization.
async function isCheckoutApplied(session) {
  const userId = session.metadata && session.metadata.userId;
  const user = userId ? await User.findById(userId).select('organizationId') : null;
  const org = user && user.organizationId
    ? await Organization.findById(user.organizationId).select('stripeCheckoutSessionId scanCredits')
    : null;
  if (!org) return false;
  return org.stripeCheckoutSessionId === session.id
    || (org.scanCredits || []).some(c => c.stripeCheckoutSessionId === session.id);
}

async function applyCheckoutOnce(session) {
  const claimId = `checkout:${session.id}`;

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await StripeEvent.create({ eventId: claimId });
    } catch (err) {
      if (!err || err.code !== 11000) throw err;
      if (await isCheckoutApplied(session)) return;

      // Claimed but not applied: another request is applying it right now — or
      // its process died midway, in which case the claim is taken over once it is
      // old enough. A claim's age is derived from its TTL date.
      const held = await StripeEvent.findOne({ eventId: claimId });
      if (held) {
        const claimedAt = held.expiresAt ? held.expiresAt.getTime() - CHECKOUT_CLAIM_TTL_MS : 0;
        if (Date.now() - claimedAt < CHECKOUT_CLAIM_STALE_MS) throw checkoutInProgress(session.id);
        await StripeEvent.deleteOne({ eventId: claimId, expiresAt: held.expiresAt });
      }
      continue;
    }

    try {
      await handleCheckoutComplete(session);
      return; // the claim stays: this session is done
    } catch (err) {
      await StripeEvent.deleteOne({ eventId: claimId }).catch(() => {});
      throw err;
    }
  }
  throw checkoutInProgress(session.id);
}

async function handleCheckoutComplete(session) {
  console.log(`🚀 [webhook] Starting checkout.session.completed for session ${session.id}`);
  const { userId, planType, billingCycle } = session.metadata || {};

  // Validate all required metadata up front, before touching the DB.
  if (!userId) {
    throw new Error('checkout.session.completed missing userId in metadata');
  }
  if (!planType || !billingCycle) {
    throw new Error(`checkout.session.completed missing planType or billingCycle in metadata for session ${session.id}`);
  }
  const key = `${planType}_${billingCycle}`;
  if (!isPlanKey(key)) {
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
    // Not saved here — deferred to the Promise.all below so the org is fully
    // configured before anything is written.
  }

  // A top-up is a one-time purchase by an org that still has a subscription that
  // has not ended — active, scheduled to cancel, or past_due. It must add a scan
  // credit batch WITHOUT touching planType/billingCycle/subscriptionStatus/
  // stripeSubscriptionId/seatsAllowed/scanLimit/expiresAt/scansUsed: the generic
  // path below would detach the org from a subscription Stripe keeps billing.
  // An org without one (never subscribed, downgraded to Free, or a legacy one-time
  // org) takes the one-time path below, which stacks credits instead of overwriting.
  const isTopUp = billingCycle === 'onetime' && hasLiveSubscription(org);

  if (isTopUp) {
    return await handleTopUpPurchase(org, user, session, key);
  }

  if (org.stripeCheckoutSessionId === session.id) {
    user.stripePending = false;
    await user.save();
    console.log(`♻️  [webhook] Checkout session ${session.id} already applied for Org ${org._id}.`);
    return;
  }

  // A subscription's status and real period end come from Stripe, read BEFORE any
  // write: if Stripe is unreachable this throws, nothing is saved, and the webhook
  // is retried — instead of saving the plan with a guessed end date and then
  // skipping the retry as "already applied".
  let subscription = null;
  if (billingCycle !== 'onetime') {
    const subscriptionId = subscriptionIdOf(session);
    if (!subscriptionId) {
      throw new Error(`checkout.session.completed for ${key} has no subscription (session ${session.id})`);
    }
    subscription = await stripe.subscriptions.retrieve(subscriptionId);
  }

  org.planType = planType || null;
  org.billingCycle = billingCycle || null;
  org.subscriptionStatus = subscription ? subscription.status : 'active';
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
    org.stripeSubscriptionId = subscription.id;
    org.cancelAtPeriodEnd = isCancellationScheduled(subscription);
    // The +months estimate is only a fallback for a subscription object without
    // period data; utils/entitlement.js enforces this date.
    const months = billingCycle === 'annual' ? 12 : 1;
    org.expiresAt = periodEndOf(subscription) || new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000);
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

  await Promise.all([org.save(), user.save()]);
  console.log(`✅ [webhook] User ${userId} plan set to ${key} on Org ${org._id}. DB update complete.`);

  // A subscription that had already ended by the time this ran (e.g. cancelled
  // immediately in the Stripe dashboard) must not leave a paid plan behind.
  if (subscription && !isSubscriptionEntitled(org)) {
    await applySubscription(org, subscription);
  }
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

module.exports = router;
module.exports.webhookHandler = webhookHandler;
