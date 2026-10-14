/**
 * backend/config/stripe.js
 *
 * The one Stripe client. Every module that talks to Stripe requires this file
 * rather than constructing its own, so tests have a single stub point and the
 * API version is decided in exactly one place.
 *
 * The API version is pinned explicitly. Stripe moves fields between versions —
 * `2025-03-31.basil` moved a subscription's billing period from
 * `subscription.current_period_end` to `subscription.items.data[].current_period_end`,
 * and an invoice's subscription from `invoice.subscription` to
 * `invoice.parent.subscription_details.subscription`. Leaving the version to the
 * SDK default would let a routine `npm update` change those shapes silently.
 * services/subscriptionLifecycle.js reads both shapes regardless, because webhook
 * payloads follow the endpoint's version in the Stripe dashboard, not this one.
 */

const Stripe = require('stripe');

const STRIPE_API_VERSION = '2026-05-27.dahlia';

const stripe = Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: STRIPE_API_VERSION });

module.exports = stripe;
module.exports.STRIPE_API_VERSION = STRIPE_API_VERSION;
