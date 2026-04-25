const mongoose = require('mongoose');

const StripeEventSchema = new mongoose.Schema({
  eventId: { type: String, required: true, unique: true },
  expiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    index: { expires: '1s' }
  }
});

module.exports = mongoose.model('StripeEvent', StripeEventSchema);
