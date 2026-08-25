/**
 * Credential encryption at rest.
 *
 * Scheduled authenticated scans have to keep the customer's login details so the
 * scan can sign itself in later without a person present. Those values were
 * being written to MongoDB as readable text.
 *
 * AES-256-GCM via Node's built-in crypto — no new dependency. GCM is
 * authenticated, so a modified ciphertext fails to decrypt rather than quietly
 * returning wrong bytes.
 *
 * Stored format: `v1:<iv>:<authTag>:<ciphertext>`, all base64. The version
 * prefix means a future scheme can be introduced without a migration, and it is
 * also how we recognise values written before this existed.
 */

const crypto = require('crypto');

const VERSION = 'v1';
const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;   // GCM standard
const KEY_BYTES = 32;  // AES-256

// Fixed salt: this derives one deployment-wide key from one deployment-wide
// secret. It is not a password hash, so a per-value salt would buy nothing.
const KEY_SALT = 'ssdt-credential-v1';

const ENVELOPE_PATTERN = /^v1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]*$/;

let cachedKey = null;

/**
 * Is a value already in our stored format?
 * @param {*} value
 * @returns {boolean}
 */
function isEncrypted(value) {
  return typeof value === 'string' && ENVELOPE_PATTERN.test(value);
}

/**
 * Resolve the encryption key, or throw.
 *
 * Deliberately NOT derived from JWT_SECRET: a key used to sign tokens must not
 * also be used to encrypt data, because compromising one then compromises both.
 *
 * @returns {Buffer}
 */
function getKey() {
  if (cachedKey) return cachedKey;

  const raw = process.env.CREDENTIAL_ENCRYPTION_KEY;
  if (!raw || !raw.trim()) {
    throw new Error(
      'CREDENTIAL_ENCRYPTION_KEY is not set. Scheduled authenticated scans store ' +
      'customer login details and cannot be saved without it.'
    );
  }

  const value = raw.trim();
  cachedKey = /^[0-9a-fA-F]{64}$/.test(value)
    ? Buffer.from(value, 'hex')
    : crypto.scryptSync(value, KEY_SALT, KEY_BYTES);

  return cachedKey;
}

/**
 * Is the key present? Used for a startup warning, never to decide whether to
 * write plaintext.
 * @returns {boolean}
 */
function isConfigured() {
  try {
    getKey();
    return true;
  } catch {
    return false;
  }
}

/**
 * Encrypt one credential value.
 *
 * Returns non-string input untouched so Mongoose's own null/undefined handling
 * still works, and passes through anything already encrypted so that reading a
 * document and saving it again cannot double-encrypt.
 *
 * @param {*} plaintext
 * @returns {*}
 */
function encrypt(plaintext) {
  if (typeof plaintext !== 'string' || plaintext === '') return plaintext;
  if (isEncrypted(plaintext)) return plaintext;

  const key = getKey();
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return [
    VERSION,
    iv.toString('base64'),
    authTag.toString('base64'),
    ciphertext.toString('base64')
  ].join(':');
}

/**
 * Decrypt one credential value.
 *
 * A value that is not in our format is one written before this module existed.
 * It is returned as-is so existing schedules keep working, and it is re-encrypted
 * the next time the document is saved — a migration that needs no downtime and
 * no backfill script.
 *
 * @param {*} stored
 * @returns {*}
 */
function decrypt(stored) {
  if (typeof stored !== 'string' || stored === '') return stored;
  if (!isEncrypted(stored)) return stored; // Legacy plaintext.

  const [, ivB64, tagB64, dataB64] = stored.split(':');

  try {
    const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), Buffer.from(ivB64, 'base64'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    return Buffer.concat([
      decipher.update(Buffer.from(dataB64, 'base64')),
      decipher.final()
    ]).toString('utf8');
  } catch (err) {
    // Wrong key, or the stored bytes were tampered with. Never return a guess:
    // a scan logging in with a corrupted password would look like bad
    // credentials and send someone hunting in the wrong place.
    throw new Error(`Stored credential could not be decrypted: ${err.message}`);
  }
}

/**
 * Reset the cached key. Tests only.
 */
function _resetKeyCache() {
  cachedKey = null;
}

module.exports = {
  encrypt,
  decrypt,
  isEncrypted,
  isConfigured,
  _resetKeyCache,
  VERSION
};
