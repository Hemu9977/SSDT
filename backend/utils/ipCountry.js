/**
 * IP address -> ISO 3166-1 alpha-2 country code, from a local MMDB file.
 *
 * Feeds the page-analysis "Country" / "Unique countries" fields, which the
 * external page-analysis service used to supply. A local lookup sends nothing
 * anywhere and cannot be affected by the target's IP allowlist.
 *
 * Default data: @ip-location-db/geo-whois-asn-country-mmdb (geofeeds + RIR whois
 * + ASN; registry data CC BY 4.0, NRO — see backend/THIRD_PARTY_NOTICES.md).
 * IP_COUNTRY_DB_PATH may point at any other country MMDB instead; both that
 * package's `{ country_code }` records and MaxMind-style `{ country: { iso_code } }`
 * records are read.
 */

const fs = require('fs');
const net = require('net');
const { Reader } = require('mmdb-lib');

let reader;      // undefined = not loaded yet, null = unavailable
function getReader() {
  if (reader !== undefined) return reader;
  try {
    const file = process.env.IP_COUNTRY_DB_PATH
      || require.resolve('@ip-location-db/geo-whois-asn-country-mmdb/geo-whois-asn-country.mmdb');
    reader = new Reader(fs.readFileSync(file));
  } catch (err) {
    console.warn(`[ipCountry] Country database unavailable: ${err.message}`);
    reader = null;
  }
  return reader;
}

/** @returns {string|null} upper-case country code, or null when unknown. */
function countryOf(ip) {
  if (!ip || !net.isIP(ip)) return null;
  const db = getReader();
  if (!db) return null;
  try {
    const rec = db.get(ip);
    const code = rec?.country_code || rec?.country?.iso_code || null;
    return code ? String(code).toUpperCase() : null;
  } catch {
    return null;
  }
}

module.exports = { countryOf };
