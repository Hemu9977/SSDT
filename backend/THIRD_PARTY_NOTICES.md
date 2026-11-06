# Third-party notices (backend)

## IP-to-country data

`utils/ipCountry.js` (used by the in-house page capture) reads
`@ip-location-db/geo-whois-asn-country-mmdb` (CC0-1.0).
That database is built in part from Regional Internet Registry statistics:

> The statistics data provided by NRO is licensed under a Creative Commons
> Attribution 4.0 International License. Copyright holder: Number Resource
> Organization (NRO), https://www.nro.net/

## Security-header grading engine

`services/inHouse/headerGrade.js` uses `@mdn/mdn-http-observatory`, licensed
under the Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/). It is used
unmodified, as an npm dependency.

## Performance audit engine

`services/inHouse/lighthouseAudit.js` uses `lighthouse` and `chrome-launcher`,
licensed under the Apache License 2.0.
