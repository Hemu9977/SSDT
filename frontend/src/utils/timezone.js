/**
 * The IANA zone the visitor's browser is in, e.g. "Asia/Tokyo".
 *
 * Scheduled scans previously sent a hardcoded 'Asia/Kolkata' for every customer, so a
 * Japanese user asking for 10:00 was scheduled against the wrong wall clock. The backend
 * now runs the schedule in whatever zone it is given, which only helps if we send the
 * real one.
 *
 * Falls back to Asia/Kolkata to match the backend default if the browser will not say.
 */
export const FALLBACK_TIME_ZONE = 'Asia/Kolkata';

export function browserTimeZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || FALLBACK_TIME_ZONE;
  } catch (err) {
    return FALLBACK_TIME_ZONE;
  }
}
