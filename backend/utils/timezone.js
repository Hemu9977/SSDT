/**
 * Timezone-aware date helpers.
 *
 * Two production bugs motivated this module:
 *
 *  1. `Intl` throws `TypeError: Can't set option timeZoneName when dateStyle is used`
 *     if `dateStyle`/`timeStyle` is combined with ANY individual component option.
 *     Only timeZone, hour12, hourCycle, calendar, numberingSystem, localeMatcher and
 *     formatMatcher are legal alongside the style shorthands. `formatInTimeZone` below
 *     uses component options exclusively so the combination cannot recur.
 *
 *  2. `ScheduledScan.computeNextRun()` built candidates with `new Date(y, m, d, h, min)`,
 *     which resolves in the *server's* zone. The backend container has no TZ set, so it
 *     ran as UTC and a customer asking for 10:00 was scanned at 19:00 JST.
 *     `zonedTimeToUtc` is the fix: it turns a wall-clock time in a named zone into the
 *     correct instant.
 *
 * Zero dependencies - the project has no date-fns/luxon/dayjs and does not need one for this.
 */

'use strict';

const DEFAULT_TIME_ZONE = 'Asia/Kolkata';

/**
 * Is `tz` an IANA zone this runtime recognises?
 * Intl throws RangeError on anything it does not know, which is the whole test.
 */
function isValidTimeZone(tz) {
  if (typeof tz !== 'string' || tz.trim() === '') return false;
  try {
    new Intl.DateTimeFormat(undefined, { timeZone: tz });
    return true;
  } catch (err) {
    return false;
  }
}

/**
 * The offset of `timeZone` at the instant `utcMs`, in milliseconds
 * (positive east of UTC, so wallTime = utcMs + offset).
 */
function timeZoneOffsetMs(utcMs, timeZone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  }).formatToParts(new Date(utcMs));

  const field = {};
  for (const part of parts) field[part.type] = part.value;

  // hour12:false renders midnight as '24' on some Node/ICU versions.
  const asIfUtc = Date.UTC(
    Number(field.year),
    Number(field.month) - 1,
    Number(field.day),
    Number(field.hour) % 24,
    Number(field.minute),
    Number(field.second)
  );

  return asIfUtc - utcMs;
}

/**
 * The instant at which the wall clock in `timeZone` reads the given date and time.
 *
 * `month` is 0-indexed, matching the Date constructor.
 *
 * Derives the zone's offset from a first guess, subtracts it, then re-derives once:
 * across a DST transition the offset at the guessed instant differs from the offset at
 * the corrected one, and the second pass lands on the right side of the jump.
 */
function zonedTimeToUtc(year, month, day, hour, minute, timeZone) {
  const zone = isValidTimeZone(timeZone) ? timeZone : DEFAULT_TIME_ZONE;
  const guess = Date.UTC(year, month, day, hour, minute, 0);

  const firstOffset = timeZoneOffsetMs(guess, zone);
  let instant = guess - firstOffset;

  const secondOffset = timeZoneOffsetMs(instant, zone);
  if (secondOffset !== firstOffset) instant = guess - secondOffset;

  return new Date(instant);
}

/**
 * The calendar date the wall clock in `timeZone` currently shows.
 * Returns { year, month (0-indexed), day }.
 */
function zonedDateParts(date, timeZone) {
  const zone = isValidTimeZone(timeZone) ? timeZone : DEFAULT_TIME_ZONE;
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: zone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(date);

  const field = {};
  for (const part of parts) field[part.type] = part.value;

  return {
    year: Number(field.year),
    month: Number(field.month) - 1,
    day: Number(field.day)
  };
}

/**
 * Human-readable date/time in a named zone, e.g. "Aug 31, 2026, 12:27 PM GMT+5:30".
 *
 * Component options only - never dateStyle/timeStyle, see the header. Falls back to a
 * plain UTC string rather than throwing: this is display text, and a bad zone must not
 * be able to fail an operation that has already succeeded.
 */
function formatInTimeZone(date, timeZone, { locale = 'en-US', withZoneName = true } = {}) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return null;

  try {
    return date.toLocaleString(locale, {
      timeZone: isValidTimeZone(timeZone) ? timeZone : DEFAULT_TIME_ZONE,
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      ...(withZoneName ? { timeZoneName: 'short' } : {})
    });
  } catch (err) {
    return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  }
}

module.exports = {
  DEFAULT_TIME_ZONE,
  isValidTimeZone,
  timeZoneOffsetMs,
  zonedTimeToUtc,
  zonedDateParts,
  formatInTimeZone
};
