// Shared building blocks for the audit plugin pages. Uses only ctx.ui / ctx.api from the shell.

export const RANGES = [['1h', 'Last hour'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['90d', 'Last 90 days'], ['180d', 'Last 180 days'], ['365d', 'Last 365 days'], ['730d', 'Last 730 days']];

export function rangeToDates(range) {
  const to = new Date();
  const m = /^(\d+)([hd])$/.exec(range || '24h');
  const n = m ? Number(m[1]) : 24;
  const unit = m ? m[2] : 'h';
  const from = new Date(to.getTime() - n * (unit === 'h' ? 3600e3 : 86400e3));
  return { from: from.toISOString(), to: to.toISOString(), hours: unit === 'h' ? n : n * 24 };
}

function localDateInput(date) {
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}-${month}-${day}`;
}

function customDayBounds(start, end) {
  const fromParts = /^(\d{4})-(\d{2})-(\d{2})$/.exec(start || '');
  const toParts = /^(\d{4})-(\d{2})-(\d{2})$/.exec(end || '');
  if (!fromParts || !toParts) return { error: 'Choose a start date and an end date.' };
  const from = new Date(Number(fromParts[1]), Number(fromParts[2]) - 1, Number(fromParts[3]), 0, 0, 0, 0);
  const to = new Date(Number(toParts[1]), Number(toParts[2]) - 1, Number(toParts[3]), 23, 59, 59, 999);
  if (from.getFullYear() !== Number(fromParts[1]) || from.getMonth() !== Number(fromParts[2]) - 1 || to.getFullYear() !== Number(toParts[1]) || to.getMonth() !== Number(toParts[2]) - 1) {
    return { error: 'Choose a real start date and end date.' };
  }
  if (to < from) return { error: 'The end date is before the start date.' };
  // Calendar dates, so a daylight-saving hour does not push a 730-day span over the cap.
  const span = Math.round((Date.UTC(to.getFullYear(), to.getMonth(), to.getDate()) - Date.UTC(from.getFullYear(), from.getMonth(), from.getDate())) / 86400000);
  if (span > 729) return { error: 'A custom range can cover at most 730 days.' };
  return { from: from.toISOString(), to: to.toISOString() };
}

export { customDayBounds };

const MONTHS = {
  january: 1, jan: 1, february: 2, feb: 2, march: 3, mar: 3, april: 4, apr: 4, may: 5,
  june: 6, jun: 6, july: 7, jul: 7, august: 8, aug: 8, september: 9, sept: 9, sep: 9, 
  october: 10, oct: 10, november: 11, nov: 11, december: 12, dec: 12,
};

// Date.UTC treats years 0–99 as 1900–1999. Compare against that so year 0001 still counts.
function calendarDay(year, month, day) {
  if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1) return false;
  const probe = new Date(Date.UTC(year, month - 1, day));
  const mappedYear = year >= 0 && year <= 99 ? year + 1900 : year;
  return probe.getUTCFullYear() === mappedYear && probe.getUTCMonth() === month - 1 && probe.getUTCDate() === day;
}

// The same 400-year cycle keeps the weekday. Date.UTC would otherwise turn year 1 into 1901.
function weekdayOf(year, month, day) {
  const probeYear = year >= 0 && year <= 99 ? year + 400 : year;
  return new Date(Date.UTC(probeYear, month - 1, day)).getUTCDay();
}

function zoneParts(zone) {
  if (!zone || /^(z|gmt)$/i.test(zone)) return { ok: true, minutes: 0 };
  const sign = zone[0] === '-' ? -1 : 1;
  const body = zone.slice(1);
  let hour;
  let minute;
  const colon = body.indexOf(':');
  if (/^\d{1,2}$/.test(body)) {
    hour = Number(body);
    minute = 0;
  } else if (colon >= 0) {
    // +05:3 is five hours and three minutes. Padding the compact form would make it 53 minutes.
    const hourText = body.slice(0, colon);
    const minuteText = body.slice(colon + 1);
    if (!/^\d{1,2}$/.test(hourText) || !/^\d{1,2}$/.test(minuteText)) return { ok: false, minutes: 0 };
    hour = Number(hourText);
    minute = Number(minuteText);
  } else {
    const digits = body.length === 3 ? `0${body}` : body;
    if (!/^\d{4}$/.test(digits)) return { ok: false, minutes: 0 };
    hour = Number(digits.slice(0, 2));
    minute = Number(digits.slice(2, 4));
  }
  // DateTimeOffset accepts an offset of at most 14 hours, and only :00 at that edge.
  if (hour > 14 || minute > 59 || (hour === 14 && minute !== 0)) return { ok: false, minutes: 0 };
  return { ok: true, minutes: sign * (hour * 60 + minute) };
}

function zoneFits(zone) {
  return zoneParts(zone).ok;
}

function offsetMinutes(zone) {
  return zoneParts(zone).minutes;
}

// Date.UTC maps years 0–99 onto 1900–1999, so the edges are checked from the clock instead.
function instantFits(year, month, day, rest) {
  if (!rest || (year > 1 && year < 9999)) return true;
  const clock = /^(\d{1,2}):(\d{1,2})(?::(\d{1,2})(?:\.(\d+))?)?/.exec(String(rest).trim());
  if (!clock) return true;
  let hour = Number(clock[1]);
  const minute = Number(clock[2]);
  const second = clock[3] === undefined ? 0 : Number(clock[3]);
  const fraction = clock[4] || '';
  const ampm = /\s*([ap]m)/i.exec(rest);
  if (ampm) {
    const mark = ampm[1].toLowerCase();
    if (mark === 'pm' && hour < 12) hour += 12;
    if (mark === 'am' && hour === 12) hour = 0;
  }
  // The host rejects a fraction that overflows the wall clock before it applies the offset.
  if (year === 9999 && month === 12 && day === 31 && hour === 23 && minute === 59 && second === 59 && fractionRoundsPastMax(fraction)) return false;
  const zone = /(GMT|[zZ]|[+-]\d{1,2}(?::\d{1,2}|\d{2})?)\s*$/.exec(String(rest).trim());
  const utcMinutes = hour * 60 + minute - (zone ? offsetMinutes(zone[1]) : 0);
  if (year === 1 && month === 1 && day === 1 && utcMinutes < 0) return false;
  if (year === 9999 && month === 12 && day === 31) {
    if (utcMinutes > 23 * 60 + 59) return false;
    // The host keeps 7 digits and rounds. An 8th digit of 5 or more at the maximum tick overflows.
    if (utcMinutes === 23 * 60 + 59 && second === 59 && fractionRoundsPastMax(fraction)) return false;
  }
  return true;
}

function zoneOnly(rest) {
  const text = String(rest || '').trim();
  return /^(?:z|gmt|[+-]\d)/i.test(text) && zoneFits(text);
}

function clockFits(rest) {
  // 23:59:59,999 is the same fraction as 23:59:59.999. 3.45 PM is 3:45 PM.
  const text = String(rest).trim().replace(/(\d),(\d+)/g, '$1.$2').replace(/^(\d{1,2})\.(\d{1,2})(?=\s*[ap]m\b)/i, '$1:$2');
  const match = /^(\d{1,2})(?::(\d{1,2})(?::(\d{1,2})(?:\.\d+)?)?)?(?:\s*([ap]m))?(?:\s*([zZ]|GMT|[+-]\d{1,2}(?::\d{1,2}|\d{2})?))?$/i.exec(text);
  if (!match || (match[2] === undefined && !match[4])) return false;
  let hour = Number(match[1]);
  const minute = match[2] === undefined ? 0 : Number(match[2]);
  const second = match[3] === undefined ? 0 : Number(match[3]);
  const ampm = match[4] ? match[4].toLowerCase() : '';
  if (ampm) {
    // 00 PM stays rejected. 13 PM is 13:00, the same value the host accepts.
    if (hour === 0 && ampm === 'pm') return false;
    if (!(hour === 0 && ampm === 'am') && (hour < 1 || hour > 23)) return false;
    if (ampm === 'pm' && hour < 12) hour += 12;
    if (ampm === 'am' && hour === 12) hour = 0;
    if (ampm === 'am' && hour > 12) return false;
  }
  if (hour > 23 || minute > 59 || second > 59) return false;
  return !match[5] || zoneFits(match[5]);
}

function rollsForward(rest) {
  if (!rest) return false;
  // The weekday forms pass the whole date, so the clock is not always at the start.
  const clock = /(\d{1,2}):(\d{1,2})(?::(\d{1,2})(?:\.(\d+))?)?/.exec(String(rest));
  if (!clock) return false;
  let hour = Number(clock[1]);
  const minute = Number(clock[2]);
  const second = clock[3] === undefined ? 0 : Number(clock[3]);
  const fraction = clock[4] || '';
  const ampm = /\s*([ap]m)/i.exec(rest);
  if (ampm) {
    const mark = ampm[1].toLowerCase();
    if (mark === 'pm' && hour < 12) hour += 12;
    if (mark === 'am' && hour === 12) hour = 0;
  }
  return hour === 23 && minute === 59 && second === 59 && fractionRoundsPastMax(fraction);
}

function nextDate(year, month, day) {
  const stamp = Date.UTC(year < 100 ? year + 400 : year, month - 1, day) + 86400000;
  const date = new Date(stamp);
  let rolledYear = date.getUTCFullYear();
  if (year < 100) rolledYear -= 400;
  return { year: rolledYear, month: date.getUTCMonth() + 1, day: date.getUTCDate() };
}

function datedWeekday(year, month, day, rest) {
  if (!rollsForward(rest)) return weekdayOf(year, month, day);
  const next = nextDate(year, month, day);
  return weekdayOf(next.year, next.month, next.day);
}

function fractionRoundsPastMax(fraction) {
  if (fraction.length <= 7) return false;
  const head = Number(fraction.slice(0, 7));
  const roundUp = fraction[7] >= '5';
  return roundUp && head === 9999999;
}

// .NET maps a two-digit year through 2049. 00 is 2000 and 50 is 1950.
function monthIndex(token) {
  return MONTHS[String(token || '').toLowerCase().replace(/\./g, '')] || 0;
}

function expandYear(text) {
  const year = Number(text);
  const length = String(text).length;
  // 0 and 6 are 2000 and 2006. A four-digit year, including 0001, stays as written.
  if (length === 1) return 2000 + year;
  if (length !== 2) return year;
  return year <= 49 ? 2000 + year : 1900 + year;
}

// The filter check and the weekday check both read a dashed date through these.
// An impossible day is the year, which is how 31-Nov-13 is 13 November 2031.
function dashedNamedParts(firstText, monthToken, lastText) {
  const month = monthIndex(monthToken);
  if (!month) return null;
  const first = Number(firstText);
  const last = Number(lastText);
  // 2013-Nov-13 is year-month-day. 29-Feb-0001 is not swapped into 2029.
  if (String(firstText).length >= 3 || first > 31) {
    if (String(lastText).length > 2 || !calendarDay(expandYear(firstText), month, last)) return null;
    return { year: expandYear(firstText), month, day: last };
  }
  const dayFirstYear = expandYear(lastText);
  if (calendarDay(dayFirstYear, month, first)) return { year: dayFirstYear, month, day: first };
  if (String(lastText).length >= 3 || String(lastText).length > 2) return null;
  if (!calendarDay(expandYear(firstText), month, last)) return null;
  return { year: expandYear(firstText), month, day: last };
}

function spacedParts(dayText, monthToken, yearText) {
  const month = monthIndex(monthToken);
  if (!month) return null;
  const day = Number(dayText);
  const year = expandYear(yearText);
  if (String(dayText).length <= 2 && calendarDay(year, month, day)) return { year, month, day };
  // 31 Nov 13 is 13 November 2031. Nov 0, 13 is 13 November 2000. A long year is not a day.
  if (String(yearText).length >= 3 || String(dayText).length > 2) return null;
  const swappedYear = expandYear(dayText);
  const swappedDay = Number(yearText);
  if (!calendarDay(swappedYear, month, swappedDay)) return null;
  return { year: swappedYear, month, day: swappedDay };
}

function monthDashParts(monthToken, dayText, yearText) {
  const month = monthIndex(monthToken);
  if (!month) return null;
  const day = Number(dayText);
  const year = expandYear(yearText);
  if (String(dayText).length <= 2 && calendarDay(year, month, day)) return { year, month, day };
  // Nov-2026-13 is 13 November 2026. The middle token is the year.
  if (String(dayText).length >= 3 && String(yearText).length <= 2 && calendarDay(expandYear(dayText), month, Number(yearText))) {
    return { year: expandYear(dayText), month, day: Number(yearText) };
  }
  // An explicit year of three or four digits is not a day. Nov-0-13 still swaps 0 into 2000.
  if (String(yearText).length >= 3 || String(dayText).length > 2 || String(yearText).length > 2) return null;
  const swappedYear = expandYear(dayText);
  const swappedDay = Number(yearText);
  if (!calendarDay(swappedYear, month, swappedDay)) return null;
  return { year: swappedYear, month, day: swappedDay };
}

function numericDashParts(monthText, dayText, yearText) {
  const year = expandYear(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  if (!calendarDay(year, month, day)) return null;
  return { year, month, day };
}

function calendarOf(value) {
  const named = /^([A-Za-z]+\.?),?\s*(\d{1,4})(?!\d),?\s*(\d{1,4})(?!\d)/.exec(value);
  if (named && monthIndex(named[1])) {
    const parts = spacedParts(named[2], named[1], named[3]);
    if (parts) return parts;
  }
  const behind = /^(\d{1,2})\s+([A-Za-z]+\.?)(?:,\s*|\s+)(\d{1,4})/.exec(value);
  if (behind && monthIndex(behind[2])) {
    const parts = spacedParts(behind[1], behind[2], behind[3]);
    if (parts) return parts;
  }
  const slash = /^(\d{1,2})\/(\d{1,2})\/(\d{2,4})/.exec(value);
  if (slash) return { year: expandYear(slash[3]), month: Number(slash[1]), day: Number(slash[2]) };
  const yearSlash = /^(\d{4})\/(\d{1,2})\/(\d{1,2})/.exec(value);
  if (yearSlash) return { year: Number(yearSlash[1]), month: Number(yearSlash[2]), day: Number(yearSlash[3]) };
  const yearNamed = /^(\d{4})\s+([A-Za-z]+\.?)\s+(\d{1,2})/.exec(value);
  if (yearNamed && monthIndex(yearNamed[2]) && calendarDay(Number(yearNamed[1]), monthIndex(yearNamed[2]), Number(yearNamed[3]))) return { year: Number(yearNamed[1]), month: monthIndex(yearNamed[2]), day: Number(yearNamed[3]) };
  const dashedName = /^(\d{1,4})-([A-Za-z]+)-(\d{1,4})/.exec(value);
  if (dashedName) {
    const named = dashedNamedParts(dashedName[1], dashedName[2], dashedName[3]);
    if (named) return named;
  }
  const numericDash = /^(\d{1,2})-(\d{1,2})-(\d{2,4})/.exec(value);
  if (numericDash) {
    const dashed = numericDashParts(numericDash[1], numericDash[2], numericDash[3]);
    if (dashed) return dashed;
  }
  const dots = /^(\d{4})\.(\d{1,2})\.(\d{1,2})/.exec(value);
  if (dots) return { year: Number(dots[1]), month: Number(dots[2]), day: Number(dots[3]) };
  const monthFirst = /^([A-Za-z]+)-(\d{1,2})-(\d{2,4})/.exec(value);
  if (monthFirst) {
    const named = monthDashParts(monthFirst[1], monthFirst[2], monthFirst[3]);
    if (named) return named;
  }
  return null;
}

function clockOrZone(rest, year, month, day) {
  if (!rest) return true;
  if (zoneOnly(rest)) return true;
  return clockFits(rest) && instantFits(year, month, day, rest);
}

function namedDay(value) {
  const ahead = /^([A-Za-z]+\.?),?\s*(\d{1,4})(?!\d),?\s*(\d{1,4})(?!\d)(?:\s+(.*))?$/.exec(value);
  if (ahead && monthIndex(ahead[1])) {
    const parts = spacedParts(ahead[2], ahead[1], ahead[3]);
    return !!parts && clockOrZone(ahead[4], parts.year, parts.month, parts.day);
  }
  const behind = /^(\d{1,2})\s+([A-Za-z]+\.?)(?:,\s*|\s+)(\d{1,4})(?:\s+(.*))?$/.exec(value);
  if (behind && monthIndex(behind[2])) {
    const parts = spacedParts(behind[1], behind[2], behind[3]);
    return !!parts && clockOrZone(behind[4], parts.year, parts.month, parts.day);
  }
  return null;
}

function rfc1123(value) {
  const match = /^(?:(Sun(?:day)?|Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?)(?:,\s*|\s+))?(\d{1,2})\s+([A-Za-z]{3,})\s+(\d{2,4})(?:\s+(.*))?$/i.exec(value);
  if (!match || !monthIndex(match[3])) return null;
  const year = expandYear(match[4]);
  const month = monthIndex(match[3]);
  const day = Number(match[2]);
  if (!calendarDay(year, month, day) || (match[5] && !(clockFits(match[5]) && instantFits(year, month, day, match[5])))) return false;
  if (!match[1]) return true;
  const names = { sun: 0, sunday: 0, mon: 1, monday: 1, tue: 2, tuesday: 2, wed: 3, wednesday: 3, thu: 4, thursday: 4, fri: 5, friday: 5, sat: 6, saturday: 6 };
  return names[match[1].toLowerCase()] === datedWeekday(year, month, day, match[5]);
}

function tClock(rest) {
  return /^\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:\s*(?:[zZ]|GMT|[+-]\d{1,2}(?::\d{1,2}|\d{2})?))?$/i.test(String(rest).trim());
}

function timedDay(year, month, day, separator, rest) {
  if (!calendarDay(year, month, day)) return false;
  if (rest === undefined) return true;
  if (zoneOnly(rest)) return separator !== 'T' && separator !== 't';
  if (/^(z|gmt)$/i.test(rest.trim())) return separator !== 'T' && separator !== 't';
  // A T before GMT, with or without a space, is not a value the host accepts.
  if ((separator === 'T' || separator === 't') && (/gmt$/i.test(rest.trim()) || !tClock(rest))) return false;
  return clockFits(rest) && instantFits(year, month, day, rest);
}

function dateFits(value) {
  value = String(value || '').trim();
  if (!value || /^\d{4}$/.test(value)) return false;
  const yearMonth = /^(\d{4})-(\d{1,2})$/.exec(value);
  if (yearMonth) return Number(yearMonth[2]) >= 1 && Number(yearMonth[2]) <= 12;
  if (/^\d{1,2}:\d{2}/.test(value) && clockFits(value)) return true;
  const leadClock = /^(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[ap]m)?)\s+(\D.*)$/i.exec(value);
  if (leadClock && clockFits(leadClock[1]) && dateFits(leadClock[2])) return true;
  const iso = /^(\d{4})-(\d{1,2})-(\d{1,2})(?:$|([Tt\s])(.*))$/.exec(value);
  if (iso) {
    const year = Number(iso[1]);
    const month = Number(iso[2]);
    const day = Number(iso[3]);
    let separator = iso[4];
    let rest = iso[5];
    // "2026-11-13 T00:00:00Z" is the same instant as the form without the space.
    if (separator === ' ' && rest && /^[Tt]/.test(rest)) {
      separator = 'T';
      rest = rest.slice(1).trim();
    }
    return timedDay(year, month, day, separator, rest);
  }
  const slash = /^(\d{1,2})\/(\d{1,2})\/(\d{2,4})(?:\s+(.*))?$/.exec(value);
  if (slash) return calendarDay(expandYear(slash[3]), Number(slash[1]), Number(slash[2])) && clockOrZone(slash[4], expandYear(slash[3]), Number(slash[1]), Number(slash[2]));
  const slashNamed = /^(\d{1,4})[/.]([A-Za-z]+)[/.](\d{1,4})(?:\s+(.*))?$/.exec(value);
  if (slashNamed) {
    const named = dashedNamedParts(slashNamed[1], slashNamed[2], slashNamed[3]);
    if (named) return clockOrZone(slashNamed[4], named.year, named.month, named.day);
  }
  const yearSlash = /^(\d{4})\/(\d{1,2})\/(\d{1,2})(?:$|([Tt\s])(.*))$/.exec(value);
  if (yearSlash) return timedDay(Number(yearSlash[1]), Number(yearSlash[2]), Number(yearSlash[3]), yearSlash[4], yearSlash[5]);
  const monthFirst = /^([A-Za-z]+)-(\d{1,4})-(\d{1,4})(?:\s+(.*))?$/.exec(value);
  if (monthFirst) {
    const named = monthDashParts(monthFirst[1], monthFirst[2], monthFirst[3]);
    if (named) return !monthFirst[4] || (clockFits(monthFirst[4]) && instantFits(named.year, named.month, named.day, monthFirst[4]));
  }
  const dashedName = /^(\d{1,4})-([A-Za-z]+)-(\d{1,4})(?:\s+(.*))?$/.exec(value);
  if (dashedName) {
    const named = dashedNamedParts(dashedName[1], dashedName[2], dashedName[3]);
    if (named) return !dashedName[4] || (clockFits(dashedName[4]) && instantFits(named.year, named.month, named.day, dashedName[4]));
  }
  const dashed = /^(\d{1,2})-(\d{1,2})-(\d{2,4})(?:\s+(.*))?$/.exec(value);
  if (dashed) {
    const named = numericDashParts(dashed[1], dashed[2], dashed[3]);
    if (named) return !dashed[4] || (clockFits(dashed[4]) && instantFits(named.year, named.month, named.day, dashed[4]));
  }
  const dots = /^(\d{4})\.(\d{1,2})\.(\d{1,2})(?:$|([Tt\s])(.*))$/.exec(value);
  if (dots) return timedDay(Number(dots[1]), Number(dots[2]), Number(dots[3]), dots[4], dots[5]);
  const isoZone = /^(\d{4})-(\d{1,2})-(\d{1,2})\s*(Z|GMT)$/i.exec(value);
  if (isoZone) return calendarDay(Number(isoZone[1]), Number(isoZone[2]), Number(isoZone[3]));
  const monthYear = /^([A-Za-z]+\.?)(?:,\s*|\s+)(\d{4})$/.exec(value);
  if (monthYear && monthIndex(monthYear[1])) return true;
  const yearMonthName = /^(\d{4})\s+([A-Za-z]+)$/.exec(value);
  if (yearMonthName && monthIndex(yearMonthName[2])) return true;
  const yearFirst = /^(\d{4})\s+([A-Za-z]+\.?)\s+(\d{1,2})(?:\s+(.*))?$/.exec(value);
  if (yearFirst && monthIndex(yearFirst[2]) && calendarDay(Number(yearFirst[1]), monthIndex(yearFirst[2]), Number(yearFirst[3]))) return !yearFirst[4] || (clockFits(yearFirst[4]) && instantFits(Number(yearFirst[1]), monthIndex(yearFirst[2]), Number(yearFirst[3]), yearFirst[4]));
  const named = namedDay(value);
  if (named !== null) return named;
  const rfc = rfc1123(value);
  if (rfc !== null) return rfc;
  const lead = /^(Sun(?:day)?|Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?)(?:,\s*|\s+)(.+)$/i.exec(value);
  if (lead) {
    if (!dateFits(lead[2])) return false;
    const rest = lead[2].trim();
    const names = { sun: 0, sunday: 0, mon: 1, monday: 1, tue: 2, tuesday: 2, wed: 3, wednesday: 3, thu: 4, thursday: 4, fri: 5, friday: 5, sat: 6, saturday: 6 };
    const wanted = names[lead[1].toLowerCase()];
    const isoDate = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(rest);
    if (isoDate) return datedWeekday(Number(isoDate[1]), Number(isoDate[2]), Number(isoDate[3]), '') === wanted;
    const isoWhen = /^(\d{4})-(\d{1,2})-(\d{1,2})[Tt\s](.*)$/.exec(rest);
    if (isoWhen) return datedWeekday(Number(isoWhen[1]), Number(isoWhen[2]), Number(isoWhen[3]), isoWhen[4]) === wanted;
    const yearMonth = /^(\d{4})-(\d{1,2})$/.exec(rest);
    if (yearMonth && Number(yearMonth[2]) >= 1 && Number(yearMonth[2]) <= 12) return weekdayOf(Number(yearMonth[1]), Number(yearMonth[2]), 1) === wanted;
    const found = calendarOf(rest);
    if (found && calendarDay(found.year, found.month, found.day)) return datedWeekday(found.year, found.month, found.day, rest) === wanted;
    const isoZoneDay = /^(\d{4})-(\d{1,2})-(\d{1,2})(Z|GMT)$/i.exec(rest);
    if (isoZoneDay) return datedWeekday(Number(isoZoneDay[1]), Number(isoZoneDay[2]), Number(isoZoneDay[3]), '') === wanted;
    const stamp = Date.parse(rest);
    if (Number.isNaN(stamp)) return false;
    return new Date(stamp).getDay() === wanted;
  }
  return false;
}

// Leading zeros are rejected, matching the host IP parser. 010.0.0.1 is not an address.
function ipv4Octet(part) {
  return /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255;
}

function ipv4Fits(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => ipv4Octet(part));
}

function cidrFits(value) {
  const slash = value.indexOf('/');
  if (slash <= 0 || value.indexOf('/', slash + 1) >= 0) return false;
  const host = value.slice(0, slash);
  const prefixText = value.slice(slash + 1);
  if (!/^(0|[1-9]\d*)$/.test(prefixText)) return false;
  const prefix = Number(prefixText);
  if (host.includes(':')) {
    if (!ipv6Fits(host) || prefix > 128) return false;
    // The host stores an IPv4-mapped address as IPv4 and rejects a prefix that is still above 32.
    if (isIpv4Mapped(host)) return (prefix >= 96 ? prefix - 96 : prefix) <= 32;
    return true;
  }
  return ipv4Fits(host) && prefix <= 32;
}

function isIpv4Mapped(value) {
  const halves = value.split('::');
  if (halves.length > 2) return false;
  const expand = (text) => {
    if (!text) return [];
    const out = [];
    for (const group of text.split(':')) {
      if (group.includes('.')) {
        const parts = group.split('.');
        if (parts.length !== 4 || !parts.every((part) => ipv4Octet(part))) return null;
        const numbers = parts.map(Number);
        out.push((numbers[0] << 8) | numbers[1], (numbers[2] << 8) | numbers[3]);
      } else if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      else out.push(parseInt(group, 16));
    }
    return out;
  };
  const left = expand(halves[0]);
  const right = halves.length === 2 ? expand(halves[1]) : [];
  if (!left || !right) return false;
  let hextets = left;
  if (halves.length === 2) {
    const missing = 8 - left.length - right.length;
    if (missing < 1) return false;
    hextets = left.concat(Array(missing).fill(0), right);
  }
  return hextets.length === 8 && hextets[0] === 0 && hextets[1] === 0 && hextets[2] === 0 && hextets[3] === 0 && hextets[4] === 0 && hextets[5] === 0xffff;
}

function ipv6Fits(value) {
  let text = String(value).trim();
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  const zoneAt = text.indexOf('%');
  if (zoneAt >= 0) {
    const id = text.slice(zoneAt + 1);
    if (!id || !/^[A-Za-z0-9._:-]+$/.test(id)) return false;
    text = text.slice(0, zoneAt);
  }
  value = text;
  if (!value.includes(':') || value.includes('%')) return false;
  const halves = value.split('::');
  if (halves.length > 2) return false;
  let count = 0;
  for (let side = 0; side < halves.length; side++) {
    if (halves[side] === '') continue;
    const groups = halves[side].split(':');
    for (let i = 0; i < groups.length; i++) {
      const group = groups[i];
      const end = side === halves.length - 1 && i === groups.length - 1;
      if (end && group.includes('.')) {
        if (!ipv4Fits(group)) return false;
        count += 2;
      } else if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
        return false;
      } else {
        count += 1;
      }
    }
  }
  return halves.length === 2 ? count < 8 : count === 8;
}

function wholeFits(value) {
  const text = String(value).trim();
  if (!/^[+-]?\d+$/.test(text)) return false;
  const number = Number(text);
  return Number.isSafeInteger(number);
}

export function valueFits(type, value) {
  if (type === 'date') return dateFits(value);
  if (type === 'wholenumber') return wholeFits(value);
  if (type === 'number') return value !== '' && !Number.isNaN(Number(value));
  if (type === 'boolean') return /^true$/i.test(value) || /^false$/i.test(value);
  if (type === 'ip') return ipv4Fits(value) || ipv6Fits(value) || cidrFits(value);
  return true;
}

export function get(doc, path) {
  return path.split('.').reduce((o, k) => (o === null || o === undefined ? undefined : o[k]), doc);
}

const COUNTRY_NAMES = {
  australia: 'AU', austria: 'AT', belgium: 'BE', brazil: 'BR', canada: 'CA', china: 'CN', denmark: 'DK',
  egypt: 'EG', finland: 'FI', france: 'FR', germany: 'DE', greece: 'GR', 'hong kong': 'HK', india: 'IN',
  indonesia: 'ID', ireland: 'IE', israel: 'IL', italy: 'IT', japan: 'JP', malaysia: 'MY', mexico: 'MX',
  netherlands: 'NL', 'the netherlands': 'NL', 'new zealand': 'NZ', norway: 'NO', pakistan: 'PK',
  philippines: 'PH', poland: 'PL', portugal: 'PT', qatar: 'QA', russia: 'RU', 'russian federation': 'RU',
  'saudi arabia': 'SA', singapore: 'SG', 'south africa': 'ZA', 'south korea': 'KR', korea: 'KR',
  spain: 'ES', sweden: 'SE', switzerland: 'CH', taiwan: 'TW', thailand: 'TH', turkey: 'TR',
  türkiye: 'TR', ukraine: 'UA', 'united arab emirates': 'AE', uae: 'AE', 'united kingdom': 'GB',
  uk: 'GB', 'great britain': 'GB', england: 'GB', 'united states': 'US', 'united states of america': 'US',
  usa: 'US', vietnam: 'VN', 'viet nam': 'VN',
};

export function countryCode(value) {
  const text = String(value || '').trim();
  if (/^[A-Za-z]{2}$/.test(text)) return text.toUpperCase() === 'UK' ? 'GB' : text.toUpperCase();
  return COUNTRY_NAMES[text.toLowerCase()] || '';
}

function flagEmoji(code) {
  return String.fromCodePoint(0x1F1E6 + code.charCodeAt(0) - 65, 0x1F1E6 + code.charCodeAt(1) - 65);
}

export function locationCell(h, doc) {
  const city = get(doc, 'source.geo.city_name');
  const country = get(doc, 'source.geo.country_name');
  const text = [city, country].filter(Boolean).join(', ');
  const code = countryCode(get(doc, 'source.geo.country_iso_code')) || countryCode(country);
  if (!code || !text) return text;
  return h('span', { class: 'loc' }, h('span', { class: 'flag', 'aria-hidden': 'true' }, flagEmoji(code)), text);
}

export function severityBadge(ui, sev) {
  const kind = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', informational: '' }[sev] || '';
  return ui.badge(sev || 'informational', kind);
}

export function outcomeBadge(ui, outcome) {
  if (!outcome) return ui.badge('-');
  return ui.badge(outcome, outcome === 'success' ? 'success' : outcome === 'failure' ? 'danger' : '');
}

export function statusBadge(ui, status) {
  const kind = { succeeded: 'success', running: 'info', pending: 'warning', failed: 'danger', idle: '' }[status] || '';
  return ui.badge(status || 'idle', kind, status === 'running');
}

export async function tenantSelect(ctx, onChange, selected) {
  const sel = ctx.ui.dropdown([{ value: '', label: 'All tenants' }], { value: selected || '', ariaLabel: 'Tenant' });
  try {
    const tenants = (await ctx.api.get(`${ctx.plugin.apiBase}/tenants/names`) || []).slice().sort((left, right) => (left.displayName || '').localeCompare(right.displayName || '', undefined, { sensitivity: 'base' }));
    sel.setOptions([
      { value: '', label: 'All tenants' },
      ...tenants.map((t) => ({ value: t.tenantId, label: `${t.displayName}${t.discoveredName && t.discoveredName !== t.displayName ? ` (${t.discoveredName})` : ''}` })),
    ], selected || '');
  } catch { /* viewer without tenants endpoint access still gets "all" */ }
  sel.addEventListener('change', () => onChange(sel.value));
  return sel;
}

export function kpiCard(ui, label, value, kind = '', delta = '') {
  return ui.h('div', { class: 'card kpi ' + kind }, ui.h('div', { class: 'label' }, label), ui.h('div', { class: 'value' }, value), ui.h('div', { class: 'delta' }, delta));
}

export function bucketsToBarList(ui, buckets, opts) {
  return ui.barList((buckets || []).map((b) => ({ key: b.key, count: b.count })), opts);
}

/** Overview drill-down: a missing-value bucket is notExists, not the literal "(none)". */
export function drillFilter(query, key, field) {
  if (query?.[`${key}Missing`] === '1') return { field, operator: 'notExists', values: [] };
  if (query?.[key]) return { field, operator: 'equals', values: [query[key]] };
  return null;
}

/**
 * Generic event explorer: time range, tenant, free text, filter chips, paginated table and a detail drawer.
 * columns: [{ title, path | render(doc, row), filterField?, class? }]
 */
export function createExplorer(el, ctx, { source, columns, sort = 'desc', defaultRange = '24h', pageSize = 50, initialFilters = [], detailFields = [], ranges = RANGES, selects = [], initialState = null, skipFilter = null }) {
  const { h, clear, table, drawer, fmt, errorMessage, jsonView, kv, badge } = ctx.ui;
  const query = new URLSearchParams(location.search);
  const carriedFilters = initialState?.filters?.map((f) => ({ field: f.field, operator: f.operator, values: [...(f.values || [])], ...(f.drill ? { drill: true } : {}) }));
  const state = {
    range: initialState?.range || defaultRange,
    tenant: initialState?.tenant ?? (query.get('tenant') || ''),
    text: initialState?.text || '',
    filters: carriedFilters || [...initialFilters],
    hits: [],
    total: 0,
    searchAfter: null,
    loading: false,
    fields: [],
    picks: { ...(initialState?.picks || {}) },
  };

  const toolbar = h('div', { class: 'toolbar' });
  const chips = h('div', { class: 'flex wrap' });
  const results = h('div', { class: 'fill' });
  const pager = h('div', { class: 'pager' });
  el.append(toolbar, chips, results, pager);

  const rangeOptions = [...ranges.map(([value, label]) => ({ value, label })), { value: 'custom', label: 'Custom' }];
  const rangeSel = ctx.ui.dropdown(rangeOptions, { value: state.range, ariaLabel: 'Time range' });
  const customFrom = h('input', { class: 'input sm', type: 'date', 'aria-label': 'Start date', hidden: true });
  const customTo = h('input', { class: 'input sm', type: 'date', 'aria-label': 'End date', hidden: true });
  const applyCustom = () => {
    state.range = 'custom';
    customFrom.hidden = false;
    customTo.hidden = false;
    if (!customFrom.value || !customTo.value) {
      const today = localDateInput(new Date());
      customFrom.value = customFrom.value || today;
      customTo.value = customTo.value || today;
    }
    reload();
  };
  rangeSel.addEventListener('change', () => {
    if (rangeSel.value === 'custom') { applyCustom(); return; }
    customFrom.hidden = true;
    customTo.hidden = true;
    state.range = rangeSel.value;
    reload();
  });
  customFrom.addEventListener('change', () => { if (state.range === 'custom') reload(); });
  customTo.addEventListener('change', () => { if (state.range === 'custom') reload(); });
  if (state.range === 'custom') {
    customFrom.hidden = false;
    customTo.hidden = false;
    customFrom.value = initialState?.customFrom || '';
    customTo.value = initialState?.customTo || '';
  }
  const textInput = h('input', { class: 'input', value: state.text, placeholder: 'Search text (AND, OR, "phrase", prefix*)', 'aria-label': 'Search text' });
  textInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { state.text = textInput.value.trim(); reload(); } });
  const searchBtn = h('button', { class: 'btn', onClick: () => { state.text = textInput.value.trim(); reload(); } }, 'Search');
  const addFilterBtn = h('button', { class: 'btn', onClick: () => addFilterDialog() }, 'Add filter');
  const refreshBtn = h('button', { class: 'btn ghost', 'aria-label': 'Refresh', onClick: () => reload() }, ctx.ui.icon('refresh'));
  toolbar.append(rangeSel, customFrom, customTo, textInput, searchBtn, addFilterBtn, refreshBtn);
  for (const spec of selects) {
    if (spec.hidden || state.picks[spec.key] === undefined) state.picks[spec.key] = spec.value || '';
    if (spec.hidden) {
      state.filters = state.filters.filter((filter) => filter.field !== spec.field);
      continue;
    }
    const sel = ctx.ui.dropdown(
      [{ value: '', label: spec.allLabel }, ...spec.options.map(([value, label]) => ({ value, label }))],
      { value: state.picks[spec.key], ariaLabel: spec.ariaLabel },
    );
    spec.control = sel;
    sel.addEventListener('change', () => {
      state.picks[spec.key] = sel.value;
      state.filters = state.filters.filter((filter) => filter.field !== spec.field);
      reload();
    });
    toolbar.insertBefore(sel, textInput);
  }
  tenantSelect(ctx, (v) => { state.tenant = v; reload(); }, state.tenant).then((sel) => toolbar.insertBefore(sel, textInput));

  ctx.api.get(`${ctx.plugin.apiBase}/sources`).then((sources) => { state.fields = sources.find((s) => s.source === source)?.fields || []; }).catch(() => {});

  function selectField(field) {
    return selects.some((spec) => spec.field === field);
  }

  function renderChips() {
    // A select owns its field. A chip for that field would show a value the search does not use.
    state.filters = state.filters.filter((filter) => !selectField(filter.field));
    clear(chips);
    state.filters.forEach((f, i) => {
      if (skipFilter?.(f)) return;
      chips.append(h('span', { class: 'chip' }, `${f.field} ${f.operator} ${(f.values || []).join(' | ')}`, h('button', { type: 'button', 'aria-label': 'Remove filter', onClick: () => { state.filters.splice(i, 1); reload(); } }, '×')));
    });
    if (state.filters.some((f) => !skipFilter?.(f))) chips.append(h('button', { class: 'btn ghost sm', onClick: () => { state.filters = state.filters.filter((f) => skipFilter?.(f)); reload(); } }, 'Clear all'));
  }

  function fieldType(path) {
    return String(state.fields.find((f) => f.path === path)?.type || 'Keyword').toLowerCase();
  }

  function operatorsFor(type) {
    const text = [['equals', 'equals'], ['notEquals', 'does not equal'], ['in', 'is one of (comma separated)'], ['notIn', 'is not one of'], ['prefix', 'starts with'], ['contains', 'contains'], ['exists', 'exists'], ['notExists', 'does not exist'], ['gt', 'greater than'], ['lt', 'less than']];
    if (type === 'date') return [['equals', 'equals'], ['gt', 'after'], ['lt', 'before'], ['exists', 'exists'], ['notExists', 'does not exist']];
    if (type === 'ip') return [['equals', 'equals'], ['notEquals', 'does not equal'], ['in', 'is one of (comma separated)'], ['notIn', 'is not one of'], ['exists', 'exists'], ['notExists', 'does not exist']];
    if (type === 'number' || type === 'wholenumber') return [['equals', 'equals'], ['notEquals', 'does not equal'], ['in', 'is one of (comma separated)'], ['notIn', 'is not one of'], ['gt', 'greater than'], ['lt', 'less than'], ['exists', 'exists'], ['notExists', 'does not exist']];
    if (type === 'boolean') return [['equals', 'equals'], ['notEquals', 'does not equal'], ['exists', 'exists'], ['notExists', 'does not exist']];
    return text;
  }

  async function addFilterDialog(preset) {
    const fieldSel = ctx.ui.dropdown(state.fields.filter((f) => !selectField(f.path)).map((f) => ({ value: f.path, label: `${f.label} (${f.path})` })), { value: preset?.field || '', ariaLabel: 'Field' });
    const opSel = ctx.ui.dropdown(operatorsFor(fieldType(fieldSel.value)), { value: 'equals', ariaLabel: 'Operator' });
    const valueInput = h('input', { class: 'input', value: preset?.value || '', placeholder: 'value' });
    const syncOperator = () => {
      const type = fieldType(fieldSel.value);
      opSel.setOptions(operatorsFor(type));
      valueInput.placeholder = type === 'date' ? '2026-11-13T00:00:00Z' : type === 'boolean' ? 'true or false' : type === 'ip' ? '203.0.113.10' : 'value';
    };
    fieldSel.addEventListener('change', syncOperator);
    syncOperator();
    const box = h('div', { class: 'col' }, h('div', { class: 'field' }, h('label', null, 'Field'), fieldSel), h('div', { class: 'field' }, h('label', null, 'Operator'), opSel), h('div', { class: 'field' }, h('label', null, 'Value'), valueInput));
    valueInput.addEventListener('input', () => valueInput.classList.remove('invalid'));
    await ctx.ui.modal.show({ title: 'Add filter', content: box, actions: [{ label: 'Cancel', value: false }, { label: 'Add', kind: 'primary', onClick: () => {
      const op = opSel.value;
      const type = fieldType(fieldSel.value);
      if (selectField(fieldSel.value)) { ctx.ui.panelNote(box, 'That field is set by a control on this page.'); return false; }
      const values = op.endsWith('xists') ? [] : (op === 'in' || op === 'notIn' ? valueInput.value.split(',').map((s) => s.trim()).filter(Boolean) : [valueInput.value.trim()]);
      if (!operatorsFor(type).some(([value]) => value === op)) { ctx.ui.panelNote(box, 'That operator is not valid for this field.'); return false; }
      if (!op.endsWith('xists') && values.length === 0) { ctx.ui.panelNote(box, 'A value is required.'); valueInput.classList.add('invalid'); return false; }
      if (op === 'contains' && values.some((value) => value.length > 64)) { ctx.ui.panelNote(box, 'Contains filters are limited to 64 characters.'); valueInput.classList.add('invalid'); return false; }
      if (values.some((value) => !valueFits(type, value))) { ctx.ui.panelNote(box, `Enter a valid ${type === 'wholenumber' ? 'number' : type}.`); valueInput.classList.add('invalid'); return false; }
      state.filters.push({ field: fieldSel.value, operator: op, values });
      reload();
      return true;
    } }] });
  }

  function addQuickFilter(field, value) {
    if (value === undefined || value === null || value === '') return;
    const spec = selects.find((item) => item.field === field);
    if (spec) {
      state.picks[spec.key] = String(value);
      if (spec.control) spec.control.value = String(value);
      state.filters = state.filters.filter((filter) => filter.field !== field);
      reload();
      return;
    }
    const text = String(value);
    state.filters = state.filters.filter((filter) => filter.field !== field || filter.operator !== 'equals');
    state.filters.push({ field, operator: 'equals', values: [text] });
    reload();
  }

  function currentBounds() {
    if (state.range !== 'custom') return rangeToDates(state.range);
    return customDayBounds(customFrom.value, customTo.value);
  }

  function buildBody(more) {
    const { from, to } = currentBounds();
    const filters = state.filters.filter((filter) => !skipFilter?.(filter) && !selectField(filter.field)).map(({ field, operator, values }) => ({ field, operator, values }));
    if (state.tenant) filters.push({ field: 'vc.tenantId', operator: 'equals', values: [state.tenant] });
    for (const spec of selects) {
      if (state.picks[spec.key]) filters.push({ field: spec.field, operator: 'equals', values: [state.picks[spec.key]] });
    }
    return { source, from, to, filters, text: state.text || null, size: pageSize, sort, searchAfter: more ? state.searchAfter : null };
  }

  function renderTable() {
    clear(results);
    const cols = columns.map((c) => ({
      title: c.title,
      class: c.class,
      render: (row) => {
        const doc = row.doc;
        let content = c.render ? c.render(doc, row) : (c.path ? get(doc, c.path) : '');
        if (content === undefined || content === null) content = '';
        if (c.filterField) {
          const value = c.path ? get(doc, c.path) : content;
          if (value !== undefined && value !== null && value !== '' && !(value instanceof Node)) {
            return h('a', { href: '#', class: content instanceof Node ? null : 'truncate', title: 'Filter by this value', onClick: (e) => { e.preventDefault(); e.stopPropagation(); addQuickFilter(c.filterField, value); } }, content instanceof Node ? content : String(content));
          }
        }
        return content;
      },
    }));
    results.append(table({ columns: cols, rows: state.hits, onRowClick: (row) => openDetail(row), emptyText: state.loading ? 'Loading…' : 'No events match.' }));
    renderPager();
  }

  function renderPager() {
    clear(pager);
    const eventCount = fmt.number(state.total);
    const eventLabel = state.hits.length < state.total ? `${eventCount} events · showing ${state.hits.length}` : `${eventCount} events`;
    pager.append(h('span', null, state.loading ? 'Loading…' : eventLabel));
    if (state.hits.length < state.total && state.searchAfter) pager.append(h('button', { type: 'button', class: 'btn sm', onClick: () => load(true) }, 'Load more'));
  }

  function scrollPlace() {
    const ancestors = [];
    let node = el;
    while (node) {
      ancestors.push({ node, top: node.scrollTop, left: node.scrollLeft });
      node = node.parentElement;
    }
    const wrap = results.querySelector('.table-wrap');
    return { ancestors, tableTop: wrap ? wrap.scrollTop : 0, tableLeft: wrap ? wrap.scrollLeft : 0 };
  }

  function restoreScroll(place) {
    for (const item of place.ancestors) {
      item.node.scrollTop = item.top;
      item.node.scrollLeft = item.left;
    }
    const wrap = results.querySelector('.table-wrap');
    if (!wrap) return;
    wrap.scrollTop = place.tableTop;
    wrap.scrollLeft = place.tableLeft;
  }

  function openDetail(row) {
    const doc = row.doc;
    const pairs = [['Time', fmt.dateTime(doc['@timestamp'])], ['Tenant', get(doc, 'vc.tenantName') || get(doc, 'vc.tenantId')], ['Source', get(doc, 'vc.source')], ['Action', get(doc, 'event.action')], ['Outcome', get(doc, 'event.outcome')], ['Severity', get(doc, 'event.severity')], ['User', get(doc, 'user.name')], ['IP', get(doc, 'source.address')], ['Location', locationCell(h, doc)], ['App', get(doc, 'client.appName')], ['File / object', get(doc, 'file.path')], ['User agent', get(doc, 'user_agent.original')], ['Message', doc.message]];
    for (const f of detailFields) pairs.push([f.label, get(doc, f.path)]);
    const labels = doc.labels ? Object.entries(doc.labels).map(([k, v]) => [k, String(v)]) : [];
    drawer.open({ title: doc.message || get(doc, 'event.action') || 'Event', content: h('div', { class: 'col gap-lg' }, kv(pairs), labels.length ? h('div', null, h('h3', null, 'Labels'), kv(labels)) : null, h('details', { class: 'json', open: true }, h('summary', null, 'Raw record'), jsonView(doc.data || doc))) });
  }

  let loadToken = 0;
  async function load(more) {
    const token = ++loadToken;
    const bounds = currentBounds();
    if ((state.text || '').length > 256) {
      state.loading = false;
      clear(results).append(h('div', { class: 'alert danger' }, 'Search text is limited to 256 characters.'));
      clear(pager);
      return;
    }
    if (bounds?.error) {
      state.loading = false;
      clear(results).append(h('div', { class: 'alert danger' }, bounds.error));
      clear(pager);
      return;
    }
    const place = more ? scrollPlace() : null;
    if (more && document.activeElement && el.contains(document.activeElement)) document.activeElement.blur();
    state.loading = true;
    if (!more) { state.hits = []; state.total = 0; state.searchAfter = null; renderTable(); }
    let res;
    try {
      res = await ctx.api.post(`${ctx.plugin.apiBase}/search`, buildBody(more));
    } catch (err) {
      if (token !== loadToken) return;
      state.loading = false;
      const alert = h('div', { class: 'alert ' + (err.status === 503 ? 'warning' : 'danger') }, err.status === 503 ? 'Search backend unavailable: ' + errorMessage(err) : errorMessage(err));
      if (more) {
        renderTable();
        results.prepend(alert);
        if (place) {
          restoreScroll(place);
          requestAnimationFrame(() => restoreScroll(place));
        }
      } else {
        clear(results).append(alert);
        renderPager();
      }
      return;
    }
    if (token !== loadToken) return;
    state.hits = more ? state.hits.concat(res.hits) : res.hits;
    state.total = res.total;
    state.searchAfter = res.hits.length ? res.hits[res.hits.length - 1].sort : null;
    state.loading = false;
    renderTable();
    if (place) {
      restoreScroll(place);
      requestAnimationFrame(() => restoreScroll(place));
    }
  }

  function reload() { renderChips(); load(false); }

  reload();
  return {
    reload,
    addQuickFilter,
    state,
    snapshot() {
      return {
        range: state.range,
        tenant: state.tenant,
        text: state.text,
        filters: state.filters.map((f) => ({ field: f.field, operator: f.operator, values: [...(f.values || [])], ...(f.drill ? { drill: true } : {}) })),
        picks: { ...state.picks },
        customFrom: customFrom.value,
        customTo: customTo.value,
      };
    },
    destroy() { loadToken += 1; drawer.close(); },
  };
}
