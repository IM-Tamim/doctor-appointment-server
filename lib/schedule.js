// Doctor schedules → bookable slots, in the clinic's local time.
//
// A doctor's weekly pattern is `availability: [{ day, sessions: [{start, end}] }]`
// plus `maxPerHour` (patients per hour, default 2 → 30-minute slots). Older
// profiles stored an explicit `slots: ["10:00", ...]` list per day; those are
// still honoured so existing doctors keep working until they re-save.

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

// Bangladesh has no DST, so a fixed offset is exact. Dates/times on
// appointments are wall-clock strings in this zone.
const TZ_OFFSET = process.env.APP_TZ_OFFSET || "+06:00";
const TZ_OFFSET_MINUTES = (() => {
  const m = /^([+-])(\d{2}):(\d{2})$/.exec(TZ_OFFSET);
  if (!m) return 360;
  return (m[1] === "-" ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3]));
})();

const PER_HOUR_OPTIONS = [1, 2, 3, 4, 6];
const DEFAULT_PER_HOUR = 2;

const isTime = (v) => typeof v === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(v);
const isDate = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(`${v}T00:00:00Z`));

const toMinutes = (hhmm) => {
  const [h, m] = hhmm.split(":").map(Number);
  return h * 60 + m;
};
const fromMinutes = (total) =>
  `${String(Math.floor(total / 60)).padStart(2, "0")}:${String(total % 60).padStart(2, "0")}`;

const perHourOf = (doctor) =>
  PER_HOUR_OPTIONS.includes(Number(doctor?.maxPerHour)) ? Number(doctor.maxPerHour) : DEFAULT_PER_HOUR;

const slotMinutesOf = (doctor) => 60 / perHourOf(doctor);

/** "YYYY-MM-DD" → "Monday" (calendar maths only, timezone-independent). */
const weekdayOf = (dateStr) => WEEKDAYS[new Date(`${dateStr}T00:00:00Z`).getUTCDay()];

/** Absolute instant of a wall-clock date + time in the clinic's zone. */
const slotInstant = (dateStr, timeStr) => new Date(`${dateStr}T${timeStr}:00${TZ_OFFSET}`);

/** Today's date and the current time, as wall-clock strings in the clinic's zone. */
const clinicNow = () => {
  const shifted = new Date(Date.now() + TZ_OFFSET_MINUTES * 60 * 1000).toISOString();
  return { date: shifted.slice(0, 10), time: shifted.slice(11, 16) };
};

const addDays = (dateStr, days) => {
  const d = new Date(`${dateStr}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
};

/** Leave days, including the legacy `blockedDates` field. */
const leaveDatesOf = (doctor) =>
  [...new Set([...(doctor?.leaveDates || []), ...(doctor?.blockedDates || [])])].sort();

/**
 * The doctor's slots on a weekday, in order. A slot's serial is its 1-based
 * position in the day, so it's stable for a given schedule and needs no
 * counter: with 30-minute slots from 10:00, 10:00 is #1 and 10:30 is #2.
 */
const daySlots = (doctor, weekday) => {
  const day = (doctor?.availability || []).find((a) => a.day === weekday);
  if (!day) return [];

  let times;
  if (Array.isArray(day.sessions) && day.sessions.length > 0) {
    const step = slotMinutesOf(doctor);
    times = [];
    for (const s of day.sessions) {
      if (!isTime(s?.start) || !isTime(s?.end)) continue;
      for (let t = toMinutes(s.start); t + step <= toMinutes(s.end); t += step) times.push(fromMinutes(t));
    }
  } else {
    times = Array.isArray(day.slots) ? day.slots.filter(isTime) : [];
  }

  return [...new Set(times)].sort().map((time, i) => ({ time, serial: i + 1 }));
};

/**
 * Validates and normalises one weekday's sessions from a form: drops empty
 * rows, sorts by start, and rejects reversed or overlapping ranges.
 */
const normalizeSessions = (sessions, day) => {
  if (!Array.isArray(sessions)) return { sessions: [] };
  const clean = sessions
    .filter((s) => s && (s.start || s.end))
    .map((s) => ({ start: String(s.start || ""), end: String(s.end || "") }));

  for (const s of clean) {
    if (!isTime(s.start) || !isTime(s.end)) return { error: `${day}: every session needs a start and end time.` };
    if (toMinutes(s.end) <= toMinutes(s.start)) return { error: `${day}: a session must end after it starts (${s.start}–${s.end}).` };
  }
  clean.sort((a, b) => toMinutes(a.start) - toMinutes(b.start));
  for (let i = 1; i < clean.length; i++) {
    if (toMinutes(clean[i].start) < toMinutes(clean[i - 1].end)) {
      return { error: `${day}: sessions ${clean[i - 1].start}–${clean[i - 1].end} and ${clean[i].start}–${clean[i].end} overlap.` };
    }
  }
  return { sessions: clean.slice(0, 6) };
};

module.exports = {
  WEEKDAYS,
  PER_HOUR_OPTIONS,
  isTime,
  isDate,
  perHourOf,
  slotMinutesOf,
  weekdayOf,
  slotInstant,
  clinicNow,
  addDays,
  leaveDatesOf,
  daySlots,
  normalizeSessions,
};
