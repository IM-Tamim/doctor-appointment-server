// Symptom → specialty suggestions for the AI assistant. Not a diagnosis tool.
//
// Google Gemini (free tier) classifies the message into one of OUR specialties
// (a fixed enum, via JSON-schema output) plus an urgency; the caller then looks
// up real doctors in the database, so the assistant can never invent one. A
// keyword red-flag check runs on every message regardless of the model, and a
// keyword classifier takes over when no API key is configured or the call fails.
const { z } = require("zod");

const SPECIALTIES = [
  "Cardiology", "Dermatology", "Dentistry", "Endocrinology", "ENT", "Gastroenterology",
  "General Medicine", "Gynecology", "Nephrology", "Neurology", "Oncology", "Ophthalmology",
  "Orthopedics", "Pediatrics", "Psychiatry", "Pulmonology", "Urology",
];

// Free-tier Gemini model; any Flash / Flash-Lite model works here.
const MODEL = process.env.AI_MODEL || "gemini-3.5-flash-lite";
const GEMINI_URL = (model) => `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

// Symptoms that need emergency care now, in English and Bangla. Matching any
// of these always produces the emergency message, whatever the model says.
const RED_FLAGS = [
  [/chest (pain|tightness|pressure)|বুকে (ব্যথা|চাপ)/i, "chest pain"],
  [/can'?t breathe|cannot breathe|difficulty breathing|short(ness)? of breath|শ্বাস(কষ্ট| নিতে কষ্ট)/i, "trouble breathing"],
  [/unconscious|faint(ed|ing)|passed out|অজ্ঞান/i, "loss of consciousness"],
  [/stroke|face droop|slurred speech|one side (weak|numb)|মুখ বেঁকে|কথা জড়িয়ে/i, "stroke signs"],
  [/seizure|convulsion|খিঁচুনি/i, "seizure"],
  [/(heavy|severe|won'?t stop) bleeding|vomiting blood|blood in vomit|প্রচুর রক্ত|রক্তবমি/i, "severe bleeding"],
  [/suicid|kill myself|end my life|self[- ]harm|আত্মহত্যা/i, "thoughts of self-harm"],
  [/poison|overdose|বিষ খে/i, "poisoning or overdose"],
  [/severe (burn|head injury)|accident|দুর্ঘটনা/i, "serious injury"],
  [/pregnan\w* .*(bleeding|severe pain)|গর্ভ.*রক্ত/i, "pregnancy emergency"],
];

const KEYWORDS = [
  ["Cardiology", /chest|heart|palpitation|blood pressure|hypertension|বুক|হৃদ|প্রেশার/i],
  ["Dermatology", /skin|rash|acne|itch|eczema|hair (fall|loss)|চুলকানি|ত্বক|ব্রণ|চুল পড়া/i],
  ["Dentistry", /tooth|teeth|gum|dental|দাঁত|মাড়ি/i],
  ["Endocrinology", /diabet|sugar|thyroid|hormone|ডায়াবেটিস|থাইরয়েড/i],
  ["ENT", /\bear\b|ears|hearing|throat|tonsil|sinus|nose|কান|গলা|নাক/i],
  ["Gastroenterology", /stomach|gastric|acidity|diarrh|constipat|vomit|liver|পেট|গ্যাস্ট্রিক|ডায়রিয়া|বমি/i],
  ["Gynecology", /period|menstru|pregnan|vaginal|pcos|মাসিক|গর্ভ/i],
  ["Nephrology", /kidney|dialysis|কিডনি/i],
  ["Neurology", /headache|migraine|numb|dizz|seizure|মাথা ব্যথা|মাথা ঘোরা/i],
  ["Oncology", /cancer|tumou?r|lump|ক্যান্সার|টিউমার/i],
  ["Ophthalmology", /\beye|vision|blurry|চোখ|দৃষ্টি/i],
  ["Orthopedics", /bone|joint|back pain|knee|fracture|sprain|হাড়|জয়েন্ট|কোমর|হাঁটু/i],
  ["Pediatrics", /\b(child|baby|infant|kid|son|daughter)\b|শিশু|বাচ্চা/i],
  ["Psychiatry", /anxi|depress|stress|panic|insomnia|sleep|উদ্বেগ|বিষণ্ণ|ঘুম/i],
  ["Pulmonology", /cough|asthma|wheez|lung|কাশি|হাঁপানি|ফুসফুস/i],
  ["Urology", /urin|bladder|prostate|প্রস্রাব/i],
];

const redFlagsIn = (text) => RED_FLAGS.filter(([rx]) => rx.test(text)).map(([, label]) => label);

const ruleBased = (text, lang) => {
  const hit = KEYWORDS.find(([, rx]) => rx.test(text));
  const specialty = hit ? hit[0] : "General Medicine";
  const reply =
    lang === "bn"
      ? `আপনার বর্ণনা অনুযায়ী একজন ${specialty} বিশেষজ্ঞ দেখানো ভালো হতে পারে।`
      : `Based on what you describe, ${/^[AEIOU]/.test(specialty) ? "an" : "a"} ${specialty} specialist is a sensible place to start.`;
  return { reply, specialty, urgency: "routine", followUpQuestion: null };
};

const TriageSchema = z.object({
  reply: z
    .string()
    .describe("2-4 short sentences to the patient: acknowledge, explain which kind of doctor fits and why. No diagnosis, no medicines, no doses."),
  specialty: z.enum(SPECIALTIES).describe("The single best-fitting specialty from the list."),
  urgency: z.enum(["emergency", "urgent", "routine"]),
  followUpQuestion: z
    .string()
    .nullable()
    .describe("One short clarifying question if the symptoms are too vague to choose well, else null."),
});

const SYSTEM = `You are the booking assistant of DocAppoint, a doctor-appointment platform in Bangladesh.
Your only job is to help a patient decide which kind of specialist to book, from this list: ${SPECIALTIES.join(", ")}.

Rules:
- You are not a doctor and must not diagnose, name a likely disease as fact, or suggest medicines, doses or home treatments.
- Pick the one specialty that best fits the described symptoms. Use General Medicine when nothing more specific fits; use Pediatrics for children under 12.
- urgency: "emergency" for anything that may be life-threatening right now (e.g. chest pain, trouble breathing, stroke signs, heavy bleeding, seizure, loss of consciousness, poisoning, thoughts of self-harm); "urgent" when the patient should be seen within a day or two; otherwise "routine".
- For an emergency, the reply must tell them to call 999 or go to the nearest emergency department now.
- Reply in the patient's language (Bangla or English), warmly and plainly.`;

// The same shape as TriageSchema, in the schema format Gemini accepts. The
// answer is still validated with zod, so a malformed one falls back to rules.
const RESPONSE_SCHEMA = {
  type: "OBJECT",
  properties: {
    reply: { type: "STRING", description: TriageSchema.shape.reply.description },
    specialty: { type: "STRING", enum: SPECIALTIES },
    urgency: { type: "STRING", enum: ["emergency", "urgent", "routine"] },
    followUpQuestion: { type: "STRING", nullable: true, description: TriageSchema.shape.followUpQuestion.description },
  },
  required: ["reply", "specialty", "urgency", "followUpQuestion"],
};

const askGemini = async ({ message, history, lang }) => {
  const res = await fetch(GEMINI_URL(MODEL), {
    method: "POST",
    headers: { "content-type": "application/json", "x-goog-api-key": process.env.GEMINI_API_KEY },
    signal: AbortSignal.timeout(30 * 1000),
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: SYSTEM }] },
      contents: [
        ...history.map((h) => ({ role: h.role === "assistant" ? "model" : "user", parts: [{ text: h.content }] })),
        { role: "user", parts: [{ text: lang === "bn" ? `${message}\n\n(Reply in Bangla.)` : message }] },
      ],
      generationConfig: { responseMimeType: "application/json", responseSchema: RESPONSE_SCHEMA, temperature: 0.2 },
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Gemini API ${res.status}: ${data.error?.message || res.statusText}`);

  const text = data.candidates?.[0]?.content?.parts?.map((p) => p.text || "").join("");
  if (!text) throw new Error(`no answer (${data.promptFeedback?.blockReason || data.candidates?.[0]?.finishReason || "empty"})`);
  const parsed = TriageSchema.safeParse(JSON.parse(text));
  if (!parsed.success) throw new Error("answer did not match the schema");
  return parsed.data;
};

/**
 * @param message  latest patient message
 * @param history  previous turns [{ role: "user"|"assistant", content }]
 * @returns { reply, specialty, urgency, followUpQuestion, redFlags, source }
 */
const triage = async ({ message, history = [], lang = "en" }) => {
  const flags = redFlagsIn([...history.filter((h) => h.role === "user").map((h) => h.content), message].join(" \n"));
  let result = null;
  let source = "rules";

  if (process.env.GEMINI_API_KEY) {
    try {
      result = await askGemini({ message, history, lang });
      source = "ai";
    } catch (err) {
      // Free-tier quota used up (429), network trouble, a blocked answer…
      console.warn(`[triage] ${err.message}; using keyword fallback`);
    }
  }

  if (!result) result = ruleBased(message, lang);
  if (flags.length) result = { ...result, urgency: "emergency" };
  return { ...result, redFlags: flags, source };
};

module.exports = { triage, SPECIALTIES };
