/**
 * sanitize.js — Input sanitization for all user-controlled fields.
 *
 * React's JSX already escapes values rendered into the DOM, preventing
 * reflected XSS. These utilities cover the additional attack surfaces:
 *   - localStorage persistence (stored strings re-read on load)
 *   - AI prompt injection (user text injected into LLM prompts)
 *   - Search/filter queries used in string comparisons
 *   - Tag/label fields stored and re-displayed
 *
 * There is no SQL database in this app so SQL injection is not applicable,
 * but the same stripping rules eliminate any similar delimiter-injection
 * risk in localStorage keys or prompt concatenation.
 */

// Characters that could break out of prompt strings or JSON stored in localStorage
const PROMPT_INJECTION_PATTERN = /[`<>{}[\]\\]/g;

// Allowed characters for structured short fields (names, tags, IPs)
const SAFE_LABEL_PATTERN = /[^a-zA-Z0-9 .,\-_:/@#()']/g;

/**
 * sanitizeText — General purpose single-line field (analyst name, tags).
 * Strips prompt-injection characters. Trims and enforces max length.
 */
export function sanitizeText(value, maxLength = 200) {
  if (typeof value !== "string") return "";
  return value
    .replace(PROMPT_INJECTION_PATTERN, "")
    .trim()
    .slice(0, maxLength);
}

/**
 * sanitizeMultiline — Textarea fields (notes, description).
 * Allows newlines but strips injection characters. Enforces max length.
 */
export function sanitizeMultiline(value, maxLength = 4000) {
  if (typeof value !== "string") return "";
  return value
    .replace(PROMPT_INJECTION_PATTERN, "")
    .slice(0, maxLength);
}

/**
 * sanitizeQuery — Search/filter input.
 * Keeps alphanumeric, spaces, dots, dashes, underscores, colons, slashes.
 * Short max length — search terms don't need to be essays.
 */
export function sanitizeQuery(value, maxLength = 200) {
  if (typeof value !== "string") return "";
  return value
    .replace(/[<>&'"`;{}[\]\\]/g, "")
    .slice(0, maxLength);
}

/**
 * sanitizeTag — Single tag label.
 * Strict: letters, numbers, spaces, hyphens, underscores only.
 */
export function sanitizeTag(value, maxLength = 50) {
  if (typeof value !== "string") return "";
  return value
    .replace(SAFE_LABEL_PATTERN, "")
    .trim()
    .slice(0, maxLength);
}

/**
 * sanitizePromptInput — Text going directly into an AI prompt.
 * Most aggressive: strips anything that could manipulate prompt structure.
 */
export function sanitizePromptInput(value, maxLength = 500) {
  if (typeof value !== "string") return "";
  return value
    .replace(/[`<>{}[\]\\]/g, "")   // remove structural chars
    .replace(/system:|assistant:|human:|<\/?[a-z]+>/gi, "") // strip role injection attempts
    .trim()
    .slice(0, maxLength);
}

/**
 * sanitizeCsvValue — Values read from CSV files before display.
 * React JSX escapes on render, but this adds defense-in-depth for
 * values used in string comparisons or localStorage keys.
 */
export function sanitizeCsvValue(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[<>&'"`;]/g, "").trim().slice(0, 500);
}