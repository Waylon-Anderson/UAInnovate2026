const PROMPT_INJECTION_PATTERN = /[`<>{}[\]\\]/g;
const SAFE_LABEL_PATTERN = /[^a-zA-Z0-9 .,\-_:/@#()']/g;

export function sanitizeText(value, maxLength = 200) {
  if (typeof value !== "string") return "";
  return value.replace(PROMPT_INJECTION_PATTERN, "").trim().slice(0, maxLength);
}

export function sanitizeMultiline(value, maxLength = 4000) {
  if (typeof value !== "string") return "";
  return value.replace(PROMPT_INJECTION_PATTERN, "").slice(0, maxLength);
}

export function sanitizeQuery(value, maxLength = 200) {
  if (typeof value !== "string") return "";
  return value.replace(/[<>&'"`;{}[\]\\]/g, "").slice(0, maxLength);
}

export function sanitizeTag(value, maxLength = 50) {
  if (typeof value !== "string") return "";
  return value.replace(SAFE_LABEL_PATTERN, "").trim().slice(0, maxLength);
}

export function sanitizePromptInput(value, maxLength = 500) {
  if (typeof value !== "string") return "";
  return value
    .replace(/[`<>{}[\]\\]/g, "")
    .replace(/system:|assistant:|human:|<\/?[a-z]+>/gi, "")
    .trim()
    .slice(0, maxLength);
}

export function sanitizeCsvValue(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[<>&'"`;]/g, "").trim().slice(0, 500);
}
