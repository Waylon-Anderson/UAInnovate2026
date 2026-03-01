export function formatTimestamp(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const mm   = String(d.getMonth() + 1).padStart(2, "0");
  const dd   = String(d.getDate()).padStart(2, "0");
  const yyyy = d.getFullYear();
  const raw  = d.getHours();
  const ampm = raw >= 12 ? "PM" : "AM";
  const hh   = String(raw % 12 || 12).padStart(2, "0");
  const min  = String(d.getMinutes()).padStart(2, "0");
  return `${mm}/${dd}/${yyyy} ${hh}:${min} ${ampm}`;
}

export function relativeTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const formatted = formatTimestamp(ts);
  const diff = Date.now() - d.getTime();
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  let relative;
  if (h > 23)    relative = `${Math.floor(h / 24)}d ago`;
  else if (h > 0) relative = `${h}h ${m}m ago`;
  else if (m > 0) relative = `${m}m ago`;
  else            relative = "just now";
  return `${relative} — ${formatted}`;
}

export function relativeOnly(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const diff = Date.now() - d.getTime();
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  if (h > 23)    return `${Math.floor(h / 24)}d ago`;
  if (h > 0)     return `${h}h ${m}m ago`;
  if (m > 0)     return `${m}m ago`;
  return "just now";
}
