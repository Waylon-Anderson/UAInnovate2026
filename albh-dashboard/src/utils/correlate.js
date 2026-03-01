// Bad domain patterns — matched against the full domain string.
// Rules:
//   string starting with "." → matches as a TLD suffix (e.g. ".ru" only matches foo.ru, not "guru")
//   otherwise → must match as a full segment separated by dots (e.g. "bad-actor" matches bad-actor.ru but NOT telemetry-bad-actorsomething.com)
const BAD_DOMAIN_PATTERNS = ["bad-actor", "phish", "c2", ".ru", ".xyz", ".tk", ".pw", ".onion"];

function isBadDomain(domain) {
  if (!domain) return false;
  const d = domain.toLowerCase();
  return BAD_DOMAIN_PATTERNS.some((pattern) => {
    if (pattern.startsWith(".")) {
      // TLD match — domain must END with this suffix
      return d.endsWith(pattern);
    }
    // Segment match — must appear as a full dot-delimited part
    return d.split(".").includes(pattern) || d.includes("." + pattern + ".") || d.startsWith(pattern + ".");
  });
}
const BRUTE_FORCE_THRESHOLD = 5;

// Collects rows from every loaded file whose key contains the keyword.
// Handles filenames with spaces, numbers, underscores — anything.
function collectRows(data, keyword) {
  const kw = keyword.toLowerCase();
  return Object.entries(data)
    .filter(([key]) => key.toLowerCase().includes(kw))
    .flatMap(([key, rows]) => {
      console.log(`[correlate] "${key}" matched keyword "${keyword}" → ${rows?.length} rows`);
      return rows || [];
    });
}

export function correlateEvents(data) {
  console.log("[correlate] Data keys:", Object.keys(data));

  const auth_logs      = collectRows(data, "auth");
  const dns_logs       = collectRows(data, "dns");
  const firewall_logs  = collectRows(data, "firewall");

  // Collect from ANY file with "malware" in the name — covers:
  // malware_alerts.csv, malware_alerts 1.csv, malware_alerts_2.csv, etc.
  const malware_alerts = collectRows(data, "malware");

  console.log(`[correlate] malware_alerts total rows: ${malware_alerts.length}`);

  const suspiciousIPs = new Set();
  const incidents     = [];

  // ── Auth: brute-force detection ──────────────────────────────────────────
  const failCounts     = {};
  const failTimestamps = {};
  auth_logs.forEach((r) => {
    const action = String(r.action || "").toLowerCase();
    if (!action.includes("failed")) return;
    const ip = r.source_ip;
    if (!ip) return;
    failCounts[ip]     = (failCounts[ip] || 0) + 1;
    if (!failTimestamps[ip]) failTimestamps[ip] = r.timestamp;
  });
  Object.entries(failCounts).forEach(([ip, count]) => {
    if (count >= BRUTE_FORCE_THRESHOLD) {
      suspiciousIPs.add(ip);
      incidents.push({
        type:      "Brute Force",
        ip,
        detail:    `${count} failed login attempts`,
        severity:  count >= 50 ? "CRITICAL" : "HIGH",
        timestamp: failTimestamps[ip],
      });
    }
  });

  // ── DNS: malicious domain queries ─────────────────────────────────────────
  dns_logs.forEach((r) => {
    if (isBadDomain(r.domain_queried)) {
      suspiciousIPs.add(r.client_ip);
      incidents.push({
        type:      "Malicious DNS",
        ip:        r.client_ip,
        detail:    r.domain_queried,
        severity:  "CRITICAL",
        timestamp: r.timestamp,
      });
    }
  });

  // ── Malware: all files with "malware" in name ─────────────────────────────
  malware_alerts.forEach((r) => {
    // Log columns on first row to help debug second file mismatches
    if (malware_alerts.indexOf(r) === 0) {
      console.log("[correlate] malware row columns:", Object.keys(r));
    }
    const host   = r.hostname   || r.host      || r.ip        || r.source_ip  || r.machine || r.device   || "Unknown";
    const threat = r.threat_name || r.threat    || r.malware   || r.alert      || r.signature || r.detection || "Unknown Threat";
    incidents.push({
      type:      "Malware",
      ip:        host,
      detail:    threat,
      severity:  "CRITICAL",
      timestamp: r.timestamp || r.time || r.date || null,
    });
  });

  // ── IP Threat Scoring ─────────────────────────────────────────────────────
  const ipScores = {};

  const addScore = (ip, points) => {
    if (!ip || !ip.startsWith("10.")) return;
    ipScores[ip] = (ipScores[ip] || 0) + points;
  };

  auth_logs.forEach((r) => {
    const action = String(r.action || "").toLowerCase();
    if (action.includes("failed")) addScore(r.source_ip, 1);
    if (suspiciousIPs.has(r.source_ip)) addScore(r.source_ip, 5);
  });

  dns_logs.forEach((r) => {
    if (isBadDomain(r.domain_queried)) addScore(r.client_ip, 40);
  });

  malware_alerts.forEach((r) => {
    const host = r.hostname || r.host || r.ip || r.source_ip || "";
    if (host.startsWith("10.")) ipScores[host] = (ipScores[host] || 0) + 50;
  });

  // Cap scores at 100
  Object.keys(ipScores).forEach((ip) => {
    ipScores[ip] = Math.min(ipScores[ip], 100);
  });

  return { incidents, ipScores, suspiciousIPs };
}