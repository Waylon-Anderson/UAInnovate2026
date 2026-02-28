const BAD_DOMAINS = ["bad-actor", "phish", "malware", "c2", ".ru", ".xyz", ".tk", ".pw"];
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
    const domain = String(r.domain_queried || "").toLowerCase();
    if (BAD_DOMAINS.some((d) => domain.includes(d))) {
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
    // Accept any row that has either hostname or threat_name populated
    const host   = r.hostname   || r.host   || r.ip       || r.source_ip || "Unknown";
    const threat = r.threat_name || r.threat || r.malware  || r.alert     || "Unknown Threat";
    incidents.push({
      type:      "Malware",
      ip:        host,
      detail:    threat,
      severity:  "CRITICAL",
      timestamp: r.timestamp || r.time || null,
    });
  });

  // ── Firewall: blocked connections ─────────────────────────────────────────
  firewall_logs.forEach((r) => {
    const action = String(r.action || "").toLowerCase();
    if (action === "block" || action === "deny") {
      incidents.push({
        type:      "Firewall Block",
        ip:        r.source_ip,
        detail:    `→ ${r.destination_ip}:${r.destination_port}`,
        severity:  "MEDIUM",
        timestamp: r.timestamp,
      });
    }
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
    const domain = String(r.domain_queried || "").toLowerCase();
    if (BAD_DOMAINS.some((d) => domain.includes(d))) addScore(r.client_ip, 40);
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