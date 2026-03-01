import { useState } from "react";
import { Crosshair, Unlock, Cpu, Radio, Database, ChevronDown, ChevronUp } from "lucide-react";

const BAD_DOMAIN_PATTERNS = ["bad-actor", "phish", "c2", ".ru", ".xyz", ".tk", ".pw", ".onion"];

function isBadDomain(domain) {
  if (!domain) return false;
  const d = domain.toLowerCase();
  return BAD_DOMAIN_PATTERNS.some((pattern) => {
    if (pattern.startsWith(".")) return d.endsWith(pattern);
    return d.split(".").includes(pattern) || d.includes("." + pattern + ".") || d.startsWith(pattern + ".");
  });
}

const STAGES = [
  {
    id:      "recon",
    label:   "Reconnaissance",
    icon:    Crosshair,
    desc:    "Attacker probing / scanning for entry points",
    mitre:   "TA0043",
    countEvidence: (data) => {
      const all = [
        ...(data.auth_logs     || []),
        ...(data.auth_logs_1   || []),
        ...Object.entries(data).filter(([k]) => k.includes("auth")).flatMap(([,v]) => v || []),
      ];
      return [...new Set(all)].filter((r) => String(r.action || "").toLowerCase().includes("failed")).length;
    },
    detect: (data) => {
      const rows = Object.entries(data).filter(([k]) => k.includes("auth")).flatMap(([,v]) => v || []);
      return rows.filter((r) => String(r.action || "").toLowerCase().includes("failed")).length >= 5;
    },
    filterKey:   "failed",
    filterSource:"auth",
    narrative:   (data) => {
      const rows = Object.entries(data).filter(([k]) => k.includes("auth")).flatMap(([,v]) => v || []);
      const fails = rows.filter((r) => String(r.action || "").toLowerCase().includes("failed"));
      const ips   = [...new Set(fails.map((r) => r.source_ip))];
      return `${fails.length} failed login attempt${fails.length !== 1 ? "s" : ""} from ${ips.length} unique IP${ips.length !== 1 ? "s" : ""} detected. Primary source: ${ips[0] || "unknown"}.`;
    },
  },
  {
    id:      "access",
    label:   "Initial Access",
    icon:    Unlock,
    desc:    "Credential brute-force achieving entry",
    mitre:   "TA0001",
    countEvidence: (data) => {
      const rows = Object.entries(data).filter(([k]) => k.includes("auth")).flatMap(([,v]) => v || []);
      return rows.filter((r) => String(r.action || "").toLowerCase().includes("failed")).length;
    },
    detect: (data) => {
      const rows = Object.entries(data).filter(([k]) => k.includes("auth")).flatMap(([,v]) => v || []);
      return rows.filter((r) => String(r.action || "").toLowerCase().includes("failed")).length >= 50;
    },
    filterKey:   "failed",
    filterSource:"auth",
    narrative:   (data) => {
      const rows  = Object.entries(data).filter(([k]) => k.includes("auth")).flatMap(([,v]) => v || []);
      const fails = rows.filter((r) => String(r.action || "").toLowerCase().includes("failed"));
      const byIP  = {};
      fails.forEach((r) => { byIP[r.source_ip] = (byIP[r.source_ip] || 0) + 1; });
      const top   = Object.entries(byIP).sort((a,b) => b[1]-a[1])[0];
      return top ? `${top[0]} made ${top[1]} failed attempts — threshold for brute-force compromise exceeded.` : "High-volume failed login activity detected.";
    },
  },
  {
    id:      "execution",
    label:   "Execution",
    icon:    Cpu,
    desc:    "Malware deployed and running on host",
    mitre:   "TA0002",
    countEvidence: (data) => {
      return Object.entries(data).filter(([k]) => k.includes("malware")).flatMap(([,v]) => v || []).length;
    },
    detect: (data) => {
      return Object.entries(data).filter(([k]) => k.includes("malware")).flatMap(([,v]) => v || []).length > 0;
    },
    filterKey:   "",
    filterSource:"malware",
    narrative:   (data) => {
      const rows    = Object.entries(data).filter(([k]) => k.includes("malware")).flatMap(([,v]) => v || []);
      const threats = [...new Set(rows.map((r) => r.threat_name || r.threat || "Unknown"))];
      const hosts   = [...new Set(rows.map((r) => r.hostname || r.host || "Unknown"))];
      return `${rows.length} malware alert${rows.length !== 1 ? "s" : ""} on ${hosts.join(", ")}. Threat${threats.length > 1 ? "s" : ""}: ${threats.join(", ")}.`;
    },
  },
  {
    id:      "c2",
    label:   "C2 Beacon",
    icon:    Radio,
    desc:    "Compromised host calling back to attacker",
    mitre:   "TA0011",
    countEvidence: (data) => {
      const rows = Object.entries(data).filter(([k]) => k.includes("dns")).flatMap(([,v]) => v || []);
      return rows.filter((r) => isBadDomain(r.domain_queried)).length;
    },
    detect: (data) => {
      const rows = Object.entries(data).filter(([k]) => k.includes("dns")).flatMap(([,v]) => v || []);
      return rows.some((r) => isBadDomain(r.domain_queried));
    },
    filterKey:   "bad-actor",
    filterSource:"dns",
    narrative:   (data) => {
      const rows    = Object.entries(data).filter(([k]) => k.includes("dns")).flatMap(([,v]) => v || []);
      const badRows = rows.filter((r) => isBadDomain(r.domain_queried));
      const domains = [...new Set(badRows.map((r) => r.domain_queried))];
      return `${badRows.length} query${badRows.length !== 1 ? "s" : ""} to malicious domain${domains.length > 1 ? "s" : ""}: ${domains.slice(0,2).join(", ")}. Active C2 channel confirmed.`;
    },
  },
  {
    id:      "exfil",
    label:   "Exfiltration",
    icon:    Database,
    desc:    "Data leaving network to external host",
    mitre:   "TA0010",
    countEvidence: (data) => {
      const rows = Object.entries(data).filter(([k]) => k.includes("firewall")).flatMap(([,v]) => v || []);
      return rows.filter((r) => r.action === "Block" && r.destination_port === "443").length;
    },
    detect: (data) => {
      const rows = Object.entries(data).filter(([k]) => k.includes("firewall")).flatMap(([,v]) => v || []);
      return rows.filter((r) => r.action === "Block" && r.destination_port === "443").length > 20;
    },
    filterKey:   "Block",
    filterSource:"firewall",
    narrative:   (data) => {
      const rows    = Object.entries(data).filter(([k]) => k.includes("firewall")).flatMap(([,v]) => v || []);
      const blocked = rows.filter((r) => r.action === "Block" && r.destination_port === "443");
      return `${blocked.length} outbound HTTPS connections blocked. Possible data exfiltration attempt via encrypted channel.`;
    },
  },
];

export default function KillChain({ data, onFilterSelect }) {
  const [expandedStage, setExpandedStage] = useState(null);

  const activeStages = new Set(STAGES.filter((s) => s.detect(data)).map((s) => s.id));
  const activeCount  = activeStages.size;

  const narrativeSentence = (() => {
    if (!activeStages.has("recon") && !activeStages.has("access")) return null;
    const parts = [];
    const authRows  = Object.entries(data).filter(([k]) => k.includes("auth")).flatMap(([,v]) => v || []);
    const failRows  = authRows.filter((r) => String(r.action || "").toLowerCase().includes("failed"));
    const extIPs    = [...new Set(failRows.map((r) => r.source_ip).filter((ip) => ip && !ip.startsWith("10.")))];
    const malRows   = Object.entries(data).filter(([k]) => k.includes("malware")).flatMap(([,v]) => v || []);
    const dnsRows   = Object.entries(data).filter(([k]) => k.includes("dns")).flatMap(([,v]) => v || []);
    const badDNS    = dnsRows.filter((r) => isBadDomain(r.domain_queried));
    const c2Hosts   = [...new Set(badDNS.map((r) => r.client_ip))];

    if (extIPs.length)   parts.push(`${extIPs[0]} launched a brute-force attack`);
    if (malRows.length)  parts.push(`malware was deployed on ${malRows[0]?.hostname || "an internal host"}`);
    if (c2Hosts.length)  parts.push(`${c2Hosts[0]} established a C2 beacon to ${badDNS[0]?.domain_queried || "external infrastructure"}`);
    return parts.length ? parts.join(", then ") + "." : null;
  })();

  return (
    <div className="card col-span-2">
      <div className="card-title" style={{ marginBottom: "16px" }}>
        <Crosshair size={14} />
        Attack Kill Chain
        <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace", marginLeft: "4px" }}>
          — click a stage for evidence
        </span>
        <div style={{ marginLeft: "auto", display: "flex", gap: "8px", alignItems: "center" }}>
          {activeCount > 0 && (
            <span className="badge badge-critical">{activeCount} stage{activeCount > 1 ? "s" : ""} detected</span>
          )}
          {activeCount === 0 && (
            <span className="badge badge-low">No stages detected</span>
          )}
        </div>
      </div>

      <div className="kill-chain">
        {STAGES.map((stage, i) => {
          const isActive   = activeStages.has(stage.id);
          const isLast     = i === STAGES.length - 1;
          const isExpanded = expandedStage === stage.id;
          const Icon       = stage.icon;
          const count      = isActive ? stage.countEvidence(data) : 0;
          const arrowActive = isActive && !isLast && activeStages.has(STAGES[i + 1]?.id);

          return (
            <div key={stage.id} className="kill-chain-step">
              <div
                className={`kill-chain-node ${isActive ? "active" : "inactive"}`}
                onClick={() => isActive && setExpandedStage(isExpanded ? null : stage.id)}
                style={{ cursor: isActive ? "pointer" : "default", position: "relative" }}
                title={isActive ? "Click to see evidence" : ""}
              >
                <Icon size={18} style={{ color: isActive ? "var(--red)" : "var(--text-muted)" }} />
                <span style={{
                  fontSize: "10px", fontWeight: 700, letterSpacing: "0.06em",
                  textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace",
                  color: isActive ? "var(--red)" : "var(--text-muted)",
                }}>
                  {stage.label}
                </span>
                <span style={{ fontSize: "9px", color: "var(--text-muted)", letterSpacing: "0.04em" }}>
                  {stage.mitre}
                </span>
                <span style={{
                  fontSize: "10px",
                  color: isActive ? "var(--text-secondary)" : "var(--text-muted)",
                  lineHeight: 1.3, textAlign: "center",
                }}>
                  {stage.desc}
                </span>
                {isActive && (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "3px" }}>
                    <span className="badge badge-critical" style={{ fontSize: "9px", padding: "1px 6px" }}>
                      {count} event{count !== 1 ? "s" : ""}
                    </span>
                    <span style={{ fontSize: "9px", color: "var(--blue)", fontFamily: "'Share Tech Mono', monospace", display: "flex", alignItems: "center", gap: "2px" }}>
                      {isExpanded ? <ChevronUp size={9} /> : <ChevronDown size={9} />}
                      {isExpanded ? "hide" : "details"}
                    </span>
                  </div>
                )}
              </div>
              {!isLast && (
                <div className={`kill-chain-arrow ${arrowActive ? "active" : "inactive"}`} />
              )}
            </div>
          );
        })}
      </div>

      {expandedStage && (() => {
        const stage = STAGES.find((s) => s.id === expandedStage);
        if (!stage) return null;
        return (
          <div className="animate-in" style={{
            marginTop: "14px", background: "var(--red-bg)",
            border: "1px solid var(--red-border)", borderRadius: "5px",
            padding: "14px 16px",
          }}>
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: "12px", flexWrap: "wrap" }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: "10px", color: "var(--red)", letterSpacing: "0.12em", textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace", marginBottom: "6px", fontWeight: 700 }}>
                  {stage.label} — Evidence Summary
                </div>
                <p style={{ fontSize: "13px", color: "var(--text-primary)", lineHeight: 1.7 }}>
                  {stage.narrative(data)}
                </p>
              </div>
              {onFilterSelect && (
                <button
                  className="btn"
                  style={{ padding: "6px 14px", fontSize: "11px", whiteSpace: "nowrap", flexShrink: 0 }}
                  onClick={() => onFilterSelect(stage.filterKey, stage.filterSource)}
                >
                  View in Log Explorer →
                </button>
              )}
            </div>
          </div>
        );
      })()}

      {narrativeSentence && (
        <div style={{
          marginTop: "14px", padding: "10px 14px",
          background: "var(--bg-secondary)", border: "1px solid var(--border)",
          borderLeft: "3px solid var(--red)", borderRadius: "4px",
          fontSize: "12px", color: "var(--text-secondary)",
          fontFamily: "'Share Tech Mono', monospace", lineHeight: 1.6,
        }}>
          <span style={{ color: "var(--red)", marginRight: "8px" }}>⚠ ATTACK STORY:</span>
          {narrativeSentence}
        </div>
      )}
    </div>
  );
}
