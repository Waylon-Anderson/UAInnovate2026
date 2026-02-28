import { useState } from "react";
import { Bot, ChevronRight, AlertCircle, ClipboardList } from "lucide-react";

function buildPrompt(incidents, data) {
  const eventSummary = incidents
    .map((i) => `[${i.severity}] ${i.type} — IP: ${i.ip} — ${i.detail}${i.timestamp ? ` @ ${i.timestamp}` : ""}`)
    .join("\n");

  const authFails  = (data.auth_logs || []).filter((r) => r.action?.includes("Failed")).length;
  const badDNS     = (data.dns_logs  || []).filter((r) => ["bad-actor","phish","c2",".ru"].some((d) => r.domain_queried?.includes(d))).length;
  const malware    = (data.malware_alerts || []).length;

  return `You are a senior SOC analyst writing a formal incident report.

Log statistics:
- Auth failures: ${authFails}
- Malicious DNS queries: ${badDNS}
- Malware alerts: ${malware}

Correlated incidents:
${eventSummary}

Write the following sections (use these exact headers):
## Incident Summary
3 sentences describing what happened, in plain English.

## Attack Progression
1-2 sentences describing how the attack stages relate to each other.

## Business Impact
1-2 sentences on potential business risk if unaddressed.

## Immediate Actions
A numbered list of 3 specific actions the analyst should take right now.`;
}

export default function AIVerdict({ incidents, data = {} }) {
  const [verdict,  setVerdict]  = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [copied,   setCopied]   = useState(false);

  async function getVerdict() {
    setLoading(true);
    setError("");
    setVerdict("");

    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": import.meta.env.VITE_ANTHROPIC_KEY || "",
          "anthropic-version": "2023-06-01",
          "anthropic-dangerous-direct-browser-access": "true",
        },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 600,
          messages: [{ role: "user", content: buildPrompt(incidents, data) }],
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error?.message || `API error ${res.status}`);
      }

      const json = await res.json();
      setVerdict(json.content[0].text);
    } catch (e) {
      setError(e.message || "Failed to contact AI. Check your API key in .env");
    } finally {
      setLoading(false);
    }
  }

  function copyReport() {
    navigator.clipboard.writeText(verdict);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  // Parse sections from markdown response
  function renderVerdict(text) {
    const sections = text.split(/^##\s+/m).filter(Boolean);
    return sections.map((section, i) => {
      const [title, ...body] = section.split("\n");
      const content = body.join("\n").trim();
      const isActions = title.toLowerCase().includes("action");

      return (
        <div key={i} style={{ marginBottom: "16px" }}>
          <div style={{
            fontSize: "10px", fontWeight: 700, letterSpacing: "0.15em",
            textTransform: "uppercase", color: "var(--blue)",
            fontFamily: "'Share Tech Mono', monospace", marginBottom: "8px",
            display: "flex", alignItems: "center", gap: "6px",
          }}>
            <span style={{ display: "inline-block", width: "3px", height: "12px", background: "var(--blue)", borderRadius: "2px" }} />
            {title.trim()}
          </div>
          <div style={{
            fontSize: "14px", lineHeight: "1.7", color: "var(--text-primary)",
            background: isActions ? "var(--green-bg)" : "var(--bg-secondary)",
            border: `1px solid ${isActions ? "var(--green-border)" : "var(--border)"}`,
            borderRadius: "4px", padding: "12px 14px",
            whiteSpace: "pre-wrap",
          }}>
            {content}
          </div>
        </div>
      );
    });
  }

  const evidenceStats = [
    { label: "Auth Failures",   value: (data.auth_logs || []).filter((r) => r.action?.includes("Failed")).length,   color: "var(--red)" },
    { label: "Bad DNS Queries", value: (data.dns_logs  || []).filter((r) => ["bad-actor","phish","c2",".ru"].some((d) => r.domain_queried?.includes(d))).length, color: "var(--red)" },
    { label: "Malware Alerts",  value: (data.malware_alerts || []).length,  color: "var(--red)" },
    { label: "Total Incidents", value: incidents.length, color: "var(--yellow)" },
  ];

  return (
    <div className="card col-span-2" style={{
      borderColor: verdict ? "var(--blue-border)" : "var(--border)",
      boxShadow: verdict ? "var(--blue-glow)" : "none",
      transition: "border-color 0.4s, box-shadow 0.4s",
    }}>
      <div className="card-title" style={{ marginBottom: "18px" }}>
        <Bot size={14} />
        AI Incident Analysis
        <div style={{ marginLeft: "auto", display: "flex", gap: "8px", alignItems: "center" }}>
          {verdict && (
            <button className="btn-green btn" style={{ padding: "5px 14px", fontSize: "11px" }} onClick={copyReport}>
              {copied ? "✓ Copied" : "Copy Report"}
            </button>
          )}
          <button
            className="btn"
            style={{ padding: "5px 14px", fontSize: "11px" }}
            onClick={getVerdict}
            disabled={loading || incidents.length === 0}
          >
            {loading ? "Analyzing..." : verdict ? "Regenerate" : "Generate Analysis"}
          </button>
        </div>
      </div>

      {/* Evidence summary */}
      <div style={{
        display: "flex", gap: "16px", flexWrap: "wrap",
        padding: "12px 14px", background: "var(--bg-secondary)",
        border: "1px solid var(--border)", borderRadius: "4px", marginBottom: "16px",
      }}>
        <span style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace", alignSelf: "center" }}>
          <ClipboardList size={10} style={{ display: "inline", marginRight: "4px" }} />
          Evidence
        </span>
        {evidenceStats.map((s) => (
          <div key={s.label} style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
            <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "18px", color: s.value > 0 ? s.color : "var(--green)", lineHeight: 1.1 }}>{s.value}</span>
            <span style={{ fontSize: "9px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase" }}>{s.label}</span>
          </div>
        ))}
      </div>

      {/* Idle */}
      {!verdict && !loading && !error && (
        <div style={{ display: "flex", alignItems: "center", gap: "10px", color: "var(--text-muted)", fontSize: "13px", padding: "8px 0" }}>
          <ChevronRight size={14} />
          <span>Click "Generate Analysis" to produce a structured incident report powered by AI.</span>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "12px 0" }}>
          <div className="spinner" style={{ width: "18px", height: "18px", borderWidth: "2px" }} />
          <span style={{ color: "var(--text-secondary)", fontSize: "13px", fontFamily: "'Share Tech Mono', monospace" }}>
            Analyzing {incidents.length} correlated events...
          </span>
        </div>
      )}

      {/* Error — red because something went wrong */}
      {error && (
        <div style={{ display: "flex", alignItems: "flex-start", gap: "10px", background: "var(--red-bg)", border: "1px solid var(--red-border)", borderRadius: "4px", padding: "12px", marginTop: "4px" }}>
          <AlertCircle size={15} style={{ color: "var(--red)", flexShrink: 0, marginTop: "1px" }} />
          <span style={{ color: "var(--red)", fontSize: "13px", fontFamily: "'Share Tech Mono', monospace" }}>{error}</span>
        </div>
      )}

      {/* Result */}
      {verdict && (
        <div className="animate-in">
          {renderVerdict(verdict)}
        </div>
      )}
    </div>
  );
}