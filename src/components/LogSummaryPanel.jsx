import { useState, useEffect, useRef } from "react";
import { X, Bot, AlertCircle, RefreshCw, Send } from "lucide-react";
import { sanitizePromptInput } from "../utils/sanitize";

// ── Build a rich data context from the raw rows ──────────────────────────────
// Passes representative samples + full statistics so the AI has real data
// without exceeding token limits on large log files.
function buildDataContext(data) {
  const authRows     = Object.entries(data).filter(([k]) => k.includes("auth")).flatMap(([,v]) => v || []);
  const dnsRows      = Object.entries(data).filter(([k]) => k.includes("dns")).flatMap(([,v]) => v || []);
  const firewallRows = Object.entries(data).filter(([k]) => k.includes("firewall")).flatMap(([,v]) => v || []);
  const malwareRows  = Object.entries(data).filter(([k]) => k.includes("malware")).flatMap(([,v]) => v || []);

  // Auth breakdown
  const authFails   = authRows.filter((r) => String(r.action || "").toLowerCase().includes("failed"));
  const authSuccess = authRows.filter((r) => String(r.action || "").toLowerCase().includes("success"));
  const failByIP    = authFails.reduce((acc, r) => { acc[r.source_ip] = (acc[r.source_ip] || 0) + 1; return acc; }, {});
  const topFailIPs  = Object.entries(failByIP).sort((a,b) => b[1]-a[1]).slice(0,10);
  const uniqueUsers = [...new Set(authFails.map((r) => r.user).filter(Boolean))];
  const failTimes   = authFails.map((r) => r.timestamp).filter(Boolean).sort();

  // DNS breakdown
  const BAD = ["bad-actor","phish","c2",".ru",".xyz",".tk",".pw",".onion"];
  const isBad = (d) => { const s = String(d||"").toLowerCase(); return BAD.some((p) => p.startsWith(".") ? s.endsWith(p) : s.split(".").includes(p)); };
  const badDNS      = dnsRows.filter((r) => isBad(r.domain_queried));
  const goodDNS     = dnsRows.filter((r) => !isBad(r.domain_queried));
  const badDomains  = [...new Set(badDNS.map((r) => r.domain_queried))];
  const badClients  = [...new Set(badDNS.map((r) => r.client_ip))];
  const topGoodDomains = Object.entries(
    goodDNS.reduce((acc, r) => { acc[r.domain_queried] = (acc[r.domain_queried]||0)+1; return acc; }, {})
  ).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([d,n])=>`${d}(${n})`).join(", ");

  // Firewall breakdown
  const fwBlocks  = firewallRows.filter((r) => String(r.action||"").toLowerCase() === "block");
  const fwAllows  = firewallRows.filter((r) => String(r.action||"").toLowerCase() === "allow");
  const blockByIP = fwBlocks.reduce((acc,r) => { acc[r.source_ip]=(acc[r.source_ip]||0)+1; return acc; }, {});
  const topBlockedIPs = Object.entries(blockByIP).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([ip,n])=>`${ip}(${n})`).join(", ");
  const blockPorts = [...new Set(fwBlocks.map((r)=>r.destination_port).filter(Boolean))].slice(0,10).join(", ");

  // Malware — include every row since there are very few
  const malwareFull = malwareRows.map((r) =>
    `  - ${r.timestamp||"??"} | host: ${r.hostname||r.host||"unknown"} | threat: ${r.threat_name||r.threat||"unknown"}`
  ).join("\n");

  // Auth sample rows (first + worst-offender window)
  const worstIP     = topFailIPs[0]?.[0];
  const worstSample = worstIP
    ? authFails.filter((r) => r.source_ip === worstIP).slice(0, 5)
        .map((r) => `  ${r.timestamp} | user: ${r.user||"?"} | ip: ${r.source_ip} | ${r.action}`)
        .join("\n")
    : "";

  return `=== LOG DATA (use this as the ground truth for all answers) ===

FILE SUMMARY:
- auth_logs: ${authRows.length} total rows (${authFails.length} failures, ${authSuccess.length} successes)
- dns_logs: ${dnsRows.length} total rows (${badDNS.length} malicious, ${goodDNS.length} clean)
- firewall_logs: ${firewallRows.length} total rows (${fwBlocks.length} blocks, ${fwAllows.length} allows)
- malware_alerts: ${malwareRows.length} total rows

AUTH LOG DETAILS:
Top source IPs by failure count:
${topFailIPs.map(([ip,n])=>`  - ${ip}: ${n} failures`).join("\n") || "  none"}
Targeted users: ${uniqueUsers.slice(0,15).join(", ") || "none"}
Failure window: ${failTimes[0]||"?"} → ${failTimes[failTimes.length-1]||"?"}
${worstSample ? `Sample failures from top offender (${worstIP}):\n${worstSample}` : ""}

DNS LOG DETAILS:
Malicious domains queried: ${badDomains.join(", ") || "none"}
Clients querying malicious domains: ${badClients.join(", ") || "none"}
Top clean domains: ${topGoodDomains || "none"}

FIREWALL LOG DETAILS:
Top blocked source IPs: ${topBlockedIPs || "none"}
Blocked destination ports: ${blockPorts || "none"}

MALWARE ALERTS (all records):
${malwareFull || "  none"}

=== END LOG DATA ===`;
}

const INITIAL_PROMPT = (dataContext) =>
`You are a senior SOC analyst assistant with access to the following live log data.

${dataContext}

Write a concise triage summary using these exact headers:

## What's Happening
2-3 sentences describing the attack activity in plain English, referencing specific IPs, users, or domains from the data.

## Key Indicators
List the most important IOCs (IPs, domains, hostnames, usernames) with brief context.

## Risk Level
One sentence on overall risk and urgency based on what you see in the data.

## Recommended Next Steps
2-3 specific triage actions referencing the actual hosts/IPs involved.

Keep the entire response under 350 words. Be specific — use the actual values from the log data.`;

function renderMessage(text) {
  const sections = text.split(/^##\s+/m).filter(Boolean);
  if (sections.length <= 1) {
    return (
      <p style={{ fontSize: "13px", lineHeight: "1.7", color: "var(--text-primary)", whiteSpace: "pre-wrap", margin: 0 }}>
        {text}
      </p>
    );
  }
  const sectionColors = {
    "what's happening":       "var(--blue)",
    "key indicators":         "var(--yellow)",
    "risk level":             "var(--red)",
    "recommended next steps": "var(--green)",
  };
  return sections.map((section, i) => {
    const [title, ...body] = section.split("\n");
    const content  = body.join("\n").trim();
    const titleKey = title.trim().toLowerCase();
    const color    = sectionColors[titleKey] || "var(--blue)";
    const isGreen  = titleKey.includes("next steps");
    return (
      <div key={i} style={{ marginBottom: i < sections.length - 1 ? "14px" : 0 }}>
        <div style={{
          fontSize: "10px", fontWeight: 700, letterSpacing: "0.15em",
          textTransform: "uppercase", color,
          fontFamily: "'Share Tech Mono', monospace", marginBottom: "6px",
          display: "flex", alignItems: "center", gap: "6px",
        }}>
          <span style={{ display: "inline-block", width: "3px", height: "11px", background: color, borderRadius: "2px" }} />
          {title.trim()}
        </div>
        <div style={{
          fontSize: "13px", lineHeight: "1.7", color: "var(--text-primary)",
          background: isGreen ? "var(--green-bg)" : "var(--bg-secondary)",
          border: `1px solid ${isGreen ? "var(--green-border)" : "var(--border)"}`,
          borderRadius: "4px", padding: "9px 12px", whiteSpace: "pre-wrap",
        }}>
          {content}
        </div>
      </div>
    );
  });
}

export default function LogSummaryPanel({ data, open, onClose }) {
  const [messages, setMessages] = useState([]);
  const [input,    setInput]    = useState("");
  const [thinking, setThinking] = useState(false);
  const [error,    setError]    = useState("");
  const scrollRef = useRef(null);
  const inputRef  = useRef(null);

  // Build context once — regenerated whenever data changes
  const dataContext = buildDataContext(data);

  useEffect(() => {
    if (open && messages.length === 0 && !thinking) runInitialSummary();
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, thinking]);

  async function callAPI(apiMessages) {
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
        max_tokens: 700,
        system: `You are a senior SOC analyst assistant. Answer all questions using only the actual log data provided. Reference specific IPs, users, domains, and timestamps from the data rather than speaking generically.\n\n${dataContext}`,
        messages: apiMessages,
      }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error?.message || `API error ${res.status}`);
    }
    const json = await res.json();
    return json.content[0].text;
  }

  async function runInitialSummary() {
    setThinking(true);
    setError("");
    try {
      const text = await callAPI([{ role: "user", content: INITIAL_PROMPT(dataContext) }]);
      setMessages([{ role: "assistant", text }]);
    } catch (e) {
      setError(e.message || "Failed to contact AI. Check VITE_ANTHROPIC_KEY in .env");
    } finally {
      setThinking(false);
    }
  }

  async function handleSend() {
    const q = sanitizePromptInput(input.trim());
    if (!q || thinking) return;
    setInput("");
    setError("");
    const userMsg    = { role: "user", text: q };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setThinking(true);

    const apiMessages = [
      { role: "user",      content: INITIAL_PROMPT(dataContext) },
      ...newMessages.map((m) => ({ role: m.role === "user" ? "user" : "assistant", content: m.text })),
    ];

    try {
      const text = await callAPI(apiMessages);
      setMessages([...newMessages, { role: "assistant", text }]);
    } catch (e) {
      setError(e.message || "Failed to contact AI. Check VITE_ANTHROPIC_KEY in .env");
      setMessages(newMessages);
    } finally {
      setThinking(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }

  function handleKeyDown(e) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); }
  }

  function handleReset() {
    setMessages([]);
    setError("");
    setInput("");
    setTimeout(() => runInitialSummary(), 50);
  }

  return (
    <>
      {open && (
        <div onClick={onClose} style={{ position: "fixed", inset: 0, background: "rgba(6,9,16,0.45)", zIndex: 200 }} />
      )}

      <div style={{
        position: "fixed", top: 0, right: 0, bottom: 0,
        width: "460px", maxWidth: "92vw",
        background: "var(--bg-card)", borderLeft: "1px solid var(--border-bright)",
        boxShadow: open ? "-8px 0 32px rgba(0,0,0,0.5)" : "none",
        zIndex: 201,
        transform: open ? "translateX(0)" : "translateX(100%)",
        transition: "transform 0.3s cubic-bezier(0.4,0,0.2,1)",
        display: "flex", flexDirection: "column", overflow: "hidden",
      }}>

        {/* Header */}
        <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", justifyContent: "space-between", background: "var(--bg-secondary)", flexShrink: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <Bot size={16} style={{ color: "var(--blue)" }} />
            <div>
              <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--text-primary)", fontFamily: "'Rajdhani', sans-serif", letterSpacing: "0.08em", textTransform: "uppercase" }}>
                AI Log Summary
              </div>
              <div style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace" }}>
                {Object.values(data).reduce((s,a)=>s+(a?.length||0),0).toLocaleString()} log entries loaded
              </div>
            </div>
          </div>
          <div style={{ display: "flex", gap: "6px" }}>
            <button onClick={handleReset} title="Reset"
              style={{ background: "transparent", border: "1px solid var(--border)", borderRadius: "4px", padding: "5px 8px", cursor: "pointer", color: "var(--text-muted)", display: "flex", alignItems: "center", transition: "all 0.15s" }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor="var(--blue)"; e.currentTarget.style.color="var(--blue)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor="var(--border)"; e.currentTarget.style.color="var(--text-muted)"; }}
            ><RefreshCw size={12} /></button>
            <button onClick={onClose}
              style={{ background: "transparent", border: "1px solid var(--border)", borderRadius: "4px", padding: "5px 8px", cursor: "pointer", color: "var(--text-muted)", display: "flex", alignItems: "center", transition: "all 0.15s" }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor="var(--red)"; e.currentTarget.style.color="var(--red)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor="var(--border)"; e.currentTarget.style.color="var(--text-muted)"; }}
            ><X size={13} /></button>
          </div>
        </div>

        {/* Messages */}
        <div ref={scrollRef} style={{ flex: 1, overflowY: "auto", padding: "16px 18px", display: "flex", flexDirection: "column", gap: "16px" }}>
          {thinking && messages.length === 0 && (
            <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "8px 0" }}>
              <div className="spinner" style={{ width: "15px", height: "15px", borderWidth: "2px" }} />
              <span style={{ color: "var(--text-secondary)", fontSize: "13px", fontFamily: "'Share Tech Mono', monospace" }}>Analyzing logs...</span>
            </div>
          )}

          {error && (
            <div style={{ display: "flex", alignItems: "flex-start", gap: "10px", background: "var(--red-bg)", border: "1px solid var(--red-border)", borderRadius: "4px", padding: "10px 12px" }}>
              <AlertCircle size={13} style={{ color: "var(--red)", flexShrink: 0, marginTop: "1px" }} />
              <span style={{ color: "var(--red)", fontSize: "12px", fontFamily: "'Share Tech Mono', monospace" }}>{error}</span>
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={i} style={{ display: "flex", flexDirection: "column", alignItems: msg.role === "user" ? "flex-end" : "flex-start" }}>
              <div style={{ fontSize: "9px", letterSpacing: "0.12em", textTransform: "uppercase", color: msg.role === "user" ? "var(--cyan)" : "var(--blue)", fontFamily: "'Share Tech Mono', monospace", marginBottom: "5px" }}>
                {msg.role === "user" ? "You" : "AI Analyst"}
              </div>
              <div style={{
                maxWidth: "94%",
                background: msg.role === "user" ? "var(--blue-bg)" : "var(--bg-secondary)",
                border: `1px solid ${msg.role === "user" ? "var(--blue-border)" : "var(--border)"}`,
                borderRadius: msg.role === "user" ? "8px 8px 2px 8px" : "8px 8px 8px 2px",
                padding: "12px 14px",
              }}>
                {renderMessage(msg.text)}
              </div>
            </div>
          ))}

          {thinking && messages.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start" }}>
              <div style={{ fontSize: "9px", letterSpacing: "0.12em", textTransform: "uppercase", color: "var(--blue)", fontFamily: "'Share Tech Mono', monospace", marginBottom: "5px" }}>AI Analyst</div>
              <div style={{ background: "var(--bg-secondary)", border: "1px solid var(--border)", borderRadius: "8px 8px 8px 2px", padding: "12px 16px", display: "flex", gap: "5px", alignItems: "center" }}>
                {[0,1,2].map((i) => (
                  <span key={i} style={{ width: "6px", height: "6px", borderRadius: "50%", background: "var(--blue)", display: "inline-block", animation: `pulse 1.2s ease-in-out ${i*0.2}s infinite` }} />
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <div style={{ padding: "12px 16px", borderTop: "1px solid var(--border)", background: "var(--bg-secondary)", flexShrink: 0 }}>
          <div style={{ display: "flex", gap: "8px", alignItems: "flex-end" }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(sanitizePromptInput(e.target.value, 500))}
              onKeyDown={handleKeyDown}
              placeholder="Ask a follow-up question… (Enter to send)"
              rows={2}
              disabled={thinking}
              style={{ flex: 1, background: "var(--bg-card)", border: "1px solid var(--border)", borderRadius: "5px", padding: "9px 12px", color: "var(--text-primary)", fontFamily: "'Rajdhani', sans-serif", fontSize: "13px", lineHeight: 1.5, outline: "none", resize: "none", opacity: thinking ? 0.5 : 1, transition: "border-color 0.15s" }}
              onFocus={(e) => { e.target.style.borderColor = "var(--blue)"; }}
              onBlur={(e)  => { e.target.style.borderColor = "var(--border)"; }}
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || thinking}
              style={{ background: input.trim() && !thinking ? "var(--blue-bg)" : "transparent", border: `1px solid ${input.trim() && !thinking ? "var(--blue)" : "var(--border)"}`, color: input.trim() && !thinking ? "var(--blue)" : "var(--text-muted)", borderRadius: "5px", padding: "10px 12px", cursor: input.trim() && !thinking ? "pointer" : "not-allowed", display: "flex", alignItems: "center", justifyContent: "center", transition: "all 0.15s", flexShrink: 0 }}
            >
              <Send size={14} />
            </button>
          </div>
          <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "6px", fontFamily: "'Share Tech Mono', monospace" }}>
            Shift+Enter for new line · Enter to send
          </div>
        </div>
      </div>
    </>
  );
}