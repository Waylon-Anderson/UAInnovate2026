import { useState, useEffect } from "react";
import {
  ClipboardList, CheckCircle, XCircle, AlertCircle,
  ArrowUpCircle, ChevronDown, ChevronUp, Clock,
  User, Tag, FileText, Lock, Unlock, Filter
} from "lucide-react";
import { relativeTime, formatTimestamp } from "../utils/formatTime";

// ── Verdict definitions ──────────────────────────────────────────────────────
const VERDICTS = [
  {
    id:    "true_positive",
    label: "True Positive",
    desc:  "Confirmed malicious activity. Immediate action required.",
    icon:  XCircle,
    color: "var(--red)",
    bg:    "var(--red-bg)",
    border:"var(--red-border)",
    badge: "badge-critical",
  },
  {
    id:    "false_positive",
    label: "False Positive",
    desc:  "Not malicious. Alert was triggered incorrectly.",
    icon:  CheckCircle,
    color: "var(--green)",
    bg:    "var(--green-bg)",
    border:"var(--green-border)",
    badge: "badge-low",
  },
  {
    id:    "benign_positive",
    label: "Benign Positive",
    desc:  "Expected behavior. Alert is valid but not a threat.",
    icon:  AlertCircle,
    color: "var(--yellow)",
    bg:    "var(--yellow-bg)",
    border:"var(--yellow-border)",
    badge: "badge-medium",
  },
  {
    id:    "escalate",
    label: "Escalate",
    desc:  "Requires senior analyst or IR team involvement.",
    icon:  ArrowUpCircle,
    color: "var(--blue)",
    bg:    "var(--blue-bg)",
    border:"var(--blue-border)",
    badge: "badge-info",
  },
];

const STORAGE_KEY = "soar_cases";

function loadCases() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
  } catch {
    return {};
  }
}

function saveCases(cases) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
  } catch {
    console.warn("Could not persist cases to localStorage.");
  }
}

function incidentId(inc) {
  return `${inc.type}__${inc.ip}__${inc.detail}`.replace(/\s+/g, "_");
}

// ── Severity badge helper ────────────────────────────────────────────────────
function severityColor(s) {
  return s === "CRITICAL" ? "var(--red)"
       : s === "HIGH"     ? "var(--yellow)"
       : s === "MEDIUM"   ? "var(--yellow)"
       :                    "var(--green)";
}

// ── Single Alert Row ─────────────────────────────────────────────────────────
function AlertRow({ inc, caseData, onOpen }) {
  const id      = incidentId(inc);
  const verdict = VERDICTS.find((v) => v.id === caseData?.verdict);
  const isWorked = !!caseData?.verdict;
  const isClaimed = !!caseData?.claimedAt;

  return (
    <div
      onClick={() => onOpen(inc)}
      style={{
        background:  "var(--bg-secondary)",
        border:      `1px solid ${verdict ? verdict.border : isWorked ? "var(--border)" : "var(--border)"}`,
        borderLeft:  `3px solid ${verdict ? verdict.color : isClaimed ? "var(--yellow)" : severityColor(inc.severity)}`,
        borderRadius:"4px",
        padding:     "12px 14px",
        cursor:      "pointer",
        transition:  "background 0.15s, border-color 0.15s",
        display:     "flex",
        alignItems:  "center",
        gap:         "12px",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-card-hover)")}
      onMouseLeave={(e) => (e.currentTarget.style.background = "var(--bg-secondary)")}
    >
      {/* Severity dot */}
      <div style={{
        width: "8px", height: "8px", borderRadius: "50%", flexShrink: 0,
        background: verdict ? verdict.color : severityColor(inc.severity),
        boxShadow: `0 0 6px ${verdict ? verdict.color : severityColor(inc.severity)}`,
      }} />

      {/* Main content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "3px", flexWrap: "wrap" }}>
          <span style={{ fontWeight: 700, fontSize: "13px" }}>{inc.type}</span>
          <span className={`badge badge-${inc.severity.toLowerCase() === "critical" ? "critical" : inc.severity.toLowerCase() === "high" ? "high" : "medium"}`}>
            {inc.severity}
          </span>
          {verdict && <span className={`badge ${verdict.badge}`}>{verdict.label}</span>}
          {!verdict && isClaimed && <span className="badge badge-info">IN PROGRESS</span>}
          {!verdict && !isClaimed && <span className="badge" style={{ background: "var(--bg-card)", color: "var(--text-muted)", border: "1px solid var(--border)" }}>OPEN</span>}
        </div>
        <div className="mono" style={{ fontSize: "11px", color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {inc.ip} — {inc.detail}
        </div>
      </div>

      {/* Right meta */}
      <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "3px", flexShrink: 0 }}>
        <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace" }}>
          {relativeTime(inc.timestamp)}
        </span>
        {caseData?.analyst && (
          <span style={{ fontSize: "10px", color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: "3px" }}>
            <User size={9} /> {caseData.analyst}
          </span>
        )}
      </div>
    </div>
  );
}

// ── Case Detail Modal ────────────────────────────────────────────────────────
function CaseModal({ inc, caseData, onSave, onClose }) {
  const id = incidentId(inc);

  const [analyst,     setAnalyst]     = useState(caseData?.analyst     || "");
  const [verdict,     setVerdict]     = useState(caseData?.verdict     || "");
  const [notes,       setNotes]       = useState(caseData?.notes       || "");
  const [description, setDescription] = useState(caseData?.description || "");
  const [tags,        setTags]        = useState(caseData?.tags        || []);
  const [tagInput,    setTagInput]    = useState("");
  const [activePane,  setActivePane]  = useState("work");
  const [claimed,     setClaimed]     = useState(!!caseData?.claimedAt);
  const [nameTouched, setNameTouched] = useState(false);

  const selectedVerdict = VERDICTS.find((v) => v.id === verdict);
  const isLocked = !analyst.trim();

  function addAuditEntry(existing, action) {
    const log = existing || [];
    return [...log, { ts: new Date().toISOString(), analyst: analyst.trim(), action }];
  }

  function handleClaim() {
    if (isLocked) return;
    setClaimed(true);
    const auditLog = addAuditEntry(caseData?.auditLog, "Claimed alert");
    onSave(id, {
      ...caseData,
      analyst,
      claimedAt: caseData?.claimedAt || new Date().toISOString(),
      auditLog,
    });
  }

  function handleSave() {
    if (isLocked) { setNameTouched(true); return; }
    const prevVerdict = caseData?.verdict;
    const actions = [];
    if (!caseData?.claimedAt && !claimed) actions.push("Saved progress");
    if (verdict && verdict !== prevVerdict) actions.push(`Verdict set to ${VERDICTS.find((v) => v.id === verdict)?.label}`);
    if (notes !== (caseData?.notes || "")) actions.push("Updated analyst notes");
    if (description !== (caseData?.description || "")) actions.push("Updated description");
    if (JSON.stringify(tags) !== JSON.stringify(caseData?.tags || [])) actions.push("Updated tags");

    let auditLog = caseData?.auditLog || [];
    actions.forEach((a) => { auditLog = addAuditEntry(auditLog, a); });
    if (auditLog.length === 0) auditLog = addAuditEntry(auditLog, "Saved progress");

    onSave(id, {
      analyst,
      verdict,
      notes,
      description,
      tags,
      claimedAt: caseData?.claimedAt || (claimed ? new Date().toISOString() : null),
      closedAt:  verdict ? new Date().toISOString() : null,
      auditLog,
    });
    onClose();
  }

  function addTag(e) {
    if (isLocked) return;
    if ((e.key === "Enter" || e.key === ",") && tagInput.trim()) {
      e.preventDefault();
      const t = tagInput.trim().replace(/,+$/, "");
      if (t && !tags.includes(t)) setTags([...tags, t]);
      setTagInput("");
    }
  }

  function removeTag(t) {
    if (isLocked) return;
    setTags(tags.filter((x) => x !== t));
  }

  const nameError = nameTouched && isLocked;

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(6,9,16,0.85)",
      zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center",
      padding: "20px",
    }} onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{
        background: "var(--bg-card)", border: "1px solid var(--border-bright)",
        borderRadius: "8px", width: "100%", maxWidth: "680px",
        maxHeight: "90vh", overflow: "hidden", display: "flex", flexDirection: "column",
        boxShadow: "0 24px 80px rgba(0,0,0,0.6)",
      }}>
        {/* Modal header */}
        <div style={{
          padding: "16px 20px", borderBottom: "1px solid var(--border)",
          display: "flex", alignItems: "center", gap: "12px",
        }}>
          <div style={{
            width: "10px", height: "10px", borderRadius: "50%", flexShrink: 0,
            background: severityColor(inc.severity),
            boxShadow: `0 0 8px ${severityColor(inc.severity)}`,
          }} />
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 700, fontSize: "15px" }}>{inc.type}</div>
            <div className="mono" style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
              {inc.ip} — {inc.detail}
            </div>
          </div>
          <span className={`badge badge-${inc.severity === "CRITICAL" ? "critical" : inc.severity === "HIGH" ? "high" : "medium"}`}>
            {inc.severity}
          </span>
          <button onClick={onClose} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", fontSize: "18px", lineHeight: 1 }}>✕</button>
        </div>

        {/* Pane tabs */}
        <div style={{ display: "flex", borderBottom: "1px solid var(--border)", background: "var(--bg-secondary)" }}>
          {[["work", "Work Alert", ClipboardList], ["description", "Description", FileText], ["activity", "Activity Log", Clock]].map(([pane, label, Icon]) => (
            <button key={pane} onClick={() => setActivePane(pane)}
              style={{
                background: "transparent", border: "none",
                borderBottom: `2px solid ${activePane === pane ? "var(--blue)" : "transparent"}`,
                color: activePane === pane ? "var(--blue)" : "var(--text-secondary)",
                padding: "10px 18px", fontSize: "12px", fontFamily: "'Rajdhani', sans-serif",
                fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase",
                cursor: "pointer", display: "flex", alignItems: "center", gap: "6px",
                transition: "all 0.15s", marginBottom: "-1px",
              }}
            >
              <Icon size={12} /> {label}
            </button>
          ))}
        </div>

        {/* Scrollable body */}
        <div style={{ overflowY: "auto", padding: "20px", flex: 1, display: "flex", flexDirection: "column", gap: "16px" }}>

          {/* ── WORK ALERT PANE ── */}
          {activePane === "work" && (
            <>
              {/* Alert metadata */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                {[
                  ["Incident Type", inc.type],
                  ["Severity",      inc.severity],
                  ["Source IP",     inc.ip],
                  ["Detail",        inc.detail],
                  ["First Seen",    formatTimestamp(inc.timestamp)],
                  ["Case ID",       id.slice(0, 20) + "..."],
                ].map(([label, value]) => (
                  <div key={label} style={{ background: "var(--bg-secondary)", borderRadius: "4px", padding: "8px 12px", border: "1px solid var(--border)" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "3px" }}>{label}</div>
                    <div className="mono" style={{ fontSize: "12px", color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{value}</div>
                  </div>
                ))}
              </div>

              {/* Claim / Analyst */}
              <div>
                <label style={{ fontSize: "10px", color: nameError ? "var(--red)" : "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: "6px" }}>
                  <User size={10} style={{ display: "inline", marginRight: "4px" }} />
                  Analyst Name {isLocked && <span style={{ color: "var(--red)" }}>*required to make changes</span>}
                </label>
                <div style={{ display: "flex", gap: "8px" }}>
                  <input
                    value={analyst}
                    onChange={(e) => { setAnalyst(e.target.value); setNameTouched(true); }}
                    placeholder="Enter your name to begin working this alert..."
                    style={{
                      flex: 1, background: "var(--bg-secondary)",
                      border: `1px solid ${nameError ? "var(--red-border)" : "var(--border)"}`,
                      borderRadius: "4px", padding: "8px 12px", color: "var(--text-primary)",
                      fontFamily: "'Rajdhani', sans-serif", fontSize: "13px", outline: "none",
                      boxShadow: nameError ? "0 0 0 2px var(--red-bg)" : "none",
                    }}
                    onFocus={(e) => (e.target.style.borderColor = "var(--blue)")}
                    onBlur={(e)  => { setNameTouched(true); e.target.style.borderColor = nameError ? "var(--red-border)" : "var(--border)"; }}
                  />
                  {!claimed && (
                    <button
                      className="btn"
                      style={{ padding: "8px 14px", fontSize: "11px", whiteSpace: "nowrap" }}
                      onClick={handleClaim}
                      disabled={isLocked}
                      title={isLocked ? "Enter your name first" : "Claim this alert"}
                    >
                      <Lock size={11} style={{ display: "inline", marginRight: "4px" }} />
                      Claim Alert
                    </button>
                  )}
                  {claimed && (
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "var(--green)", fontSize: "12px", fontFamily: "'Share Tech Mono', monospace", whiteSpace: "nowrap" }}>
                      <Lock size={12} /> Claimed
                    </div>
                  )}
                </div>
                {nameError && (
                  <p style={{ fontSize: "11px", color: "var(--red)", marginTop: "5px", fontFamily: "'Share Tech Mono', monospace" }}>
                    ⚠ You must enter your name before working this alert.
                  </p>
                )}
              </div>

              {/* Locked overlay message when no name entered */}
              {isLocked && nameTouched && (
                <div style={{
                  background: "rgba(255,59,92,0.06)", border: "1px solid var(--red-border)",
                  borderRadius: "4px", padding: "10px 14px",
                  display: "flex", alignItems: "center", gap: "10px",
                }}>
                  <Lock size={13} style={{ color: "var(--red)", flexShrink: 0 }} />
                  <span style={{ fontSize: "12px", color: "var(--red)", fontFamily: "'Share Tech Mono', monospace" }}>
                    Verdict, tags, and notes are locked until an analyst name is provided.
                  </span>
                </div>
              )}

              {/* Verdict selection */}
              <div style={{ opacity: isLocked ? 0.35 : 1, pointerEvents: isLocked ? "none" : "auto", transition: "opacity 0.2s" }}>
                <label style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: "8px" }}>
                  Verdict
                </label>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                  {VERDICTS.map((v) => {
                    const Icon      = v.icon;
                    const isSelected = verdict === v.id;
                    return (
                      <button key={v.id} onClick={() => setVerdict(isSelected ? "" : v.id)}
                        style={{
                          background:  isSelected ? v.bg : "var(--bg-secondary)",
                          border:      `1px solid ${isSelected ? v.color : "var(--border)"}`,
                          borderRadius:"4px", padding: "10px 12px", cursor: "pointer",
                          display: "flex", alignItems: "flex-start", gap: "10px",
                          transition: "all 0.15s", textAlign: "left",
                          boxShadow: isSelected ? `0 0 12px ${v.bg}` : "none",
                        }}
                      >
                        <Icon size={16} style={{ color: v.color, flexShrink: 0, marginTop: "1px" }} />
                        <div>
                          <div style={{ fontSize: "12px", fontWeight: 700, color: isSelected ? v.color : "var(--text-primary)", fontFamily: "'Rajdhani', sans-serif", letterSpacing: "0.04em" }}>
                            {v.label}
                          </div>
                          <div style={{ fontSize: "10px", color: "var(--text-secondary)", marginTop: "2px", lineHeight: 1.4 }}>
                            {v.desc}
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Tags + Notes locked without analyst name */}
              <div style={{ opacity: isLocked ? 0.35 : 1, pointerEvents: isLocked ? "none" : "auto", transition: "opacity 0.2s" }}>

              {/* Tags */}
              <div style={{ marginBottom: "16px" }}>
                <label style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: "6px" }}>
                  <Tag size={10} style={{ display: "inline", marginRight: "4px" }} />
                  Tags (press Enter to add)
                </label>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "8px" }}>
                  {tags.map((t) => (
                    <span key={t} style={{
                      background: "var(--blue-bg)", border: "1px solid var(--blue-border)",
                      color: "var(--blue)", borderRadius: "3px", padding: "2px 8px",
                      fontSize: "11px", fontFamily: "'Share Tech Mono', monospace",
                      display: "flex", alignItems: "center", gap: "5px",
                    }}>
                      {t}
                      <span onClick={() => removeTag(t)} style={{ cursor: "pointer", opacity: 0.6, lineHeight: 1 }}>✕</span>
                    </span>
                  ))}
                </div>
                <input
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyDown={addTag}
                  placeholder="e.g. brute-force, external-ip, reviewed..."
                  style={{
                    width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border)",
                    borderRadius: "4px", padding: "8px 12px", color: "var(--text-primary)",
                    fontFamily: "'Share Tech Mono', monospace", fontSize: "12px", outline: "none",
                  }}
                  onFocus={(e) => (e.target.style.borderColor = "var(--blue)")}
                  onBlur={(e)  => (e.target.style.borderColor = "var(--border)")}
                />
              </div>{/* end tags div */}

              {/* Analyst notes */}
              <div>
                <label style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: "6px" }}>
                  Analyst Notes
                </label>
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Document your investigation steps, findings, and reasoning..."
                  rows={5}
                  style={{
                    width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border)",
                    borderRadius: "4px", padding: "10px 12px", color: "var(--text-primary)",
                    fontFamily: "'Rajdhani', sans-serif", fontSize: "13px", lineHeight: 1.6,
                    outline: "none", resize: "vertical",
                  }}
                  onFocus={(e) => (e.target.style.borderColor = "var(--blue)")}
                  onBlur={(e)  => (e.target.style.borderColor = "var(--border)")}
                />
              </div>
              </div>{/* end locked wrapper */}
            </>
          )}

          {/* ── DESCRIPTION PANE ── */}
          {activePane === "description" && (
            <>
              <div style={{ background: "var(--bg-secondary)", border: "1px solid var(--border)", borderRadius: "4px", padding: "12px 14px" }}>
                <p style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: 1.6 }}>
                  Use this pane to document a full description of the alert — what it means, why it fired, relevant context, and any supporting evidence. This persists with the case and is visible to other analysts.
                </p>
              </div>
              <div>
                <label style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", display: "block", marginBottom: "6px" }}>
                  <FileText size={10} style={{ display: "inline", marginRight: "4px" }} />
                  Alert Description
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder={`Describe this alert in full detail.\n\nExample:\n- Why did this alert fire?\n- What systems or users are affected?\n- What is the potential impact?\n- What evidence supports or refutes this being a real threat?\n- Are there related alerts or prior incidents?`}
                  rows={14}
                  style={{
                    width: "100%", background: "var(--bg-secondary)", border: "1px solid var(--border)",
                    borderRadius: "4px", padding: "12px 14px", color: "var(--text-primary)",
                    fontFamily: "'Rajdhani', sans-serif", fontSize: "13px", lineHeight: 1.7,
                    outline: "none", resize: "vertical",
                  }}
                  onFocus={(e) => (e.target.style.borderColor = "var(--blue)")}
                  onBlur={(e)  => (e.target.style.borderColor = "var(--border)")}
                />
              </div>
            </>
          )}

          {/* ── ACTIVITY LOG PANE ── */}
          {activePane === "activity" && (
            <>
              <div style={{ background: "var(--bg-secondary)", border: "1px solid var(--border)", borderRadius: "4px", padding: "10px 14px", marginBottom: "4px" }}>
                <p style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                  Full chain of custody for this alert. Every action is timestamped and attributed.
                </p>
              </div>
              {(!caseData?.auditLog || caseData.auditLog.length === 0) ? (
                <div style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)", fontSize: "13px", fontFamily: "'Share Tech Mono', monospace" }}>
                  No activity yet. Claim or save this alert to begin the log.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "0" }}>
                  {[...caseData.auditLog].reverse().map((entry, i) => (
                    <div key={i} style={{
                      display: "flex", gap: "12px", padding: "10px 0",
                      borderBottom: i < caseData.auditLog.length - 1 ? "1px solid var(--border)" : "none",
                    }}>
                      {/* Timeline dot */}
                      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flexShrink: 0, paddingTop: "3px" }}>
                        <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "var(--blue)", flexShrink: 0 }} />
                        {i < caseData.auditLog.length - 1 && (
                          <div style={{ width: "1px", flex: 1, background: "var(--border)", marginTop: "4px" }} />
                        )}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: "13px", color: "var(--text-primary)", marginBottom: "2px" }}>
                          {entry.action}
                        </div>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace", display: "flex", gap: "10px" }}>
                          <span>{formatTimestamp(entry.ts)}</span>
                          {entry.analyst && <span style={{ color: "var(--blue)" }}>by {entry.analyst}</span>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal footer */}
        <div style={{
          padding: "14px 20px", borderTop: "1px solid var(--border)",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          background: "var(--bg-secondary)", gap: "10px", flexWrap: "wrap",
        }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace" }}>
            {caseData?.closedAt
              ? `Closed: ${relativeTime(caseData.closedAt)}`
              : caseData?.claimedAt
              ? `Claimed: ${relativeTime(caseData.claimedAt)}`
              : "Unclaimed"}
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button className="btn" style={{ padding: "7px 16px", fontSize: "12px", borderColor: "var(--border)", color: "var(--text-secondary)" }} onClick={onClose}>
              Cancel
            </button>
            <button
              className={`btn ${selectedVerdict ? "btn-" + (selectedVerdict.id === "true_positive" ? "red" : selectedVerdict.id === "false_positive" ? "green" : "") : ""}`}
              style={{
                padding: "7px 20px", fontSize: "12px",
                ...(isLocked ? { opacity: 0.5, cursor: "not-allowed", borderColor: "var(--border)", color: "var(--text-muted)" } : {}),
                ...(selectedVerdict && !isLocked && !["true_positive","false_positive"].includes(selectedVerdict.id) ? {
                  borderColor: selectedVerdict.color, color: selectedVerdict.color,
                } : {}),
              }}
              onClick={() => { setNameTouched(true); handleSave(); }}
              title={isLocked ? "Enter your analyst name first" : ""}
            >
              {isLocked ? "⚠ Name Required" : verdict ? `Close as ${VERDICTS.find((v) => v.id === verdict)?.label}` : "Save Progress"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main SOAR Workbench ──────────────────────────────────────────────────────
export default function SOARWorkbench({ incidents, cases, onSaveCase }) {
  const [openInc,        setOpenInc]        = useState(null);
  const [filterState,    setFilterState]    = useState("all");
  const [filterVerdict,  setFilterVerdict]  = useState("all");
  const [filterSeverity, setFilterSeverity] = useState("all");

  function saveCase(id, caseData) {
    onSaveCase(id, caseData);
  }

  function getState(inc) {
    const c = cases[incidentId(inc)];
    if (!c) return "open";
    if (c.verdict) return "closed";
    if (c.claimedAt) return "in_progress";
    return "open";
  }

  const filtered = incidents.filter((inc) => {
    const state    = getState(inc);
    const c        = cases[incidentId(inc)];
    const verdict  = c?.verdict || "none";
    const stateMatch    = filterState    === "all" || filterState    === state;
    const verdictMatch  = filterVerdict  === "all" || filterVerdict  === verdict;
    const severityMatch = filterSeverity === "all" || inc.severity   === filterSeverity;
    return stateMatch && verdictMatch && severityMatch;
  });

  const counts = {
    open:        incidents.filter((i) => getState(i) === "open").length,
    in_progress: incidents.filter((i) => getState(i) === "in_progress").length,
    closed:      incidents.filter((i) => getState(i) === "closed").length,
  };

  const severityCounts = ["CRITICAL","HIGH","MEDIUM","LOW"].reduce((acc, s) => {
    acc[s] = incidents.filter((i) => i.severity === s).length;
    return acc;
  }, {});

  const verdictCounts = VERDICTS.reduce((acc, v) => {
    acc[v.id] = incidents.filter((i) => cases[incidentId(i)]?.verdict === v.id).length;
    return acc;
  }, {});

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

      {/* ── Header stats ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "10px" }}>
        {[
          { label: "Open",        value: counts.open,        color: "var(--red)" },
          { label: "In Progress", value: counts.in_progress, color: "var(--yellow)" },
          { label: "Closed",      value: counts.closed,      color: "var(--green)" },
          { label: "Total",       value: incidents.length,   color: "var(--blue)" },
        ].map(({ label, value, color }) => (
          <div key={label} className="card" style={{ padding: "14px 16px", textAlign: "center" }}>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: "26px", color, lineHeight: 1 }}>{value}</div>
            <div style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", marginTop: "4px" }}>{label}</div>
          </div>
        ))}
      </div>

      {/* ── Filters ── */}
      <div className="card" style={{ padding: "12px 16px" }}>
        <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.1em", textTransform: "uppercase", fontFamily: "'Share Tech Mono', monospace", display: "flex", alignItems: "center", gap: "5px" }}>
            <Filter size={10} /> Filter
          </span>

          {/* State filters */}
          <div style={{ display: "flex", gap: "5px" }}>
            {[["all","All"], ["open","Open"], ["in_progress","In Progress"], ["closed","Closed"]].map(([val, label]) => (
              <button key={val} onClick={() => setFilterState(val)}
                style={{
                  background: filterState === val ? "var(--blue-bg)" : "transparent",
                  border: `1px solid ${filterState === val ? "var(--blue)" : "var(--border)"}`,
                  color: filterState === val ? "var(--blue)" : "var(--text-muted)",
                  borderRadius: "3px", padding: "4px 10px", fontSize: "11px",
                  fontFamily: "'Rajdhani', sans-serif", fontWeight: 600,
                  letterSpacing: "0.06em", textTransform: "uppercase", cursor: "pointer",
                  transition: "all 0.15s",
                }}
              >{label}{val !== "all" ? ` (${counts[val] ?? 0})` : ""}</button>
            ))}
          </div>

          <div style={{ width: "1px", height: "20px", background: "var(--border)" }} />

          {/* Verdict filters */}
          <div style={{ display: "flex", gap: "5px", flexWrap: "wrap" }}>
            <button onClick={() => setFilterVerdict("all")}
              style={{
                background: filterVerdict === "all" ? "var(--blue-bg)" : "transparent",
                border: `1px solid ${filterVerdict === "all" ? "var(--blue)" : "var(--border)"}`,
                color: filterVerdict === "all" ? "var(--blue)" : "var(--text-muted)",
                borderRadius: "3px", padding: "4px 10px", fontSize: "11px",
                fontFamily: "'Rajdhani', sans-serif", fontWeight: 600,
                letterSpacing: "0.06em", textTransform: "uppercase", cursor: "pointer",
              }}
            >All Verdicts</button>
            {VERDICTS.map((v) => (
              <button key={v.id} onClick={() => setFilterVerdict(filterVerdict === v.id ? "all" : v.id)}
                style={{
                  background: filterVerdict === v.id ? v.bg : "transparent",
                  border: `1px solid ${filterVerdict === v.id ? v.color : "var(--border)"}`,
                  color: filterVerdict === v.id ? v.color : "var(--text-muted)",
                  borderRadius: "3px", padding: "4px 10px", fontSize: "11px",
                  fontFamily: "'Rajdhani', sans-serif", fontWeight: 600,
                  letterSpacing: "0.06em", textTransform: "uppercase", cursor: "pointer",
                  transition: "all 0.15s",
                }}
              >{v.label}{verdictCounts[v.id] > 0 ? ` (${verdictCounts[v.id]})` : ""}</button>
            ))}
          </div>

          <div style={{ width: "1px", height: "20px", background: "var(--border)" }} />

          {/* Severity filters */}
          <div style={{ display: "flex", gap: "5px", flexWrap: "wrap" }}>
            {[
              ["all",      "All",      "var(--blue)",   "var(--blue)"],
              ["CRITICAL", "Critical", "var(--red)",    "var(--red-bg)"],
              ["HIGH",     "High",     "var(--yellow)", "var(--yellow-bg)"],
              ["MEDIUM",   "Medium",   "var(--yellow)", "var(--yellow-bg)"],
              ["LOW",      "Low",      "var(--green)",  "var(--green-bg)"],
            ].map(([val, label, color, bg]) => (
              <button key={val} onClick={() => setFilterSeverity(val)}
                style={{
                  background: filterSeverity === val ? bg : "transparent",
                  border: `1px solid ${filterSeverity === val ? color : "var(--border)"}`,
                  color: filterSeverity === val ? color : "var(--text-muted)",
                  borderRadius: "3px", padding: "4px 10px", fontSize: "11px",
                  fontFamily: "'Rajdhani', sans-serif", fontWeight: 600,
                  letterSpacing: "0.06em", textTransform: "uppercase", cursor: "pointer",
                  transition: "all 0.15s",
                }}
              >
                {label}{val !== "all" && severityCounts[val] > 0 ? ` (${severityCounts[val]})` : ""}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ── Alert queue ── */}
      <div className="card">
        <div className="card-title">
          <ClipboardList size={14} />
          Alert Queue
          <span style={{ marginLeft: "auto", fontSize: "11px", color: "var(--text-muted)", fontFamily: "'Share Tech Mono', monospace" }}>
            {filtered.length} alert{filtered.length !== 1 ? "s" : ""}
          </span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          {filtered.length === 0 && (
            <div style={{ padding: "24px", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>
              No alerts match the current filter.
            </div>
          )}
          {filtered.map((inc, i) => (
            <AlertRow
              key={i}
              inc={inc}
              caseData={cases[incidentId(inc)]}
              onOpen={setOpenInc}
            />
          ))}
        </div>
      </div>

      {/* ── Case modal ── */}
      {openInc && (
        <CaseModal
          inc={openInc}
          caseData={cases[incidentId(openInc)]}
          onSave={saveCase}
          onClose={() => setOpenInc(null)}
        />
      )}
    </div>
  );
}