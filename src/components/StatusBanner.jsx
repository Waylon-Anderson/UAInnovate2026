import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";

export default function StatusBanner({ incidents }) {
  const criticalCount = incidents.filter((i) => i.severity === "CRITICAL").length;
  const highCount     = incidents.filter((i) => i.severity === "HIGH").length;

  let state, label, desc, Icon;

  if (criticalCount > 0) {
    state = "threat";
    label = "⚠ ACTIVE THREAT DETECTED";
    desc  = `${criticalCount} critical incident${criticalCount > 1 ? "s" : ""} require immediate attention.`;
    Icon  = ShieldAlert;
  } else if (highCount > 0) {
    state = "warning";
    label = "MONITORING — ELEVATED RISK";
    desc  = `${highCount} high-severity event${highCount > 1 ? "s" : ""} detected. Continued monitoring recommended.`;
    Icon  = ShieldQuestion;
  } else {
    state = "clear";
    label = "ALL CLEAR";
    desc  = "No critical or high-severity incidents detected across all log sources.";
    Icon  = ShieldCheck;
  }

  return (
    <div className={`status-banner ${state}`}>
      <Icon
        size={28}
        style={{
          color: state === "threat" ? "var(--red)" : state === "warning" ? "var(--yellow)" : "var(--green)",
          flexShrink: 0,
        }}
      />
      <div>
        <div className="status-label">{label}</div>
        <div className="status-desc">{desc}</div>
      </div>
    </div>
  );
}
