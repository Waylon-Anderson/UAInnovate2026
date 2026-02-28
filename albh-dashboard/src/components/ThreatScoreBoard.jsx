import { useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Target } from "lucide-react";

// RED >= 70 (bad), YELLOW >= 40 (concern), GREEN < 15 (ok)
function scoreColor(score) {
  if (score >= 70) return "var(--red)";
  if (score >= 40) return "var(--yellow)";
  if (score >= 15) return "var(--yellow)";
  return "var(--green)";
}

function scoreBadge(score) {
  if (score >= 70) return { label: "CRITICAL", cls: "badge-critical" };
  if (score >= 40) return { label: "HIGH",     cls: "badge-high" };
  if (score >= 15) return { label: "MEDIUM",   cls: "badge-medium" };
  return           { label: "LOW",      cls: "badge-low" };
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div style={{ background: "var(--bg-card)", border: "1px solid var(--border-bright)", borderRadius: "4px", padding: "10px 14px", fontSize: "12px", fontFamily: "'Share Tech Mono', monospace" }}>
      <p style={{ color: "var(--blue)", marginBottom: "4px" }}>{d.ip}</p>
      <p style={{ color: scoreColor(d.score) }}>Threat Score: {d.score}</p>
    </div>
  );
};

export default function ThreatScoreboard({ ipScores }) {
  const rows = useMemo(() =>
    Object.entries(ipScores)
      .map(([ip, score]) => ({ ip, score }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 8),
  [ipScores]);

  return (
    <div className="card">
      <div className="card-title">
        <Target size={14} />
        Threat Scoreboard
      </div>

      <ResponsiveContainer width="100%" height={110}>
        <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 60 }}>
          <XAxis type="number" hide domain={[0, 100]} />
          <YAxis
            type="category" dataKey="ip"
            tick={{ fill: "var(--text-secondary)", fontSize: 10, fontFamily: "'Share Tech Mono', monospace" }}
            tickLine={false} axisLine={false} width={60}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
          <Bar dataKey="score" radius={[0, 3, 3, 0]} barSize={9}>
            {rows.map((r, i) => (
              <Cell key={i} fill={scoreColor(r.score)} opacity={0.85} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      <div style={{ marginTop: "12px", display: "flex", flexDirection: "column", gap: "6px" }}>
        {rows.length === 0 && (
          <p style={{ color: "var(--text-muted)", fontSize: "13px" }}>No scored IPs.</p>
        )}
        {rows.map((r, i) => {
          const { label, cls } = scoreBadge(r.score);
          return (
            <div
              key={r.ip}
              className="animate-in"
              style={{
                animationDelay: `${i * 50}ms`,
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "6px 10px", background: "var(--bg-secondary)", borderRadius: "4px",
                border: `1px solid ${i === 0 && r.score >= 70 ? "var(--red-border)" : "var(--border)"}`,
              }}
            >
              <span className="mono" style={{ fontSize: "12px", color: i === 0 && r.score >= 70 ? "var(--red)" : "var(--text-primary)" }}>
                {r.ip}
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span className={`badge ${cls}`}>{label}</span>
                <span className="mono" style={{ fontSize: "13px", fontWeight: 700, color: scoreColor(r.score), minWidth: "28px", textAlign: "right" }}>
                  {r.score}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}