import { useMemo } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, ReferenceLine, ReferenceDot,
} from "recharts";
import { Activity } from "lucide-react";
import { formatTimestamp } from "../utils/formatTime";

function bucketByMinute(rows, actionFilter) {
  const counts = {};
  rows.forEach((r) => {
    const action = String(r.action || "").toLowerCase();
    const filter = actionFilter ? actionFilter.toLowerCase() : "";
    if (actionFilter && !action.includes(filter)) return;
    const ts = r.timestamp?.slice(0, 16);
    if (!ts) return;
    counts[ts] = (counts[ts] || 0) + 1;
  });
  return counts;
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: "var(--bg-card)", border: "1px solid var(--border-bright)",
      borderRadius: "4px", padding: "10px 14px",
      fontSize: "12px", fontFamily: "'Share Tech Mono', monospace",
    }}>
      <p style={{ color: "var(--text-secondary)", marginBottom: "6px" }}>{label}</p>
      {payload.map((p) => (
        <p key={p.name} style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  );
};

export default function TimelineChart({ data }) {
  const chartData = useMemo(() => {
    const authFails   = bucketByMinute(data.auth_logs    || [], "Failed");
    const authSuccess = bucketByMinute(data.auth_logs    || [], "Success");
    const fwBlocks    = bucketByMinute(data.firewall_logs || [], "Block");
    const allTimes = new Set([
      ...Object.keys(authFails),
      ...Object.keys(authSuccess),
      ...Object.keys(fwBlocks),
    ]);
    return [...allTimes].sort().map((ts) => {
      const d   = new Date(ts);
      const mm  = String(d.getMonth() + 1).padStart(2, "0");
      const dd  = String(d.getDate()).padStart(2, "0");
      const hh  = String(d.getHours()).padStart(2, "0");
      const min = String(d.getMinutes()).padStart(2, "0");
      return {
        time:               `${mm}/${dd} ${hh}:${min}`,
        fullTs:             ts,
        "Auth Failures":    authFails[ts]   || 0,
        "Auth Success":     authSuccess[ts] || 0,
        "Firewall Blocks":  fwBlocks[ts]    || 0,
      };
    });
  }, [data]);

  const anomaly = useMemo(() => {
    if (!chartData.length) return null;
    const peak = [...chartData].sort((a, b) => b["Auth Failures"] - a["Auth Failures"])[0];
    if (!peak || peak["Auth Failures"] < 5) return null;
    return peak;
  }, [chartData]);

  return (
    <div className="card col-span-2">
      <div className="card-title">
        <Activity size={14} />
        Event Timeline
        {anomaly && (
          <span className="badge badge-critical" style={{ marginLeft: "auto" }}>
            Spike: {anomaly["Auth Failures"]} failures at {anomaly.time}
          </span>
        )}
      </div>
      <ResponsiveContainer width="100%" height={230}>
        <LineChart data={chartData} margin={{ top: 8, right: 8, bottom: 0, left: 10 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
          <XAxis
            dataKey="time"
            tick={{ fill: "var(--text-muted)", fontSize: 10, fontFamily: "'Share Tech Mono', monospace" }}
            tickLine={false}
            axisLine={{ stroke: "var(--border)" }}
            interval="preserveStartEnd"
          />
          <YAxis
            tick={{ fill: "var(--text-muted)", fontSize: 10, fontFamily: "'Share Tech Mono', monospace" }}
            tickLine={false}
            axisLine={false}
            label={{ value: "Events", angle: -90, position: "insideLeft", offset: 10, fill: "var(--text-muted)", fontSize: 10, fontFamily: "'Share Tech Mono', monospace" }}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend wrapperStyle={{ fontSize: "11px", fontFamily: "'Rajdhani', sans-serif", paddingTop: "8px" }} />
          {anomaly && (
            <ReferenceLine
              x={anomaly.time}
              stroke="var(--red)"
              strokeDasharray="4 2"
              strokeOpacity={0.7}
            />
          )}
          {anomaly && (
            <ReferenceDot
              x={anomaly.time}
              y={anomaly["Auth Failures"]}
              r={6}
              fill="var(--red)"
              stroke="var(--bg-card)"
              strokeWidth={2}
              label={{ value: `⚠ ${anomaly["Auth Failures"]} failures`, position: "top", fill: "var(--red)", fontSize: 10, fontFamily: "'Share Tech Mono', monospace" }}
            />
          )}
          <Line type="monotone" dataKey="Auth Failures"   stroke="var(--red)"    strokeWidth={2}   dot={false} activeDot={{ r: 4, strokeWidth: 0 }} />
          <Line type="monotone" dataKey="Auth Success"    stroke="var(--green)"  strokeWidth={1.5} dot={false} activeDot={{ r: 4, strokeWidth: 0 }} />
          <Line type="monotone" dataKey="Firewall Blocks" stroke="var(--yellow)" strokeWidth={1.5} dot={false} activeDot={{ r: 4, strokeWidth: 0 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
