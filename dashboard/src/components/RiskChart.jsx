import React, { useMemo } from "react";
import { Pie, PieChart, Cell, ResponsiveContainer, Tooltip } from "recharts";

const COLORS = {
  CRITICAL: "#ff4d6a",
  HIGH:     "#ff8c42",
  MEDIUM:   "#ffd166",
  LOW:      "#06d6a0",
  INFO:     "#4a5568",
};

const TOOLTIP_STYLE = {
  backgroundColor: "#111827",
  border: "1px solid #1e2d45",
  borderRadius: 10,
  color: "#f0f4ff",
  fontSize: 12,
  fontFamily: "'DM Sans', system-ui, sans-serif",
  boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
};

export default function RiskChart({ byPriority }) {
  const data = useMemo(() => {
    const src = byPriority ?? {};
    return ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
      .map(key => ({ name: key, value: Number(src[key] ?? 0), color: COLORS[key] }))
      .filter(d => d.value > 0);
  }, [byPriority]);

  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <div>
      <div className="relative mx-auto" style={{ width: "100%", maxWidth: 240 }}>
        <ResponsiveContainer width="100%" height={210}>
          <PieChart>
            <Tooltip
              formatter={(value, name) => [value, name]}
              contentStyle={TOOLTIP_STYLE}
            />
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={62}
              outerRadius={90}
              paddingAngle={2}
              stroke="none"
            >
              {data.map(entry => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        {/* Centre */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <div style={{ color: "#f0f4ff", letterSpacing: "-0.03em", fontVariantNumeric: "tabular-nums" }} className="text-[28px] font-bold">
            {total}
          </div>
          <div style={{ color: "var(--text-muted)" }} className="text-[11px] mt-0.5">total</div>
        </div>
      </div>

      {total === 0 && (
        <div style={{ color: "var(--text-muted)" }} className="mt-2 text-center text-xs">No data available.</div>
      )}

      <div className="mt-4 space-y-1.5">
        {data.map(d => (
          <div key={d.name} className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-sm" style={{ background: d.color }} />
              <span style={{ color: "var(--text-secondary)" }} className="text-xs">{d.name}</span>
            </div>
            <span style={{ color: "#f0f4ff", fontVariantNumeric: "tabular-nums" }} className="text-xs font-semibold">
              {d.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
