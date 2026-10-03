import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { ChartTooltip } from "@/components/chart-tooltip";
import { SEVERITY_COLORS, SEVERITY_ORDER } from "@/lib/chart-colors";

export function SeverityBarChart({ findings }: { findings: { severity: string }[] }) {
  const data = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: findings.filter((f) => f.severity === severity).length,
  })).filter((d) => d.count > 0);

  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground">No findings yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 24 }}>
        <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
        <YAxis
          type="category"
          dataKey="severity"
          width={90}
          tick={{ fontSize: 12 }}
          stroke="var(--muted-foreground)"
          tickLine={false}
          axisLine={false}
        />
        <Bar dataKey="count" name="Findings" radius={[0, 4, 4, 0]} maxBarSize={20}>
          {data.map((d) => (
            <Cell key={d.severity} fill={SEVERITY_COLORS[d.severity]} />
          ))}
        </Bar>
        <Tooltip content={ChartTooltip} />
      </BarChart>
    </ResponsiveContainer>
  );
}
