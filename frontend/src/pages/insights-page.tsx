import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { ChartTooltip } from "@/components/chart-tooltip";
import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useAssets } from "@/hooks/use-assets";
import { useFindings } from "@/hooks/use-findings";
import { CATEGORICAL_COLORS, NEUTRAL_COLOR, SEVERITY_COLORS, SEVERITY_ORDER } from "@/lib/chart-colors";
import type { Asset, Finding, IdentityConfidence } from "@/lib/types";

const TREND_DAYS = 30;

function FindingsTrendChart({ findings }: { findings: Finding[] }) {
  const days: { date: string; count: number }[] = [];
  const counts = new Map<string, number>();
  for (const f of findings) {
    const key = f.created_at.slice(0, 10);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  for (let i = TREND_DAYS - 1; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    days.push({ date: `${d.getMonth() + 1}/${d.getDate()}`, count: counts.get(key) ?? 0 });
  }

  if (findings.length === 0) {
    return <p className="text-sm text-muted-foreground">No findings yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={days} margin={{ left: -16, right: 8 }}>
        <CartesianGrid strokeDasharray="0" vertical={false} stroke="var(--border)" />
        <XAxis dataKey="date" tick={{ fontSize: 11 }} stroke="var(--muted-foreground)" interval={4} />
        <YAxis allowDecimals={false} tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
        <Area
          type="monotone"
          dataKey="count"
          name="Findings"
          stroke={CATEGORICAL_COLORS[0]}
          fill={CATEGORICAL_COLORS[0]}
          fillOpacity={0.1}
          strokeWidth={2}
        />
        <Tooltip content={ChartTooltip} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function TopVulnerableAssetsChart({ findings, assets }: { findings: Finding[]; assets: Asset[] }) {
  const assetById = new Map(assets.map((a) => [a.id, a]));
  const counts = new Map<number, number>();
  for (const f of findings) {
    counts.set(f.asset_id, (counts.get(f.asset_id) ?? 0) + 1);
  }
  const data = [...counts.entries()]
    .map(([assetId, count]) => {
      const asset = assetById.get(assetId);
      const label = asset ? asset.hostname ?? asset.ip_address ?? `#${assetId}` : `#${assetId}`;
      return { label, count };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground">No findings yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} layout="vertical" margin={{ left: 16, right: 24 }}>
        <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
        <YAxis
          type="category"
          dataKey="label"
          width={130}
          tick={{ fontSize: 12 }}
          stroke="var(--muted-foreground)"
          tickLine={false}
          axisLine={false}
        />
        <Bar dataKey="count" name="Findings" radius={[0, 4, 4, 0]} maxBarSize={18}>
          {data.map((d) => (
            <Cell key={d.label} fill={CATEGORICAL_COLORS[0]} />
          ))}
        </Bar>
        <Tooltip content={ChartTooltip} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function FindingsByEngineChart({ findings }: { findings: Finding[] }) {
  const engines = ["nuclei", "openvas"];
  const data = engines.map((engine) => {
    const row: Record<string, string | number> = { engine: engine === "nuclei" ? "Nuclei" : "OpenVAS" };
    for (const severity of SEVERITY_ORDER) {
      row[severity] = findings.filter((f) => f.engine === engine && f.severity === severity).length;
    }
    return row;
  });

  const presentSeverities = SEVERITY_ORDER.filter((s) => data.some((row) => (row[s] as number) > 0));

  if (presentSeverities.length === 0) {
    return <p className="text-sm text-muted-foreground">No findings yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} margin={{ left: -16 }}>
        <CartesianGrid strokeDasharray="0" vertical={false} stroke="var(--border)" />
        <XAxis dataKey="engine" tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
        <YAxis allowDecimals={false} tick={{ fontSize: 12 }} stroke="var(--muted-foreground)" />
        {presentSeverities.map((severity, i) => (
          <Bar
            key={severity}
            dataKey={severity}
            name={severity}
            stackId="severity"
            fill={SEVERITY_COLORS[severity]}
            radius={i === presentSeverities.length - 1 ? [4, 4, 0, 0] : undefined}
            maxBarSize={64}
          />
        ))}
        <Tooltip content={ChartTooltip} />
      </BarChart>
    </ResponsiveContainer>
  );
}

const IDENTITY_LABELS: Record<IdentityConfidence, string> = { mac: "MAC", hostname: "Hostname", ip: "IP only" };

function IdentityConfidenceDonut({ assets }: { assets: Asset[] }) {
  const tiers: IdentityConfidence[] = ["mac", "hostname", "ip"];
  const data = tiers
    .map((tier, i) => ({
      tier: IDENTITY_LABELS[tier],
      count: assets.filter((a) => a.identity_confidence === tier).length,
      fill: CATEGORICAL_COLORS[i],
    }))
    .concat([
      {
        tier: "Unclassified",
        count: assets.filter((a) => !a.identity_confidence).length,
        fill: NEUTRAL_COLOR,
      },
    ])
    .filter((d) => d.count > 0);

  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground">No assets yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="count" nameKey="tier" innerRadius={55} outerRadius={80} paddingAngle={2}>
          {data.map((d) => (
            <Cell key={d.tier} fill={d.fill} />
          ))}
        </Pie>
        <Tooltip content={ChartTooltip} />
      </PieChart>
    </ResponsiveContainer>
  );
}

function TopCvesTable({ findings }: { findings: Finding[] }) {
  const byCve = new Map<string, { count: number; worstSeverity: string }>();
  for (const f of findings) {
    if (!f.cve) continue;
    const existing = byCve.get(f.cve);
    if (!existing) {
      byCve.set(f.cve, { count: 1, worstSeverity: f.severity });
      continue;
    }
    existing.count += 1;
    if (SEVERITY_ORDER.indexOf(f.severity as (typeof SEVERITY_ORDER)[number]) < SEVERITY_ORDER.indexOf(existing.worstSeverity as (typeof SEVERITY_ORDER)[number])) {
      existing.worstSeverity = f.severity;
    }
  }
  const rows = [...byCve.entries()]
    .map(([cve, v]) => ({ cve, ...v }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  if (rows.length === 0) {
    return <p className="p-6 text-sm text-muted-foreground">No CVE-tagged findings yet.</p>;
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>CVE</TableHead>
          <TableHead>Occurrences</TableHead>
          <TableHead>Worst severity</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((r) => (
          <TableRow key={r.cve}>
            <TableCell className="font-mono text-xs">{r.cve}</TableCell>
            <TableCell>{r.count}</TableCell>
            <TableCell>
              <SeverityBadge severity={r.worstSeverity} />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function InsightsPage() {
  const { data: findings, isLoading: findingsLoading } = useFindings({});
  const { data: assets, isLoading: assetsLoading } = useAssets();

  return (
    <div>
      <PageHeader
        title="Insights"
        description="Trends and patterns across every scan — where risk is concentrated, not just what's currently open."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Findings over time</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? <Skeleton className="h-65 w-full" /> : <FindingsTrendChart findings={findings ?? []} />}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top vulnerable assets</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading || assetsLoading ? (
              <Skeleton className="h-65 w-full" />
            ) : (
              <TopVulnerableAssetsChart findings={findings ?? []} assets={assets ?? []} />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Findings by engine</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? <Skeleton className="h-65 w-full" /> : <FindingsByEngineChart findings={findings ?? []} />}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Asset identity confidence</CardTitle>
          </CardHeader>
          <CardContent>
            {assetsLoading ? <Skeleton className="h-55 w-full" /> : <IdentityConfidenceDonut assets={assets ?? []} />}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Most frequent CVEs</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {findingsLoading ? (
              <div className="space-y-2 p-6">
                {Array.from({ length: 4 }).map((_, i) => (
                  <Skeleton key={i} className="h-8 w-full" />
                ))}
              </div>
            ) : (
              <TopCvesTable findings={findings ?? []} />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
