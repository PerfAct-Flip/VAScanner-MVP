import { Radar, ScanLine, Server, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
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
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { useAgents } from "@/hooks/use-agents";
import { useAssets } from "@/hooks/use-assets";
import { useFindings } from "@/hooks/use-findings";
import { useScans } from "@/hooks/use-scans";
import { SEVERITY_COLORS, SEVERITY_ORDER, scanStatusColor } from "@/lib/chart-colors";
import { cn } from "@/lib/utils";

function StatCard({
  icon: Icon,
  label,
  value,
  loading,
}: {
  icon: typeof Server;
  label: string;
  value: number | string;
  loading: boolean;
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 py-5">
        <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
          <Icon className="size-5" />
        </div>
        <div>
          <div className="text-xs text-muted-foreground">{label}</div>
          {loading ? (
            <Skeleton className="mt-1 h-6 w-10" />
          ) : (
            <div className="text-xl font-semibold">{value}</div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function SeverityBarChart({ findings }: { findings: { severity: string }[] }) {
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

function ScanStatusDonut({ scans }: { scans: { status: string }[] }) {
  const statuses = ["completed", "running", "queued", "failed", "canceled"];
  const data = statuses
    .map((status) => ({ status, count: scans.filter((s) => s.status === status).length }))
    .filter((d) => d.count > 0);

  if (data.length === 0) {
    return <p className="text-sm text-muted-foreground">No scans yet.</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="count" nameKey="status" innerRadius={55} outerRadius={80} paddingAngle={2}>
          {data.map((d) => (
            <Cell key={d.status} fill={scanStatusColor(d.status)} />
          ))}
        </Pie>
        <Tooltip content={ChartTooltip} />
      </PieChart>
    </ResponsiveContainer>
  );
}

export function DashboardPage() {
  const { data: assets, isLoading: assetsLoading } = useAssets();
  const { data: scans, isLoading: scansLoading } = useScans();
  const { data: agents, isLoading: agentsLoading } = useAgents();
  const { data: findings, isLoading: findingsLoading } = useFindings({});

  const runningScans = scans?.filter((s) => s.status === "queued" || s.status === "running").length ?? 0;
  const agentsOnline = agents?.filter((a) => a.status === "online").length ?? 0;
  const recentScans = scans?.slice(0, 5) ?? [];

  return (
    <div>
      <PageHeader title="Dashboard" description="Operational overview of assets, scans, and agent presence." />

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard icon={Server} label="Total assets" value={assets?.length ?? 0} loading={assetsLoading} />
        <StatCard icon={ScanLine} label="Total scans" value={scans?.length ?? 0} loading={scansLoading} />
        <StatCard icon={ShieldAlert} label="Scans running" value={runningScans} loading={scansLoading} />
        <StatCard icon={Radar} label="Agents online" value={agentsOnline} loading={agentsLoading} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle>Recent scans</CardTitle>
            <Link to="/scans" className="text-sm text-primary hover:underline">
              View all
            </Link>
          </CardHeader>
          <CardContent className="space-y-2">
            {scansLoading ? (
              Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)
            ) : recentScans.length === 0 ? (
              <p className="text-sm text-muted-foreground">No scans yet.</p>
            ) : (
              recentScans.map((scan) => (
                <Link
                  key={scan.id}
                  to={`/scans/${scan.id}`}
                  className="flex items-center justify-between rounded-lg border p-3 text-sm transition-colors hover:bg-accent"
                >
                  <div>
                    <div className="font-medium capitalize">
                      Scan #{scan.id} · {scan.type}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {scan.start_time ? new Date(scan.start_time).toLocaleString() : "Not started"}
                    </div>
                  </div>
                  <StatusBadge status={scan.status} />
                </Link>
              ))
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Agent presence</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {agentsLoading ? (
              Array.from({ length: 2 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)
            ) : !agents || agents.length === 0 ? (
              <p className="text-sm text-muted-foreground">No agents reporting yet.</p>
            ) : (
              agents.map((agent) => (
                <div key={agent.id} className="flex items-center justify-between text-sm">
                  <div>
                    <div className="font-medium">{agent.name}</div>
                    <div className="text-xs capitalize text-muted-foreground">{agent.type}</div>
                  </div>
                  <Badge
                    className={cn(
                      "border-transparent capitalize",
                      agent.status === "online"
                        ? "bg-green-600 text-white dark:bg-green-600"
                        : "bg-slate-400 text-white dark:bg-slate-500",
                    )}
                  >
                    {agent.status}
                  </Badge>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Findings by severity</CardTitle>
          </CardHeader>
          <CardContent>
            {findingsLoading ? <Skeleton className="h-55 w-full" /> : <SeverityBarChart findings={findings ?? []} />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Scan status</CardTitle>
          </CardHeader>
          <CardContent>
            {scansLoading ? <Skeleton className="h-55 w-full" /> : <ScanStatusDonut scans={scans ?? []} />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
