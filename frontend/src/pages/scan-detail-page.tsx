import { ArrowLeft, Download, FileText, RotateCcw, XCircle } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { ReportsPanel } from "@/components/reports-panel";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useCancelScan, useRetryScan, useScan, useScanFindings } from "@/hooks/use-scans";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";

function EngineCard({
  name,
  status,
  progress,
  progressPct,
  errorMessage,
  startedAt,
  finishedAt,
}: {
  name: string;
  status: string;
  progress: string | null;
  progressPct: number;
  errorMessage: string | null;
  startedAt: string | null;
  finishedAt: string | null;
}) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle className="capitalize">{name}</CardTitle>
        <StatusBadge status={status} />
      </CardHeader>
      <CardContent className="space-y-3">
        <div>
          <div className="mb-1 flex justify-between text-xs text-muted-foreground">
            <span>{progress || "—"}</span>
            <span>{progressPct}%</span>
          </div>
          <Progress value={progressPct} />
        </div>
        {errorMessage && (
          <p className="rounded-md bg-destructive/10 p-2 text-xs text-destructive">
            {errorMessage}
          </p>
        )}
        <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
          <div>
            <div className="font-medium text-foreground">Started</div>
            {startedAt ? new Date(startedAt).toLocaleString() : "—"}
          </div>
          <div>
            <div className="font-medium text-foreground">Finished</div>
            {finishedAt ? new Date(finishedAt).toLocaleString() : "—"}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="p-10 text-center text-sm text-muted-foreground">
        No findings reported by this engine.
      </div>
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Asset</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>CVE</TableHead>
          <TableHead>Description</TableHead>
          <TableHead>Recommendation</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => (
          <TableRow key={f.id}>
            <TableCell className="text-muted-foreground">#{f.asset_id}</TableCell>
            <TableCell>
              <SeverityBadge severity={f.severity} />
            </TableCell>
            <TableCell>{f.cve ?? "—"}</TableCell>
            <TableCell className="max-w-md">{f.description ?? "—"}</TableCell>
            <TableCell className="max-w-md">{f.recommendation ?? "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function ScanDetailPage() {
  const { id } = useParams();
  const scanId = Number(id);
  const { data: scan, isLoading } = useScan(scanId);
  const { data: findings } = useScanFindings(scanId);
  const cancelScan = useCancelScan();
  const retryScan = useRetryScan();

  if (isLoading || !scan) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  const engineOrder = ["discover", "nuclei", "openvas"];
  const engines = [...scan.engines].sort(
    (a, b) => engineOrder.indexOf(a.engine) - engineOrder.indexOf(b.engine),
  );
  const canCancel = scan.status === "queued" || scan.status === "running";
  const canRetry = scan.status === "failed";

  return (
    <div>
      <Link
        to="/scans"
        className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-4" />
        Back to scans
      </Link>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">Scan #{scan.id}</h1>
            <StatusBadge status={scan.status} />
          </div>
          <p className="mt-1 text-sm capitalize text-muted-foreground">
            {scan.type} scan · started{" "}
            {scan.start_time ? new Date(scan.start_time).toLocaleString() : "—"}
          </p>
        </div>
        <div className="flex gap-2">
          {canCancel && (
            <Button
              variant="outline"
              onClick={() => cancelScan.mutate(scan.id)}
              disabled={cancelScan.isPending}
            >
              <XCircle className="size-4" />
              Cancel scan
            </Button>
          )}
          {canRetry && (
            <Button
              variant="outline"
              onClick={() => retryScan.mutate(scan.id)}
              disabled={retryScan.isPending}
            >
              <RotateCcw className="size-4" />
              Retry failed
            </Button>
          )}
          <Button variant="outline" render={<a href={api.reportCsvUrl(scan.id)} />}>
            <Download className="size-4" />
            CSV
          </Button>
          <Button variant="outline" render={<a href={api.reportPdfUrl(scan.id)} />}>
            <FileText className="size-4" />
            PDF
          </Button>
        </div>
      </div>

      <div className="mb-6 grid gap-4 md:grid-cols-2">
        {engines.map((engine) => (
          <EngineCard
            key={engine.engine}
            name={engine.engine}
            status={engine.status}
            progress={engine.progress}
            progressPct={engine.progress_pct}
            errorMessage={engine.error_message}
            startedAt={engine.started_at}
            finishedAt={engine.finished_at}
          />
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Tabs defaultValue="nuclei">
            <TabsList className="mx-4">
              <TabsTrigger value="nuclei">
                Nuclei Results ({findings?.nuclei.length ?? 0})
              </TabsTrigger>
              <TabsTrigger value="openvas">
                OpenVAS Results ({findings?.openvas.length ?? 0})
              </TabsTrigger>
            </TabsList>
            <TabsContent value="nuclei">
              <FindingsTable findings={findings?.nuclei ?? []} />
            </TabsContent>
            <TabsContent value="openvas">
              <FindingsTable findings={findings?.openvas ?? []} />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Reports</CardTitle>
        </CardHeader>
        <CardContent>
          <ReportsPanel scanId={scan.id} />
        </CardContent>
      </Card>
    </div>
  );
}
