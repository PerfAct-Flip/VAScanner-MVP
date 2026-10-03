import { ArrowLeft, Download, FileText, RotateCcw, XCircle } from "lucide-react";
import { Link, useParams } from "react-router-dom";

import { IdentityBadge } from "@/components/identity-badge";
import { ReportsPanel } from "@/components/reports-panel";
import { SeverityBadge } from "@/components/severity-badge";
import { SeverityBarChart } from "@/components/severity-bar-chart";
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
import { useCancelScan, useRetryScan, useScan, useScanAssets, useScanFindings } from "@/hooks/use-scans";
import { api } from "@/lib/api";
import type { Asset, Finding } from "@/lib/types";

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

function FindingsTable({ findings, assetsById }: { findings: Finding[]; assetsById: Map<number, Asset> }) {
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
        {findings.map((f) => {
          const asset = assetsById.get(f.asset_id);
          const label = asset ? (asset.hostname ?? asset.ip_address ?? `#${f.asset_id}`) : `#${f.asset_id}`;
          return (
            <TableRow key={f.id}>
              <TableCell className="align-top text-muted-foreground whitespace-nowrap">
                {label}
                {asset?.hostname && asset.ip_address && (
                  <span className="ml-1 text-xs">({asset.ip_address})</span>
                )}
              </TableCell>
              <TableCell className="align-top whitespace-nowrap">
                <SeverityBadge severity={f.severity} />
              </TableCell>
              <TableCell className="align-top whitespace-nowrap">{f.cve ?? "—"}</TableCell>
              {/* Overrides the table's default whitespace-nowrap, which doesn't
                  truncate long text — it just lets it visually bleed into the
                  next column. A fixed width + normal wrapping keeps these two
                  long-text columns from overlapping each other. */}
              <TableCell className="w-64 max-w-64 align-top wrap-break-word whitespace-normal">
                {f.description ?? "—"}
              </TableCell>
              <TableCell className="w-64 max-w-64 align-top wrap-break-word whitespace-normal">
                {f.recommendation ?? "—"}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

function ScannedAssetsCard({
  assets,
  title,
  emptyMessage,
}: {
  assets: Asset[] | undefined;
  title: string;
  emptyMessage: string;
}) {
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle>
          {title} ({assets?.length ?? 0})
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {!assets || assets.length === 0 ? (
          <p className="px-6 pb-6 text-sm text-muted-foreground">{emptyMessage}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead>IP address</TableHead>
                <TableHead>MAC address</TableHead>
                <TableHead>Identity</TableHead>
                <TableHead>Open ports</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {assets.map((asset) => (
                <TableRow key={asset.id}>
                  <TableCell>{asset.hostname ?? "—"}</TableCell>
                  <TableCell className="font-mono text-xs">{asset.ip_address ?? "—"}</TableCell>
                  <TableCell className="font-mono text-xs">{asset.mac_address ?? "—"}</TableCell>
                  <TableCell>
                    <IdentityBadge confidence={asset.identity_confidence} />
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {asset.open_ports?.split(",").join(", ") ?? "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

export function ScanDetailPage() {
  const { id } = useParams();
  const scanId = Number(id);
  const { data: scan, isLoading } = useScan(scanId);
  const { data: findings } = useScanFindings(scanId, scan?.status);
  const { data: assets } = useScanAssets(scanId, scan?.status);
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
  const canRetry = scan.retryable;
  const hasDiscover = scan.type === "internal" && engines.some((e) => e.engine === "discover");
  const assetsById = new Map((assets ?? []).map((a) => [a.id, a]));

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

      <ScannedAssetsCard
        assets={assets}
        title={hasDiscover ? "Discovered Hosts" : "Target Assets"}
        emptyMessage={
          hasDiscover
            ? "No hosts found yet — this fills in live as Discovery runs."
            : "No target assets recorded for this scan."
        }
      />

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
              <FindingsTable findings={findings?.nuclei ?? []} assetsById={assetsById} />
            </TabsContent>
            <TabsContent value="openvas">
              <FindingsTable findings={findings?.openvas ?? []} assetsById={assetsById} />
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Findings by Severity</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <div>
            <p className="mb-2 text-sm font-medium text-muted-foreground">
              Nuclei ({findings?.nuclei.length ?? 0})
            </p>
            <SeverityBarChart findings={findings?.nuclei ?? []} />
          </div>
          <div>
            <p className="mb-2 text-sm font-medium text-muted-foreground">
              OpenVAS ({findings?.openvas.length ?? 0})
            </p>
            <SeverityBarChart findings={findings?.openvas ?? []} />
          </div>
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Reports</CardTitle>
        </CardHeader>
        <CardContent>
          <ReportsPanel scanId={scan.id} scanType={scan.type} />
        </CardContent>
      </Card>
    </div>
  );
}
