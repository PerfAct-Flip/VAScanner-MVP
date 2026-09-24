import { Download, FileText, Trash2 } from "lucide-react";

import { PciReportDialog } from "@/components/pci-report-dialog";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useDeleteReport, useGenerateReport, useReports } from "@/hooks/use-reports";
import { api } from "@/lib/api";
import type { ScanType } from "@/lib/types";

export function ReportsPanel({ scanId, scanType }: { scanId?: number; scanType?: ScanType }) {
  const { data: reports, isLoading } = useReports(scanId);
  const generateReport = useGenerateReport();
  const deleteReport = useDeleteReport(scanId);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium">Generated reports</h3>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => generateReport.mutate({ scan_id: scanId, format: "csv" })}
            disabled={generateReport.isPending}
          >
            <Download className="size-4" />
            Generate CSV
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => generateReport.mutate({ scan_id: scanId, format: "pdf" })}
            disabled={generateReport.isPending}
          >
            <FileText className="size-4" />
            Generate PDF
          </Button>
          {/* PCI ASV certification only covers external scans (PCI DSS 11.3.2) —
              an internal scan has no ASV attestation to make. */}
          {scanId !== undefined && scanType === "external" && <PciReportDialog scanId={scanId} />}
        </div>
      </div>

      {isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : !reports || reports.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No reports generated yet — a generated report is a saved snapshot, distinct from the
          always-live CSV/PDF download links above.
        </p>
      ) : (
        <div className="divide-y rounded-md border">
          {reports.map((r) => (
            <div key={r.id} className="flex items-center justify-between px-3 py-2 text-sm">
              <div className="flex items-center gap-3">
                <span className="font-medium uppercase">{r.format}</span>
                <span className="text-muted-foreground">{new Date(r.generated_at).toLocaleString()}</span>
                <span className="text-muted-foreground">{r.finding_count} finding(s)</span>
              </div>
              <div className="flex gap-1">
                <Button size="sm" variant="ghost" render={<a href={api.reportDownloadUrl(r.id)} />}>
                  <Download className="size-4" />
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => deleteReport.mutate(r.id)}
                  disabled={deleteReport.isPending}
                  aria-label="Delete report"
                >
                  <Trash2 className="size-4 text-destructive" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
