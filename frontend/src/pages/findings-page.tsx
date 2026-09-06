import { Download, FileText } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/page-header";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
import { useFindings } from "@/hooks/use-findings";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];

function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="p-10 text-center text-sm text-muted-foreground">
        No findings match these filters.
      </div>
    );
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Scan</TableHead>
          <TableHead>Asset</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>CVE</TableHead>
          <TableHead>Description</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => (
          <TableRow key={f.id}>
            <TableCell className="text-muted-foreground">#{f.scan_id}</TableCell>
            <TableCell className="text-muted-foreground">#{f.asset_id}</TableCell>
            <TableCell>
              <SeverityBadge severity={f.severity} />
            </TableCell>
            <TableCell>{f.cve ?? "—"}</TableCell>
            <TableCell className="max-w-lg truncate">{f.description ?? "—"}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function FindingsPage() {
  const [severity, setSeverity] = useState<string | undefined>(undefined);
  const { data: findings, isLoading } = useFindings({ severity });

  const nuclei = findings?.filter((f) => f.engine === "nuclei") ?? [];
  const openvas = findings?.filter((f) => f.engine === "openvas") ?? [];

  return (
    <div>
      <PageHeader
        title="Findings"
        description="Nuclei and OpenVAS findings, always kept in structurally separate sections."
        action={
          <div className="flex gap-2">
            <Button variant="outline" render={<a href={api.reportCsvUrl()} />}>
              <Download className="size-4" />
              Export CSV
            </Button>
            <Button variant="outline" render={<a href={api.reportPdfUrl()} />}>
              <FileText className="size-4" />
              Export PDF
            </Button>
          </div>
        }
      />

      <div className="mb-4">
        <Select
          value={severity}
          onValueChange={(v) => setSeverity(v === "all" ? undefined : (v as string))}
        >
          <SelectTrigger className="w-44">
            <SelectValue placeholder="All severities" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="space-y-2 p-6">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : (
            <Tabs defaultValue="nuclei">
              <TabsList className="mx-4">
                <TabsTrigger value="nuclei">Nuclei Results ({nuclei.length})</TabsTrigger>
                <TabsTrigger value="openvas">OpenVAS Results ({openvas.length})</TabsTrigger>
              </TabsList>
              <TabsContent value="nuclei">
                <FindingsTable findings={nuclei} />
              </TabsContent>
              <TabsContent value="openvas">
                <FindingsTable findings={openvas} />
              </TabsContent>
            </Tabs>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
