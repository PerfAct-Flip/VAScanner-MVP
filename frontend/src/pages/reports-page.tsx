import { Download, FileText } from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { ReportsPanel } from "@/components/reports-panel";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { api } from "@/lib/api";

export function ReportsPage() {
  return (
    <div>
      <PageHeader
        title="Reports"
        description="Generate a saved snapshot report, or grab an always-live export of current findings."
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
      <Card>
        <CardContent className="pt-6">
          <ReportsPanel />
        </CardContent>
      </Card>
    </div>
  );
}
