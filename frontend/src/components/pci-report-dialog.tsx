import { FileText } from "lucide-react";
import { type FormEvent, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useGenerateReport } from "@/hooks/use-reports";
import type { PciCompanyInfo, PciReportInfo } from "@/lib/types";

const EMPTY_COMPANY: PciCompanyInfo = {
  company: "",
  contact_name: "",
  job_title: "",
  telephone: "",
  email: "",
  address: "",
  city: "",
  state: "",
  postal_code: "",
  country: "",
  url: "",
};

// The ASV's own identity barely changes between reports — remembering it
// locally saves re-typing ~10 fields every time. The scan customer's info
// is scan-specific and intentionally not remembered.
const ASV_DRAFT_KEY = "pci-report-asv-info";

function loadAsvDraft(): PciCompanyInfo {
  try {
    const raw = localStorage.getItem(ASV_DRAFT_KEY);
    if (raw) return { ...EMPTY_COMPANY, ...JSON.parse(raw) };
  } catch {
    // ignore malformed/unavailable storage
  }
  return EMPTY_COMPANY;
}

function CompanyFields({
  value,
  onChange,
  prefix,
}: {
  value: PciCompanyInfo;
  onChange: (patch: Partial<PciCompanyInfo>) => void;
  prefix: string;
}) {
  return (
    <div className="grid grid-cols-2 gap-3">
      <div className="col-span-2 grid gap-1.5">
        <Label>Company</Label>
        <Input required value={value.company} onChange={(e) => onChange({ company: e.target.value })} />
      </div>
      <div className="grid gap-1.5">
        <Label>Contact name</Label>
        <Input required value={value.contact_name} onChange={(e) => onChange({ contact_name: e.target.value })} />
      </div>
      <div className="grid gap-1.5">
        <Label>Job title</Label>
        <Input required value={value.job_title} onChange={(e) => onChange({ job_title: e.target.value })} />
      </div>
      <div className="grid gap-1.5">
        <Label>Telephone</Label>
        <Input required value={value.telephone} onChange={(e) => onChange({ telephone: e.target.value })} />
      </div>
      <div className="grid gap-1.5">
        <Label>Email</Label>
        <Input required type="email" value={value.email} onChange={(e) => onChange({ email: e.target.value })} />
      </div>
      <div className="col-span-2 grid gap-1.5">
        <Label>Business address</Label>
        <Textarea
          required
          rows={2}
          value={value.address}
          onChange={(e) => onChange({ address: e.target.value })}
        />
      </div>
      <div className="grid gap-1.5">
        <Label>City</Label>
        <Input value={value.city} onChange={(e) => onChange({ city: e.target.value })} />
      </div>
      <div className="grid gap-1.5">
        <Label>State/Province</Label>
        <Input value={value.state} onChange={(e) => onChange({ state: e.target.value })} />
      </div>
      <div className="grid gap-1.5">
        <Label>ZIP/Postal code</Label>
        <Input value={value.postal_code} onChange={(e) => onChange({ postal_code: e.target.value })} />
      </div>
      <div className="grid gap-1.5">
        <Label>Country</Label>
        <Input value={value.country} onChange={(e) => onChange({ country: e.target.value })} />
      </div>
      <div className="col-span-2 grid gap-1.5">
        <Label>URL</Label>
        <Input value={value.url} onChange={(e) => onChange({ url: e.target.value })} placeholder={`https://...`} />
      </div>
      <p className="col-span-2 text-xs text-muted-foreground">{prefix}</p>
    </div>
  );
}

export function PciReportDialog({ scanId }: { scanId: number }) {
  const [open, setOpen] = useState(false);
  const [customer, setCustomer] = useState<PciCompanyInfo>(EMPTY_COMPANY);
  const [asv, setAsv] = useState<PciCompanyInfo>(loadAsvDraft);
  const [certNumber, setCertNumber] = useState("");
  const [scanType, setScanType] = useState<"Full scan" | "Partial scan">("Full scan");
  const generateReport = useGenerateReport();

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    localStorage.setItem(ASV_DRAFT_KEY, JSON.stringify(asv));

    const pci_info: PciReportInfo = {
      customer,
      asv,
      asv_certificate_number: certNumber,
      scan_report_type: scanType,
    };

    generateReport.mutate(
      { scan_id: scanId, format: "pci", pci_info },
      { onSuccess: () => setOpen(false) },
    );
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm" variant="outline" />}>
        <FileText className="size-4" />
        Generate PCI ASV Report
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Generate PCI ASV Scan Report</DialogTitle>
            <DialogDescription>
              Produces the Attestation of Scan Compliance, Executive Summary, and Vulnerability
              Details documents for this scan. This app has no customer/tenant model, so these
              details are entered per report rather than stored.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-5 py-4">
            <div>
              <h4 className="mb-2 text-sm font-medium">Scan customer</h4>
              <CompanyFields
                value={customer}
                onChange={(patch) => setCustomer((prev) => ({ ...prev, ...patch }))}
                prefix="The organization being scanned — appears in Section A.1 and the attestation signature."
              />
            </div>

            <div>
              <h4 className="mb-2 text-sm font-medium">Approved Scanning Vendor (your company)</h4>
              <CompanyFields
                value={asv}
                onChange={(patch) => setAsv((prev) => ({ ...prev, ...patch }))}
                prefix="Remembered locally on this device for next time."
              />
              <div className="mt-3 grid gap-1.5">
                <Label>ASV certificate number</Label>
                <Input required value={certNumber} onChange={(e) => setCertNumber(e.target.value)} />
              </div>
            </div>

            <div className="grid gap-1.5">
              <Label>Scan report type</Label>
              <Select value={scanType} onValueChange={(v) => setScanType((v ?? "Full scan") as typeof scanType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Full scan">Full scan</SelectItem>
                  <SelectItem value="Partial scan">Partial scan</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button type="submit" disabled={generateReport.isPending}>
              {generateReport.isPending ? "Generating…" : "Generate report"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
