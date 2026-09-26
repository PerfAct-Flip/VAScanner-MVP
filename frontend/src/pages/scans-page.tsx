import { Plus, X } from "lucide-react";
import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";

import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
import { ScrollArea } from "@/components/ui/scroll-area";
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
import { useAgents } from "@/hooks/use-agents";
import { useAssets } from "@/hooks/use-assets";
import { useCreateScan, useRetryScan, useScans } from "@/hooks/use-scans";
import type { CredentialType, ScanEngineChoice, ScanType } from "@/lib/types";

interface CredentialRow {
  id: string;
  type: CredentialType;
  username: string;
  secret: string;
  port: string;
}

const ENGINE_LABELS: Record<ScanEngineChoice, string> = {
  discover: "Discovery (ping-sweep + port check)",
  nuclei: "Nuclei",
  openvas: "OpenVAS / SSH Audit",
};

// crypto.randomUUID() only exists in secure contexts (HTTPS/localhost) — this
// app is served over plain HTTP on a bare IP, where it's undefined and throws.
function newRowId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function emptyCredentialRow(): CredentialRow {
  return { id: newRowId(), type: "ssh", username: "", secret: "", port: "" };
}

function NewScanDialog() {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState<ScanType>("external");
  const [assetIds, setAssetIds] = useState<number[]>([]);
  const [agentId, setAgentId] = useState<string>("");
  const [credentials, setCredentials] = useState<CredentialRow[]>([]);
  const [engines, setEngines] = useState<Record<ScanEngineChoice, boolean>>({
    discover: true,
    nuclei: true,
    openvas: true,
  });
  const { data: assets, isLoading: assetsLoading } = useAssets();
  const { data: agents, isLoading: agentsLoading } = useAgents();
  const createScan = useCreateScan();

  const internalAgents = (agents ?? []).filter((a) => a.type === "internal");
  const isInternal = type === "internal";
  const engineChoices: ScanEngineChoice[] = isInternal ? ["discover", "nuclei", "openvas"] : ["nuclei", "openvas"];
  const selectedEngines = engineChoices.filter((e) => engines[e]);
  const validCredentials = credentials
    .filter((c) => c.username.trim() !== "" && c.secret !== "")
    .map((c) => ({
      type: c.type,
      username: c.username.trim(),
      secret: c.secret,
      ...(c.port.trim() !== "" ? { port: Number(c.port) } : {}),
    }));

  const needsAssetsForNoDiscover = isInternal && !engines.discover && assetIds.length === 0;
  // Not blocking: missing a credential for OpenVAS is a predictable,
  // recoverable situation, not a reason to refuse the whole scan — the
  // backend just skips that one engine and returns a warning explaining
  // why, shown as a toast after submission.
  const willSkipOpenvas = isInternal && engines.openvas && validCredentials.length === 0;
  const canSubmit =
    (isInternal ? agentId !== "" : assetIds.length > 0) && selectedEngines.length > 0 && !needsAssetsForNoDiscover;

  function toggleAsset(id: number, checked: boolean) {
    setAssetIds((prev) => (checked ? [...prev, id] : prev.filter((a) => a !== id)));
  }

  function toggleEngine(name: ScanEngineChoice, checked: boolean) {
    setEngines((prev) => ({ ...prev, [name]: checked }));
  }

  function updateCredential(id: string, patch: Partial<CredentialRow>) {
    setCredentials((prev) => prev.map((c) => (c.id === id ? { ...c, ...patch } : c)));
  }

  function removeCredential(id: string) {
    setCredentials((prev) => prev.filter((c) => c.id !== id));
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;

    createScan.mutate(
      isInternal
        ? {
            type,
            asset_ids: assetIds,
            agent_id: Number(agentId),
            credentials: validCredentials,
            engines: selectedEngines,
          }
        : { type, asset_ids: assetIds, engines: selectedEngines },
      {
        onSuccess: () => {
          setOpen(false);
          setAssetIds([]);
          setAgentId("");
          setCredentials([]);
          setEngines({ discover: true, nuclei: true, openvas: true });
        },
      },
    );
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button />}>
        <Plus className="size-4" />
        New scan
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Start a new scan</DialogTitle>
            <DialogDescription>
              {isInternal
                ? "The chosen agent runs whichever engines you select below against its network."
                : "The selected engines run in parallel against the target assets."}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label>Scan type</Label>
              <Select value={type} onValueChange={(v) => setType(v as ScanType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="external">External</SelectItem>
                  <SelectItem value="internal">Internal</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid gap-2">
              <Label>Engines to run</Label>
              <div className="flex flex-wrap gap-4">
                {engineChoices.map((name) => (
                  <label key={name} className="flex cursor-pointer items-center gap-2 text-sm">
                    <Checkbox
                      checked={engines[name]}
                      onCheckedChange={(checked) => toggleEngine(name, checked === true)}
                    />
                    {ENGINE_LABELS[name]}
                  </label>
                ))}
              </div>
              {selectedEngines.length === 0 && (
                <p className="text-xs text-destructive">Select at least one engine.</p>
              )}
              {needsAssetsForNoDiscover && (
                <p className="text-xs text-destructive">
                  Skipping Discovery requires pre-seeding at least one asset below.
                </p>
              )}
              {willSkipOpenvas && (
                <p className="text-xs text-amber-600 dark:text-amber-500">
                  No credential added below — OpenVAS / SSH Audit will be skipped for this scan rather than
                  failing. Add one below if you want it to run, or ignore this to scan without it.
                </p>
              )}
            </div>

            {isInternal && (
              <div className="grid gap-2">
                <Label>Presence Agent</Label>
                {agentsLoading ? (
                  <Skeleton className="h-9 w-full" />
                ) : internalAgents.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    No internal agents registered yet — install and run the Presence Agent on a
                    machine inside the target network first.
                  </p>
                ) : (
                  <Select value={agentId} onValueChange={(v) => setAgentId(v ?? "")}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select an agent" />
                    </SelectTrigger>
                    <SelectContent>
                      {internalAgents.map((agent) => (
                        <SelectItem key={agent.id} value={String(agent.id)}>
                          {agent.name} · {agent.status}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </div>
            )}

            <div className="grid gap-2">
              <Label>
                {isInternal ? (engines.discover ? "Pre-seed assets (optional)" : "Target assets") : "Target assets"}
              </Label>
              {isInternal && (
                <p className="text-xs text-muted-foreground">
                  {engines.discover
                    ? "The agent discovers live hosts on its network automatically — pick assets here only if you want to scan specific known hosts in addition to what it finds."
                    : "Discovery is unchecked above, so nothing will be found automatically — pick at least one asset to scan directly."}
                </p>
              )}
              {assetsLoading ? (
                <Skeleton className="h-32 w-full" />
              ) : !assets || assets.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {isInternal
                    ? engines.discover
                      ? "No assets to pre-seed — that's fine, the agent will discover targets itself."
                      : "No assets available — add one first, or check Discovery above."
                    : "No assets available — add an asset first."}
                </p>
              ) : (
                <ScrollArea className="h-48 rounded-md border">
                  <div className="space-y-1 p-3">
                    {assets.map((asset) => (
                      <label
                        key={asset.id}
                        className="flex cursor-pointer items-center gap-3 rounded px-2 py-1.5 text-sm hover:bg-accent"
                      >
                        <Checkbox
                          checked={assetIds.includes(asset.id)}
                          onCheckedChange={(checked) => toggleAsset(asset.id, checked === true)}
                        />
                        <span className="font-medium">{asset.hostname ?? asset.ip_address}</span>
                        {asset.hostname && asset.ip_address && (
                          <span className="text-muted-foreground">{asset.ip_address}</span>
                        )}
                      </label>
                    ))}
                  </div>
                </ScrollArea>
              )}
            </div>

            {isInternal && (
              <div className="grid gap-2">
                <div className="flex items-center justify-between">
                  <Label>{engines.openvas ? "Credentials (needed for OpenVAS / SSH Audit)" : "Credentials (optional)"}</Label>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setCredentials((prev) => [...prev, emptyCredentialRow()])}
                  >
                    <Plus className="size-4" />
                    Add credential
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Used for authenticated checks (SSH config, pending updates) against discovered
                  hosts. Each credential is tried against every target — leave empty and OpenVAS /
                  SSH Audit will just be skipped for this scan rather than failing.
                </p>
                {credentials.map((cred) => (
                  <div key={cred.id} className="grid grid-cols-[100px_1fr_1fr_80px_auto] gap-2 rounded-md border p-2">
                    <Select
                      value={cred.type}
                      onValueChange={(v) => updateCredential(cred.id, { type: (v ?? "ssh") as CredentialType })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ssh">SSH</SelectItem>
                        <SelectItem value="winrm">WinRM</SelectItem>
                        <SelectItem value="snmp">SNMP</SelectItem>
                      </SelectContent>
                    </Select>
                    <Input
                      placeholder="Username"
                      value={cred.username}
                      onChange={(e) => updateCredential(cred.id, { username: e.target.value })}
                    />
                    <Input
                      type="password"
                      placeholder="Password"
                      value={cred.secret}
                      onChange={(e) => updateCredential(cred.id, { secret: e.target.value })}
                    />
                    <Input
                      placeholder="Port"
                      inputMode="numeric"
                      value={cred.port}
                      onChange={(e) => updateCredential(cred.id, { port: e.target.value })}
                    />
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => removeCredential(cred.id)}
                      aria-label="Remove credential"
                    >
                      <X className="size-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <DialogFooter>
            <Button type="submit" disabled={createScan.isPending || !canSubmit}>
              {createScan.isPending ? "Starting…" : "Start scan"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function ScansPage() {
  const { data: scans, isLoading } = useScans();
  const retryScan = useRetryScan();

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Choose which engines to run per scan — Discovery, Nuclei, and OpenVAS/SSH Audit each run independently."
        action={<NewScanDialog />}
      />

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="space-y-2 p-6">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : !scans || scans.length === 0 ? (
            <div className="p-10 text-center text-sm text-muted-foreground">
              No scans yet. Start one from the Scans page.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Overall status</TableHead>
                  <TableHead>Nuclei</TableHead>
                  <TableHead>OpenVAS</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => {
                  const nuclei = scan.engines.find((e) => e.engine === "nuclei");
                  const openvas = scan.engines.find((e) => e.engine === "openvas");
                  return (
                    <TableRow key={scan.id}>
                      <TableCell className="text-muted-foreground">{scan.id}</TableCell>
                      <TableCell className="capitalize">{scan.type}</TableCell>
                      <TableCell>
                        <StatusBadge status={scan.status} />
                      </TableCell>
                      <TableCell>
                        {nuclei ? <StatusBadge status={nuclei.status} /> : "—"}
                      </TableCell>
                      <TableCell>
                        {openvas ? <StatusBadge status={openvas.status} /> : "—"}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {scan.start_time ? new Date(scan.start_time).toLocaleString() : "—"}
                      </TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-2">
                          {scan.status === "failed" && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => retryScan.mutate(scan.id)}
                              disabled={retryScan.isPending}
                            >
                              Retry
                            </Button>
                          )}
                          <Button variant="outline" size="sm" render={<Link to={`/scans/${scan.id}`} />}>
                            View
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
