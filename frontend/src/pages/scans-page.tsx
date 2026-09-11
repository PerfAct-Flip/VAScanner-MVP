import { Plus } from "lucide-react";
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
import { useCreateScan, useScans } from "@/hooks/use-scans";
import type { ScanType } from "@/lib/types";

function NewScanDialog() {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState<ScanType>("external");
  const [assetIds, setAssetIds] = useState<number[]>([]);
  const [agentId, setAgentId] = useState<string>("");
  const { data: assets, isLoading: assetsLoading } = useAssets();
  const { data: agents, isLoading: agentsLoading } = useAgents();
  const createScan = useCreateScan();

  const internalAgents = (agents ?? []).filter((a) => a.type === "internal");
  const isInternal = type === "internal";
  const canSubmit = isInternal ? agentId !== "" : assetIds.length > 0;

  function toggleAsset(id: number, checked: boolean) {
    setAssetIds((prev) => (checked ? [...prev, id] : prev.filter((a) => a !== id)));
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    createScan.mutate(
      isInternal
        ? { type, asset_ids: assetIds, agent_id: Number(agentId) }
        : { type, asset_ids: assetIds },
      {
        onSuccess: () => {
          setOpen(false);
          setAssetIds([]);
          setAgentId("");
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
                ? "The chosen agent discovers live hosts on its network, then runs Nuclei and OpenVAS against them."
                : "Nuclei and OpenVAS will both run in parallel against the selected targets."}
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
                {isInternal ? "Pre-seed assets (optional)" : "Target assets"}
              </Label>
              {isInternal && (
                <p className="text-xs text-muted-foreground">
                  The agent discovers live hosts on its network automatically — pick assets here
                  only if you want to scan specific known hosts in addition to what it finds.
                </p>
              )}
              {assetsLoading ? (
                <Skeleton className="h-32 w-full" />
              ) : !assets || assets.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {isInternal
                    ? "No assets to pre-seed — that's fine, the agent will discover targets itself."
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

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Every scan runs Nuclei and OpenVAS as independent parallel engines."
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
                        <Button variant="outline" size="sm" render={<Link to={`/scans/${scan.id}`} />}>
                          View
                        </Button>
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
