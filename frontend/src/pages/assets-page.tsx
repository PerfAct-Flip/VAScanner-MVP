import { Plus, Trash2 } from "lucide-react";
import { type FormEvent, useState } from "react";

import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAssets, useCreateAsset, useDeleteAsset } from "@/hooks/use-assets";
import type { AssetCreate } from "@/lib/types";

const CRITICALITY_OPTIONS = ["Critical", "High", "Medium", "Low"];
const ENVIRONMENT_OPTIONS = ["production", "staging", "development", "internal"];

function AddAssetDialog() {
  const [open, setOpen] = useState(false);
  const createAsset = useCreateAsset();
  const [form, setForm] = useState<AssetCreate>({
    hostname: "",
    ip_address: "",
    environment: "",
    criticality: "",
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!form.hostname && !form.ip_address) return;
    createAsset.mutate(
      {
        hostname: form.hostname || undefined,
        ip_address: form.ip_address || undefined,
        environment: form.environment || undefined,
        criticality: form.criticality || undefined,
      },
      {
        onSuccess: () => {
          setOpen(false);
          setForm({ hostname: "", ip_address: "", environment: "", criticality: "" });
        },
      },
    );
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button />}>
        <Plus className="size-4" />
        Add asset
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>Add asset</DialogTitle>
            <DialogDescription>
              Provide at least a hostname or an IP address.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="hostname">Hostname</Label>
              <Input
                id="hostname"
                placeholder="web01.example.com"
                value={form.hostname}
                onChange={(e) => setForm((f) => ({ ...f, hostname: e.target.value }))}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="ip">IP address</Label>
              <Input
                id="ip"
                placeholder="10.0.1.15"
                value={form.ip_address}
                onChange={(e) => setForm((f) => ({ ...f, ip_address: e.target.value }))}
              />
            </div>
            <div className="grid gap-2">
              <Label>Environment</Label>
              <Select
                value={form.environment}
                onValueChange={(v) => setForm((f) => ({ ...f, environment: v ?? undefined }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select environment" />
                </SelectTrigger>
                <SelectContent>
                  {ENVIRONMENT_OPTIONS.map((env) => (
                    <SelectItem key={env} value={env}>
                      {env}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label>Criticality</Label>
              <Select
                value={form.criticality}
                onValueChange={(v) => setForm((f) => ({ ...f, criticality: v ?? undefined }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select criticality" />
                </SelectTrigger>
                <SelectContent>
                  {CRITICALITY_OPTIONS.map((c) => (
                    <SelectItem key={c} value={c}>
                      {c}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="submit"
              disabled={createAsset.isPending || (!form.hostname && !form.ip_address)}
            >
              {createAsset.isPending ? "Adding…" : "Add asset"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function AssetsPage() {
  const { data: assets, isLoading } = useAssets();
  const deleteAsset = useDeleteAsset();

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Inventory of hosts available as scan targets."
        action={<AddAssetDialog />}
      />

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="space-y-2 p-6">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : !assets || assets.length === 0 ? (
            <div className="p-10 text-center text-sm text-muted-foreground">
              No assets yet. Add your first asset to start scanning.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Hostname</TableHead>
                  <TableHead>IP address</TableHead>
                  <TableHead>Environment</TableHead>
                  <TableHead>Criticality</TableHead>
                  <TableHead>Added</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((asset) => (
                  <TableRow key={asset.id}>
                    <TableCell className="text-muted-foreground">{asset.id}</TableCell>
                    <TableCell className="font-medium">{asset.hostname ?? "—"}</TableCell>
                    <TableCell>{asset.ip_address ?? "—"}</TableCell>
                    <TableCell className="capitalize">{asset.environment ?? "—"}</TableCell>
                    <TableCell>{asset.criticality ?? "—"}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(asset.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => deleteAsset.mutate(asset.id)}
                        disabled={deleteAsset.isPending}
                      >
                        <Trash2 className="size-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
