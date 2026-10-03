import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { ScanCreate } from "@/lib/types";

const isActive = (status: string) => status === "queued" || status === "running";

export function useScans() {
  return useQuery({
    queryKey: ["scans"],
    queryFn: api.listScans,
    refetchInterval: (query) => {
      const scans = query.state.data;
      return scans?.some((s) => isActive(s.status)) ? 4000 : false;
    },
  });
}

export function useScan(id: number) {
  return useQuery({
    queryKey: ["scans", id],
    queryFn: () => api.getScan(id),
    enabled: Number.isFinite(id),
    refetchInterval: (query) => (query.state.data && isActive(query.state.data.status) ? 3000 : false),
  });
}

export function useScanStatus(id: number) {
  return useQuery({
    queryKey: ["scans", id, "status"],
    queryFn: () => api.getScanStatus(id),
    enabled: Number.isFinite(id),
    refetchInterval: (query) => (query.state.data && isActive(query.state.data.overall_status) ? 3000 : false),
  });
}

export function useScanFindings(id: number, scanStatus?: string) {
  const queryClient = useQueryClient();
  // Findings only show up once a scan finishes, but this query had no
  // polling at all — a scan completing while the detail page was open
  // never refreshed it, so the only way to see results was a manual
  // reload. Poll alongside the scan's own status while it's active; once
  // it goes terminal, fire one last refetch to catch the final batch of
  // findings that may have been written just before the status flipped
  // (polling stops the instant isActive goes false, so without this the
  // very last write could still be missed).
  const wasActive = useRef(false);
  useEffect(() => {
    const active = !!scanStatus && isActive(scanStatus);
    if (!active && wasActive.current) {
      queryClient.invalidateQueries({ queryKey: ["scans", id, "findings"] });
    }
    wasActive.current = active;
  }, [scanStatus, id, queryClient]);

  return useQuery({
    queryKey: ["scans", id, "findings"],
    queryFn: () => api.getScanFindings(id),
    enabled: Number.isFinite(id),
    refetchInterval: scanStatus && isActive(scanStatus) ? 4000 : false,
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ScanCreate) => api.createScan(payload),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      toast.success("Scan started");
      // Non-fatal heads-up (e.g. a target doesn't resolve via DNS, or
      // OpenVAS was skipped for lack of a credential) — the scan still
      // runs, this is just visibility, not an error.
      for (const warning of scan.warnings ?? []) {
        toast.warning(warning);
      }
    },
    onError: (err: Error) => toast.error(`Failed to start scan: ${err.message}`),
  });
}

export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.cancelScan(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      queryClient.invalidateQueries({ queryKey: ["scans", id] });
      toast.success("Scan canceled");
    },
    onError: (err: Error) => toast.error(`Failed to cancel scan: ${err.message}`),
  });
}

export function useRetryScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.retryScan(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      queryClient.invalidateQueries({ queryKey: ["scans", id] });
      toast.success("Retrying failed engine(s)");
    },
    onError: (err: Error) => toast.error(`Failed to retry scan: ${err.message}`),
  });
}
