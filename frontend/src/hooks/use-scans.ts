import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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

export function useScanFindings(id: number) {
  return useQuery({
    queryKey: ["scans", id, "findings"],
    queryFn: () => api.getScanFindings(id),
    enabled: Number.isFinite(id),
  });
}

export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ScanCreate) => api.createScan(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      toast.success("Scan started — Nuclei and OpenVAS are now running in parallel");
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
