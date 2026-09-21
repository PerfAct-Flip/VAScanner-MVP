import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { ReportCreate } from "@/lib/types";

export function useReports(scanId?: number) {
  return useQuery({
    queryKey: ["reports", scanId ?? "all"],
    queryFn: () => api.listReports(scanId),
  });
}

export function useGenerateReport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ReportCreate) => api.generateReport(payload),
    onSuccess: (report) => {
      queryClient.invalidateQueries({ queryKey: ["reports", report.scan_id ?? "all"] });
      toast.success(`${report.format.toUpperCase()} report generated`);
    },
    onError: (err: Error) => toast.error(`Failed to generate report: ${err.message}`),
  });
}

export function useDeleteReport(scanId?: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteReport(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports", scanId ?? "all"] });
      toast.success("Report deleted");
    },
    onError: (err: Error) => toast.error(`Failed to delete report: ${err.message}`),
  });
}
