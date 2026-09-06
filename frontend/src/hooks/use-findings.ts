import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";

export function useFindings(params: {
  scan_id?: number;
  asset_id?: number;
  engine?: string;
  severity?: string;
}) {
  return useQuery({
    queryKey: ["findings", params],
    queryFn: () => api.listFindings(params),
  });
}
