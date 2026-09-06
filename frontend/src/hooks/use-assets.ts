import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api } from "@/lib/api";
import type { AssetCreate } from "@/lib/types";

export function useAssets() {
  return useQuery({
    queryKey: ["assets"],
    queryFn: api.listAssets,
  });
}

export function useCreateAsset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: AssetCreate) => api.createAsset(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      toast.success("Asset added");
    },
    onError: (err: Error) => toast.error(`Failed to add asset: ${err.message}`),
  });
}

export function useDeleteAsset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteAsset(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      toast.success("Asset deleted");
    },
    onError: (err: Error) => toast.error(`Failed to delete asset: ${err.message}`),
  });
}
