import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";

export function useAgents() {
  return useQuery({
    queryKey: ["agents"],
    queryFn: api.listAgents,
    refetchInterval: 15000,
  });
}
