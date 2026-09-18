import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { IdentityConfidence } from "@/lib/types";

const LABELS: Record<IdentityConfidence, string> = {
  mac: "MAC",
  hostname: "Hostname",
  ip: "IP only",
};

// Ordered by how safe it is to trust across a DHCP lease change — an
// IP-only match is the weakest signal (see app/routers/agents.py's
// discover-results matching logic) and is called out so a stale/duplicate
// asset is easy to spot.
const STYLES: Record<IdentityConfidence, string> = {
  mac: "bg-emerald-600 text-white dark:bg-emerald-500",
  hostname: "bg-blue-500 text-white dark:bg-blue-500",
  ip: "bg-slate-400 text-white dark:bg-slate-500",
};

export function IdentityBadge({ confidence }: { confidence: IdentityConfidence | null }) {
  if (!confidence) return <span className="text-muted-foreground">—</span>;
  return <Badge className={cn("border-transparent", STYLES[confidence])}>{LABELS[confidence]}</Badge>;
}
