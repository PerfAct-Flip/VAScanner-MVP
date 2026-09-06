import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-red-600 text-white dark:bg-red-500",
  High: "bg-orange-500 text-white dark:bg-orange-500",
  Medium: "bg-yellow-500 text-black dark:bg-yellow-500",
  Low: "bg-blue-500 text-white dark:bg-blue-500",
  Informational: "bg-slate-400 text-white dark:bg-slate-500",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge className={cn("border-transparent", SEVERITY_STYLES[severity] ?? "bg-muted text-foreground")}>
      {severity}
    </Badge>
  );
}
