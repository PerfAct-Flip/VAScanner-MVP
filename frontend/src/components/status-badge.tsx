import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STATUS_STYLES: Record<string, string> = {
  queued: "bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100",
  running: "bg-blue-500 text-white dark:bg-blue-500",
  completed: "bg-green-600 text-white dark:bg-green-600",
  failed: "bg-red-600 text-white dark:bg-red-500",
  canceled: "bg-slate-500 text-white dark:bg-slate-600",
};

function label(status: string) {
  return status
    .split("_")
    .map((w) => w[0]?.toUpperCase() + w.slice(1))
    .join(" ");
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <Badge className={cn("border-transparent capitalize", STATUS_STYLES[status] ?? "bg-muted text-foreground")}>
      {label(status)}
    </Badge>
  );
}
