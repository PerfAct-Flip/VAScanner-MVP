import type { TooltipContentProps } from "recharts/types/component/Tooltip";
import type { NameType, ValueType } from "recharts/types/component/DefaultTooltipContent";

export function ChartTooltip({ active, payload, label }: TooltipContentProps<ValueType, NameType>) {
  if (!active || !payload || payload.length === 0) return null;

  return (
    <div className="rounded-lg border bg-popover px-3 py-2 text-sm shadow-md">
      {label !== undefined && <div className="mb-1 font-medium text-popover-foreground">{label}</div>}
      <div className="space-y-0.5">
        {payload.map((entry) => (
          <div key={entry.name} className="flex items-center gap-2 text-muted-foreground">
            <span className="size-2 rounded-full" style={{ backgroundColor: entry.color }} />
            <span>{entry.name}:</span>
            <span className="font-medium text-popover-foreground">{entry.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
