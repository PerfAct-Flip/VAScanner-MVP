// Matches SeverityBadge's existing Tailwind mapping so charts and badges read
// as the same visual language, rather than introducing a second palette for
// the same concept.
export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"] as const;

export const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#dc2626", // red-600
  High: "#f97316", // orange-500
  Medium: "#eab308", // yellow-500
  Low: "#3b82f6", // blue-500
  Informational: "#94a3b8", // slate-400
};

// Status palette (state, not identity) — from the dataviz skill's validated
// reference palette; kept distinct from SEVERITY_COLORS and CATEGORICAL_COLORS
// so a status color never doubles as a series color.
export const STATUS_COLORS = {
  good: "#0ca30c",
  warning: "#fab219",
  serious: "#ec835a",
  critical: "#d03b3b",
  neutral: "#94a3b8",
} as const;

// Categorical palette (identity, e.g. engine or scan type) — first three slots
// of the dataviz skill's validated default palette, which is the subset that
// clears the CVD/normal-vision floor for every pairing (not just adjacent),
// safe for pie/donut charts.
export const CATEGORICAL_COLORS = ["#2a78d6", "#eb6834", "#1baf7a"];

export const NEUTRAL_COLOR = "#c3c2b7";

export function scanStatusColor(status: string): string {
  switch (status) {
    case "completed":
      return STATUS_COLORS.good;
    case "running":
      return STATUS_COLORS.warning;
    case "failed":
      return STATUS_COLORS.critical;
    case "canceled":
      return NEUTRAL_COLOR;
    default:
      return STATUS_COLORS.neutral; // queued
  }
}
