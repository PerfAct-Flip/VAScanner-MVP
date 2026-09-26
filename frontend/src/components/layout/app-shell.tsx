import {
  FileText,
  LayoutDashboard,
  LineChart,
  ListChecks,
  Radar,
  ScanLine,
  Server,
  ShieldAlert,
} from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";

import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/scans", label: "Scans", icon: ScanLine },
  { to: "/findings", label: "Findings", icon: ListChecks },
  { to: "/insights", label: "Insights", icon: LineChart },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/agents", label: "Agents", icon: Radar },
];

export function AppShell() {
  return (
    <div className="flex min-h-screen w-full bg-muted/30">
      <aside className="hidden w-60 shrink-0 border-r bg-background md:flex md:flex-col">
        <div className="flex items-center gap-2 border-b px-6 py-5">
          <ShieldAlert className="size-6 text-primary" />
          <span className="text-lg font-semibold tracking-tight">Vuln Scanner</span>
        </div>
        <nav className="flex flex-1 flex-col gap-1 p-3">
          {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                )
              }
            >
              <Icon className="size-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t p-4 text-xs text-muted-foreground">
          Choose which engines run per scan — Discovery, Nuclei, and OpenVAS/SSH Audit.
        </div>
      </aside>

      <div className="flex min-h-screen flex-1 flex-col">
        <header className="flex items-center justify-between border-b bg-background px-4 py-3 md:hidden">
          <div className="flex items-center gap-2">
            <ShieldAlert className="size-5 text-primary" />
            <span className="font-semibold">Vuln Scanner</span>
          </div>
        </header>
        <main className="flex-1 p-4 md:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
