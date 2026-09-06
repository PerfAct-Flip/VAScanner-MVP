import { Route, Routes } from "react-router-dom";
import { Toaster } from "sonner";

import { AppShell } from "@/components/layout/app-shell";
import { AgentsPage } from "@/pages/agents-page";
import { AssetsPage } from "@/pages/assets-page";
import { DashboardPage } from "@/pages/dashboard-page";
import { FindingsPage } from "@/pages/findings-page";
import { ScanDetailPage } from "@/pages/scan-detail-page";
import { ScansPage } from "@/pages/scans-page";

function App() {
  return (
    <>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:id" element={<ScanDetailPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="agents" element={<AgentsPage />} />
        </Route>
      </Routes>
      <Toaster richColors position="top-right" />
    </>
  );
}

export default App;
