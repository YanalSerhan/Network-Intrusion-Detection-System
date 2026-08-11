/**
 * Application shell: routing and layout.
 *
 * Routes are declared here rather than scattered so the navigable surface of
 * the dashboard is readable in one place.
 */
import { Navigate, Route, Routes } from "react-router-dom";

import { Layout } from "./components/Layout";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { AlertsPage } from "./pages/AlertsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RulesPage } from "./pages/RulesPage";

export function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="/rules" element={<RulesPage />} />
        {/* Unknown paths return to the overview rather than a blank screen. */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
