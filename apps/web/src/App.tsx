/**
 * Sentinel X Mission Control - Main App.
 *
 * Connects to the actual local /api/v1 backend. Never invents dashboard metrics.
 * Shows SIMULATED/RECORDED/LIVE labels on all data.
 */

import React, { useState } from "react";
import { ApiProvider, useApi } from "./contexts/ApiContext";
import { Layout } from "./components/Layout";
import { MissionControl } from "./screens/MissionControl";
import { AttackLab } from "./screens/AttackLab";
import { PairedRunComparator } from "./screens/PairedRunComparator";
import { IncidentEvidenceTimeline } from "./screens/IncidentEvidenceTimeline";
import { EVCSContainmentExplorer } from "./screens/EVCSContainmentExplorer";
import { SiteGuardScanner } from "./screens/SiteGuardScanner";
import { FixVerification } from "./screens/FixVerification";
import { LiveShield } from "./screens/LiveShield";
import { EscalationInbox } from "./screens/EscalationInbox";
import { EvaluationMetrics } from "./screens/EvaluationMetrics";

type ScreenId =
  | "mission-control"
  | "attack-lab"
  | "paired-comparator"
  | "evidence-timeline"
  | "evcs-explorer"
  | "site-guard"
  | "fix-verification"
  | "live-shield"
  | "escalation-inbox"
  | "evaluation-metrics";

const SCREEN_COMPONENTS: Record<ScreenId, React.ComponentType> = {
  "mission-control": MissionControl,
  "attack-lab": AttackLab,
  "paired-comparator": PairedRunComparator,
  "evidence-timeline": IncidentEvidenceTimeline,
  "evcs-explorer": EVCSContainmentExplorer,
  "site-guard": SiteGuardScanner,
  "fix-verification": FixVerification,
  "live-shield": LiveShield,
  "escalation-inbox": EscalationInbox,
  "evaluation-metrics": EvaluationMetrics,
};

function AppInner() {
  const [currentScreen, setCurrentScreen] = useState<ScreenId>("mission-control");
  const { healthError } = useApi();

  if (healthError) {
    return (
      <div className="p-6 bg-red-50 border border-red-100 rounded-lg">
        <h2 className="text-lg font-bold text-red-800">Backend Unavailable</h2>
        <p className="text-red-700">{healthError}</p>
        <p className="text-sm text-red-600 mt-2">
          Make sure the Sentinel X API is running on http://127.0.0.1:8080
        </p>
      </div>
    );
  }

  const Screen = SCREEN_COMPONENTS[currentScreen as keyof typeof SCREEN_COMPONENTS];

  return (
    <Layout currentScreen={currentScreen} onNavigate={(s) => setCurrentScreen(s as ScreenId)}>
      <Screen />
    </Layout>
  );
}

export default function App() {
  return (
    <ApiProvider>
      <AppInner />
    </ApiProvider>
  );
}
