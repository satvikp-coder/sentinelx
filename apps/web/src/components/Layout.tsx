/**
 * Layout shell: sidebar navigation + main content area.
 * Responsive: sidebar collapses on narrow screens.
 */

import React, { useState } from "react";
import { useApi } from "../contexts/ApiContext";
import { LabelChip } from "./LabelChip";

interface LayoutProps {
  children: React.ReactNode;
  currentScreen: string;
  onNavigate: (screen: string) => void;
}

const SCREENS: { id: string; label: string }[] = [
  { id: "mission-control", label: "Mission Control" },
  { id: "attack-lab", label: "Attack Lab" },
  { id: "paired-comparator", label: "Paired Run Comparator" },
  { id: "evidence-timeline", label: "Incident Evidence Timeline" },
  { id: "evcs-explorer", label: "EVCS Containment Explorer" },
  { id: "site-guard", label: "Site Guard Scanner" },
  { id: "fix-verification", label: "Fix Verification & Approval" },
  { id: "live-shield", label: "Live Shield" },
  { id: "escalation-inbox", label: "Escalation Inbox" },
  { id: "evaluation-metrics", label: "Evaluation Metrics & Reports" },
];

export function Layout({ children, currentScreen, onNavigate }: LayoutProps) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const { health, healthLoading, healthError } = useApi();

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar (desktop) */}
      {!sidebarOpen ? null : (
        <aside className="hidden md:flex flex-col w-64 bg-white border-r border-gray-200">
          <div className="p-4 border-b border-gray-200">
            <h1 className="text-xl font-bold text-gray-900">Sentinel X</h1>
            <p className="text-xs text-gray-500 mt-1">Mission Control</p>
          </div>
          <nav className="flex-1 overflow-y-auto p-2 space-y-1">
            {SCREENS.map((s) => {
              const active = currentScreen === s.id;
              return (
                <button
                  key={s.id}
                  onClick={() => onNavigate(s.id)}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    active
                      ? "bg-blue-50 text-blue-700 font-medium border border-blue-100"
                      : "text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                  }`}
                >
                  {s.label}
                </button>
              );
            })}
          </nav>
          <div className="p-4 border-t border-gray-200">
            <div className="text-xs text-gray-500 mb-2">Backend status</div>
            {healthLoading ? (
              <div className="text-xs text-gray-400">loading...</div>
            ) : healthError ? (
              <div className="text-xs text-red-600">{healthError}</div>
            ) : (
              <div className="flex items-center gap-2 text-xs">
                <span
                  className={`inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium ${
                    health?.status === "ok" ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"
                  }`}
                >
                  {health?.status}
                </span>
                <span>{health?.mode ?? "unknown"}</span>
                <LabelChip label={health?.mode ?? "unknown"} />
              </div>
            )}
          </div>
        </aside>
      )}
      {/* Mobile sidebar toggle */}
      {sidebarOpen && (
        <button className="md:hidden p-3 text-gray-600 hover:bg-gray-100" onClick={() => setSidebarOpen(false)}>
          <span className="sr-only">Close sidebar</span>
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
      )}
      {!sidebarOpen && (
        <button className="md:hidden p-3 text-gray-600 hover:bg-gray-100 absolute top-4 left-4 z-50" onClick={() => setSidebarOpen(true)}>
          <span className="sr-only">Open sidebar</span>
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
      )}
      {/* Main content */}
      <main className="flex-1 overflow-y-auto bg-gray-50 p-6 md:p-8">
        {children}
      </main>
    </div>
  );
}
