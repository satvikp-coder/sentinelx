/**
 * Label chip: SIMULATED / RECORDED / LIVE / OBSERVED / INFERRED / VERIFIED.
 * Always shows the provenance label, never hides it.
 */

import React from "react";

interface LabelChipProps {
  label: string;
}

const STYLE: Record<string, string> = {
  SIMULATED: "bg-blue-100 text-blue-800",
  RECORDED: "bg-green-100 text-green-800",
  LIVE: "bg-purple-100 text-purple-800",
  OBSERVED: "bg-teal-100 text-teal-800",
  INFERRED: "bg-amber-100 text-amber-800",
  VERIFIED: "bg-emerald-100 text-emerald-800",
};

export function LabelChip({ label }: LabelChipProps) {
  const cls = STYLE[label] || "bg-gray-100 text-gray-800";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${cls} border-opacity-50`}>
      {label}
    </span>
  );
}
