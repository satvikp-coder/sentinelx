/**
 * Metric card showing numerator/denominator with a simple bar.
 * Never invents metrics - only displays what the backend provides.
 */

import React from "react";
import { Metric } from "../api";

interface MetricCardProps {
  metric: Metric;
  labelSuffix?: string;
}

export function MetricCard({ metric, labelSuffix }: MetricCardProps) {
  const pct = metric.denominator > 0 ? metric.numerator / metric.denominator : 0;
  const width = Math.min(100, Math.max(0, pct * 100));
  const value = metric.value != null ? metric.value.toFixed(3) : "n/a";

  return (
    <div className="border rounded-lg p-3 bg-white">
      <div className="flex justify-between items-start mb-1">
        <h3 className="text-sm font-semibold text-gray-800">{metric.name}</h3>
        {labelSuffix && (
          <span className="text-xs text-gray-500">{labelSuffix}</span>
        )}
      </div>
      <div className="text-lg font-mono font-bold text-gray-900">
        {metric.numerator}/{metric.denominator}
      </div>
      <div className="text-xs text-gray-500 mt-1">
        value: {value}
      </div>
      <div className="w-full bg-gray-100 rounded h-1.5 mt-2">
        <div
          className="bg-blue-600 h-1.5 rounded"
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  );
}
