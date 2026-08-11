/**
 * Packets-per-second line chart.
 *
 * Reads from persisted statistics snapshots rather than live counters: live
 * values reset when the sensor restarts, so a chart built on them would lose
 * its history on every deploy.
 */
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { StatisticsPoint } from "../api/types";
import { Empty } from "./States";

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function PpsChart({ points }: { points: StatisticsPoint[] }) {
  if (points.length === 0) {
    return (
      <Empty message="No statistics recorded yet. Snapshots appear once the sensor has been running." />
    );
  }

  const data = points.map((point) => ({
    time: formatTime(point.captured_at),
    pps: Math.round(point.packets_per_second),
  }));

  return (
    <div style={{ width: "100%", height: 200 }}>
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="time"
            tick={{ fill: "var(--text-muted)", fontSize: 11 }}
            stroke="var(--border)"
            minTickGap={24}
          />
          <YAxis
            tick={{ fill: "var(--text-muted)", fontSize: 11 }}
            stroke="var(--border)"
            width={52}
          />
          <Tooltip
            contentStyle={{
              background: "var(--surface-raised)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              color: "var(--text)",
              fontSize: "0.85rem",
            }}
            labelStyle={{ color: "var(--text-muted)" }}
            formatter={(value: number) => [value.toLocaleString(), "Packets/sec"]}
          />
          <Area
            type="monotone"
            dataKey="pps"
            stroke="var(--accent)"
            strokeWidth={2}
            fill="var(--accent)"
            fillOpacity={0.12}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
