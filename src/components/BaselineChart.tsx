import type { ActivityLog, AgentBaseline, AgentProfile } from '../types/agentguard';

interface BaselineChartProps {
  agent: AgentProfile;
  baseline?: AgentBaseline;
  logs: ActivityLog[];
}

export function BaselineChart({ agent, baseline, logs }: BaselineChartProps) {
  const agentLogs = logs
    .filter((l) => l.agentId === agent.id)
    .slice(0, 14)
    .reverse();

  const width = 620;
  const height = 220;
  const padLeft = 42;
  const padRight = 18;
  const padTop = 20;
  const padBottom = 32;
  const innerW = width - padLeft - padRight;
  const innerH = height - padTop - padBottom;

  const upperBound = baseline?.hourlyVolumeRange.upperBound ?? agent.maxActionsPerHour * 0.7;
  const lowerBound = baseline?.hourlyVolumeRange.lowerBound ?? 0;
  const mean = baseline?.hourlyVolumeRange.mean ?? agent.maxActionsPerHour * 0.4;

  const maxLogVol = agentLogs.reduce((m, l) => Math.max(m, l.volume), 0);
  const yMax = Math.max(upperBound * 1.25, maxLogVol * 1.15, agent.maxActionsPerHour * 1.1, 30);

  const yFor = (val: number) => padTop + innerH - (val / yMax) * innerH;
  const bandTop = yFor(upperBound);
  const bandBottom = yFor(lowerBound);
  const meanY = yFor(mean);
  const capY = yFor(agent.maxActionsPerHour);

  const barGap = agentLogs.length > 0 ? innerW / agentLogs.length : innerW;
  const barWidth = Math.max(10, Math.min(26, barGap * 0.56));

  const actionTotals = Object.entries(baseline?.actionDistribution ?? {}).sort(
    (a, b) => b[1] - a[1]
  );
  const totalActions = actionTotals.reduce((sum, [, count]) => sum + count, 0) || 1;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
        <div>
          <span className="font-medium text-slate-200">{agent.name}</span>
          <span className="mx-2 text-slate-600">·</span>
          <span>
            Baseline range:{' '}
            <span className="font-mono text-slate-200 tabular-nums">
              {lowerBound.toFixed(1)}–{upperBound.toFixed(1)}
            </span>{' '}
            req/hr (mean {mean.toFixed(1)} ± {baseline?.hourlyVolumeRange.k ?? 2.5}σ)
          </span>
        </div>
        <div className="flex items-center gap-4 text-[11px]">
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-xs bg-sky-500/25 border border-sky-500/50" />
            Learned Normal Band
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-0.5 w-3 bg-slate-400" />
            Max Policy Cap ({agent.maxActionsPerHour})
          </span>
        </div>
      </div>

      {agentLogs.length === 0 ? (
        <div className="flex h-[200px] items-center justify-center rounded-lg border border-slate-800/80 bg-[#0D131F] text-xs text-slate-400">
          No recent activity events recorded for this agent yet.
        </div>
      ) : (
        <div className="w-full overflow-x-auto">
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="w-full min-w-[420px] h-auto"
            role="img"
            aria-label={`Baseline versus current volume chart for ${agent.name}`}
          >
            {/* Horizontal grid lines */}
            {[0, 0.25, 0.5, 0.75, 1].map((t) => {
              const val = Math.round(yMax * t);
              const y = yFor(val);
              return (
                <g key={t}>
                  <line
                    x1={padLeft}
                    y1={y}
                    x2={width - padRight}
                    y2={y}
                    stroke="#1E293B"
                    strokeDasharray="2 3"
                  />
                  <text
                    x={padLeft - 8}
                    y={y + 3}
                    textAnchor="end"
                    className="fill-slate-500 font-mono text-[10px]"
                  >
                    {val}
                  </text>
                </g>
              );
            })}

            {/* Baseline range band (mean ± k*std) */}
            <rect
              x={padLeft}
              y={bandTop}
              width={innerW}
              height={Math.max(2, bandBottom - bandTop)}
              fill="#0EA5E9"
              fillOpacity={0.12}
            />
            <line
              x1={padLeft}
              y1={meanY}
              x2={width - padRight}
              y2={meanY}
              stroke="#38BDF8"
              strokeWidth={1.25}
              strokeDasharray="4 3"
            />

            {/* Hard maxActionsPerHour policy line */}
            {agent.maxActionsPerHour <= yMax && (
              <line
                x1={padLeft}
                y1={capY}
                x2={width - padRight}
                y2={capY}
                stroke="#64748B"
                strokeWidth={1}
                strokeDasharray="2 2"
              />
            )}

            {/* Activity bars */}
            {agentLogs.map((log, idx) => {
              const xCenter = padLeft + idx * barGap + barGap / 2;
              const x = xCenter - barWidth / 2;
              const y = yFor(log.volume);
              const barH = Math.max(3, padTop + innerH - y);
              const color =
                log.analysis.severity === 'Critical'
                  ? '#EF4444'
                  : log.analysis.severity === 'Warning' || log.analysis.severity === 'Confirm'
                    ? '#F59E0B'
                    : '#10B981';

              const timeLabel = new Date(log.timestamp).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
              });

              return (
                <g key={log.id}>
                  <rect
                    x={x}
                    y={y}
                    width={barWidth}
                    height={barH}
                    rx={3}
                    fill={color}
                    fillOpacity={0.85}
                  >
                    <title>
                      {`${log.action} · ${log.volume} req/hr · Risk ${log.analysis.riskScore} (${log.analysis.classification})`}
                    </title>
                  </rect>
                  <text
                    x={xCenter}
                    y={y - 5}
                    textAnchor="middle"
                    className="fill-slate-300 font-mono text-[9px]"
                  >
                    {log.volume}
                  </text>
                  {(idx % 2 === 0 || agentLogs.length <= 8) && (
                    <text
                      x={xCenter}
                      y={height - 10}
                      textAnchor="middle"
                      className="fill-slate-500 font-mono text-[9px]"
                    >
                      {timeLabel}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      )}

      {/* Learned Baseline Action Distribution */}
      <div className="border-t border-slate-800/80 pt-3">
        <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
          <span>Learned Baseline Action Distribution</span>
          <span className="font-mono tabular-nums text-slate-300">
            {baseline?.learnedCount ?? 0} normal samples
          </span>
        </div>
        {actionTotals.length === 0 ? (
          <p className="text-xs text-slate-500">Baseline collecting initial normal observations…</p>
        ) : (
          <div className="space-y-1.5">
            {actionTotals.slice(0, 4).map(([action, count]) => {
              const pct = Math.round((count / totalActions) * 100);
              return (
                <div key={action} className="flex items-center gap-3 text-xs">
                  <span className="w-40 truncate font-mono text-slate-300">{action}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full rounded-full bg-sky-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="w-10 text-right font-mono tabular-nums text-slate-400">
                    {pct}%
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
