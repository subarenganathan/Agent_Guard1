import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import type {
  ActivityLog,
  AgentBaseline,
  AgentProfile,
  AgentStatus,
  AttackScenario,
  NotificationChannel,
  OwnerAlert,
} from '../types/agentguard';
import { BaselineChart } from './BaselineChart';
import { RiskGauge } from './RiskGauge';
import { SimulatedAlertCard } from './SimulatedAlertCard';

interface OverviewViewProps {
  agents: AgentProfile[];
  baselines: Record<string, AgentBaseline>;
  logs: ActivityLog[];
  alerts: OwnerAlert[];
  channel: NotificationChannel;
  onChangeChannel: (ch: NotificationChannel) => void;
  onSimulate: (agentId: string, scenario: AttackScenario) => Promise<void>;
  onUpdateAgentStatus: (agentId: string, status: AgentStatus) => Promise<void>;
  onResolveAlert: (alertId: string, action: 'confirm_mine' | 'pause_agent' | 'revoke_token') => Promise<void>;
  onResetDemo: () => Promise<void>;
  busyAction: string | null;
}

export function OverviewView({
  agents,
  baselines,
  logs,
  alerts,
  channel,
  onChangeChannel,
  onSimulate,
  onUpdateAgentStatus,
  onResolveAlert,
  onResetDemo,
  busyAction,
}: OverviewViewProps) {
  const [selectedAgentId, setSelectedAgentId] = useState<string>(agents[0]?.id ?? '');
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  const selectedAgent = agents.find((a) => a.id === selectedAgentId) ?? agents[0];
  const openAlerts = alerts.filter((a) => a.status === 'Open');
  const featuredAlert = openAlerts[0] ?? alerts[0] ?? null;

  const activeCount = agents.filter((a) => a.status === 'Active').length;
  const meanRisk =
    agents.length > 0
      ? Math.round(agents.reduce((sum, a) => sum + a.riskScore, 0) / agents.length)
      : 0;

  return (
    <div className="space-y-6">
      {/* Page Header & Quick Simulation Toolbar */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 text-balance">
            Delegated AI Agent Security Overview
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Real-time 24/7 behavioral baselines correlated with your Owner Change Log.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onResetDemo}
            disabled={busyAction === 'reset'}
            className="rounded-lg border border-slate-700 bg-[#111827] px-3 py-2 text-xs font-medium text-slate-300 transition-colors hover:border-slate-600 hover:text-slate-100 disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            Reset Demo Data
          </button>
        </div>
      </div>

      {/* 4-Column Summary Metric Strip (Single-Elevation, Hairline Dividers) */}
      <div className="grid grid-cols-2 divide-y divide-slate-800 rounded-xl border border-slate-800 bg-[#111827] sm:grid-cols-4 sm:divide-x sm:divide-y-0">
        <div className="p-4 sm:p-5">
          <div className="text-xs text-slate-400">Active Agents</div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-slate-100">
              {activeCount}
            </span>
            <span className="text-xs text-slate-500">of {agents.length} registered</span>
          </div>
        </div>
        <div className="p-4 sm:p-5">
          <div className="text-xs text-slate-400">Open Owner Alerts</div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span
              className={`font-mono text-2xl font-semibold tabular-nums ${
                openAlerts.length > 0 ? 'text-amber-400' : 'text-emerald-400'
              }`}
            >
              {openAlerts.length}
            </span>
            <span className="text-xs text-slate-500">{alerts.length} total logged</span>
          </div>
        </div>
        <div className="p-4 sm:p-5">
          <div className="text-xs text-slate-400">Events Analyzed</div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-semibold tabular-nums text-slate-100">
              {logs.length}
            </span>
            <span className="text-xs text-slate-500">24/7 stream</span>
          </div>
        </div>
        <div className="p-4 sm:p-5">
          <div className="text-xs text-slate-400">Fleet Mean Risk</div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span
              className={`font-mono text-2xl font-semibold tabular-nums ${
                meanRisk >= 70
                  ? 'text-red-400'
                  : meanRisk >= 36
                    ? 'text-amber-400'
                    : 'text-emerald-400'
              }`}
            >
              {meanRisk}
            </span>
            <span className="text-xs text-slate-500">/ 100 score</span>
          </div>
        </div>
      </div>

      {/* Quick Attack Injector Strip */}
      {selectedAgent && (
        <div className="rounded-xl border border-slate-800 bg-[#111827] p-4 sm:p-5">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="overview-sim-agent" className="text-xs font-medium text-slate-300">
                Simulate activity for:
              </label>
              <select
                id="overview-sim-agent"
                value={selectedAgent.id}
                onChange={(e) => setSelectedAgentId(e.target.value)}
                className="rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-1.5 text-xs font-medium text-slate-100 focus:border-sky-500 focus:outline-none"
              >
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.platform} · {a.status})
                  </option>
                ))}
              </select>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {(
                [
                  { id: 'normal', label: 'Normal Event', tone: 'neutral' },
                  { id: 'stolen_token', label: 'Inject Stolen Token', tone: 'danger' },
                  { id: 'prompt_injection', label: 'Inject Prompt Hijack', tone: 'danger' },
                  { id: 'scope_creep', label: 'Inject Scope Creep', tone: 'warn' },
                  { id: 'burst_exfiltration', label: 'Inject Burst Read', tone: 'danger' },
                  { id: 'owner_approved_shift', label: 'Approved Change Shift', tone: 'accent' },
                ] as const
              ).map((btn) => {
                const isBusy = busyAction === `sim_${btn.id}`;
                const toneCls =
                  btn.tone === 'danger'
                    ? 'border-red-500/35 bg-red-500/10 text-red-300 hover:bg-red-500/20'
                    : btn.tone === 'warn'
                      ? 'border-amber-500/35 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20'
                      : btn.tone === 'accent'
                        ? 'border-sky-500/35 bg-sky-500/10 text-sky-300 hover:bg-sky-500/20'
                        : 'border-slate-700 bg-[#0B0F17] text-slate-200 hover:border-slate-600';

                return (
                  <button
                    key={btn.id}
                    type="button"
                    disabled={busyAction !== null || selectedAgent.status !== 'Active'}
                    onClick={() => onSimulate(selectedAgent.id, btn.id)}
                    className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-45 whitespace-nowrap shrink-0 ${toneCls}`}
                  >
                    {isBusy ? 'Running…' : btn.label}
                  </button>
                );
              })}
            </div>
          </div>
          {selectedAgent.status !== 'Active' && (
            <p className="mt-2.5 text-xs text-amber-400">
              {selectedAgent.name} is currently {selectedAgent.status}. Reactivate it below to run new simulations.
            </p>
          )}
        </div>
      )}

      {/* Agent Risk Score Gauges */}
      <section aria-labelledby="agent-fleet-heading" className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 id="agent-fleet-heading" className="text-base font-semibold text-slate-100">
            Monitored AI Agents
          </h2>
          <span className="text-xs text-slate-400">
            Click any agent card to inspect its baseline chart
          </span>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {agents.map((agent) => {
            const isSelected = selectedAgent?.id === agent.id;
            const baseline = baselines[agent.id];
            const statusColor =
              agent.status === 'Active'
                ? 'text-emerald-400'
                : agent.status === 'Paused'
                  ? 'text-amber-400'
                  : 'text-red-400';

            return (
              <div
                key={agent.id}
                onClick={() => setSelectedAgentId(agent.id)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelectedAgentId(agent.id);
                  }
                }}
                className={`cursor-pointer rounded-xl border p-5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 ${
                  isSelected
                    ? 'border-sky-500/60 bg-[#141D2F]'
                    : 'border-slate-800 bg-[#111827] hover:border-slate-700'
                }`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-slate-100 truncate">
                      {agent.name}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-slate-400">
                      <span>{agent.platform}</span>
                      <span aria-hidden="true">·</span>
                      <span className={`font-medium ${statusColor}`}>
                        Status: {agent.status}
                      </span>
                    </div>
                    <p className="mt-2 text-xs leading-relaxed text-slate-400 line-clamp-2">
                      {agent.purpose}
                    </p>
                  </div>
                  <RiskGauge score={agent.riskScore} />
                </div>

                <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/80 pt-3 text-xs text-slate-400">
                  <span className="font-mono text-[11px] text-slate-400 truncate max-w-[180px]">
                    {agent.tokenId}
                  </span>
                  <span className="font-mono tabular-nums text-[11px]">
                    {baseline?.learnedCount ?? 0} samples · cap {agent.maxActionsPerHour}/hr
                  </span>
                </div>

                <div
                  className="mt-3 flex items-center gap-2"
                  onClick={(e) => e.stopPropagation()}
                >
                  {agent.status === 'Active' ? (
                    <>
                      <button
                        type="button"
                        onClick={() => onUpdateAgentStatus(agent.id, 'Paused')}
                        className="rounded-md border border-slate-700 bg-[#0B0F17] px-2.5 py-1 text-xs text-slate-300 hover:border-amber-500/40 hover:text-amber-300 transition-colors"
                      >
                        Pause
                      </button>
                      <button
                        type="button"
                        onClick={() => onUpdateAgentStatus(agent.id, 'Revoked')}
                        className="rounded-md border border-slate-700 bg-[#0B0F17] px-2.5 py-1 text-xs text-slate-300 hover:border-red-500/40 hover:text-red-300 transition-colors"
                      >
                        Revoke Token
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      onClick={() => onUpdateAgentStatus(agent.id, 'Active')}
                      className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 transition-colors"
                    >
                      Reactivate Agent
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Middle Split: Baseline vs Current Chart + Simulated Owner Alert Card */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12 items-stretch">
        <div className="xl:col-span-7 rounded-xl border border-slate-800 bg-[#111827] p-5">
          <div className="mb-4 flex items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Baseline vs. Observed Activity
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                24/7 learned volume range (mean ± k·std) without rigid time-of-day false alarms
              </p>
            </div>
          </div>
          {selectedAgent && (
            <BaselineChart
              agent={selectedAgent}
              baseline={baselines[selectedAgent.id]}
              logs={logs}
            />
          )}
        </div>

        <div className="xl:col-span-5">
          <SimulatedAlertCard
            alert={featuredAlert}
            channel={channel}
            onChangeChannel={onChangeChannel}
            onResolveAlert={onResolveAlert}
            busyAlertId={busyAction?.startsWith('resolve_') ? busyAction.replace('resolve_', '') : null}
          />
        </div>
      </div>

      {/* Live Activity Timeline Table */}
      <section className="rounded-xl border border-slate-800 bg-[#111827]">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-5 py-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Live Activity Timeline
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Recent delegated API calls scored by AgentGuard. Click any row to inspect fired signals.
            </p>
          </div>
          <span className="font-mono text-xs tabular-nums text-slate-400">
            Showing latest {Math.min(12, logs.length)} of {logs.length}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-[#0D131F] text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Agent</th>
                <th className="px-4 py-3 font-medium">Action & Endpoint</th>
                <th className="px-4 py-3 font-medium">Scope</th>
                <th className="px-4 py-3 font-medium text-right">Volume</th>
                <th className="px-4 py-3 font-medium">Origin</th>
                <th className="px-4 py-3 font-medium text-right">Risk</th>
                <th className="px-4 py-3 font-medium">Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {logs.slice(0, 12).map((log) => {
                const agentName = agents.find((a) => a.id === log.agentId)?.name ?? log.agentId;
                const isExpanded = expandedLogId === log.id;
                const clsColor =
                  log.analysis.severity === 'Critical'
                    ? 'text-red-400'
                    : log.analysis.severity === 'Warning' || log.analysis.severity === 'Confirm'
                      ? 'text-amber-400'
                      : 'text-emerald-400';

                return (
                  <FragmentRow
                    key={log.id}
                    log={log}
                    agentName={agentName}
                    clsColor={clsColor}
                    isExpanded={isExpanded}
                    onToggle={() => setExpandedLogId(isExpanded ? null : log.id)}
                  />
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function FragmentRow({
  log,
  agentName,
  clsColor,
  isExpanded,
  onToggle,
}: {
  log: ActivityLog;
  agentName: string;
  clsColor: string;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer transition-colors hover:bg-slate-800/40"
      >
        <td className="px-4 py-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
          {new Date(log.timestamp).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          })}
        </td>
        <td className="px-4 py-3 font-medium text-slate-200 whitespace-nowrap">
          {agentName}
        </td>
        <td className="px-4 py-3">
          <div className="font-mono text-slate-200">{log.action}</div>
          <div className="font-mono text-[11px] text-slate-500">{log.endpoint}</div>
        </td>
        <td className="px-4 py-3 font-mono text-slate-300 whitespace-nowrap">
          {log.scopeUsed}
        </td>
        <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-200 whitespace-nowrap">
          {log.volume}/hr
        </td>
        <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
          <div>{log.region}</div>
          <div className="font-mono text-[11px] text-slate-500">{log.userAgent}</div>
        </td>
        <td className={`px-4 py-3 text-right font-mono font-semibold tabular-nums whitespace-nowrap ${clsColor}`}>
          {log.analysis.riskScore}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <div className="flex items-center justify-between gap-2">
            <span className={`font-medium ${clsColor}`}>{log.analysis.classification}</span>
            {isExpanded ? (
              <ChevronUp className="h-3.5 w-3.5 text-slate-500" />
            ) : (
              <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
            )}
          </div>
        </td>
      </tr>
      {isExpanded && (
        <tr className="bg-[#0D131F]">
          <td colSpan={8} className="px-4 py-4">
            <div className="space-y-3">
              <div className="text-xs text-slate-200">
                <span className="font-semibold text-slate-100">Explanation: </span>
                {log.analysis.explanation}
              </div>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                {[
                  ['Scope Violation', log.analysis.componentScores.scopeViolation],
                  ['Endpoint Novelty', log.analysis.componentScores.endpointNovelty],
                  ['Volume Deviation', log.analysis.componentScores.volumeDeviation],
                  ['Identity Shift', log.analysis.componentScores.identityShift],
                  ['Unapproved Change', log.analysis.componentScores.unapprovedChange],
                ].map(([label, score]) => (
                  <div key={String(label)} className="rounded-lg border border-slate-800 bg-[#0B0F17] p-2.5">
                    <div className="text-[11px] text-slate-400">{label}</div>
                    <div className="mt-0.5 font-mono text-sm font-semibold tabular-nums text-slate-100">
                      {score}/100
                    </div>
                  </div>
                ))}
              </div>
              {log.analysis.firedSignals.length > 0 && (
                <div className="space-y-1 text-xs text-slate-400">
                  {log.analysis.firedSignals.map((sig, i) => (
                    <div key={i}>
                      <span className="font-medium text-slate-200">{sig.label}:</span> {sig.detail}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
