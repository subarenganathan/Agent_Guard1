import { useEffect, useState } from 'react';
import type {
  ActivityLog,
  AgentProfile,
  AgentScope,
  AttackScenario,
  NotificationChannel,
  OwnerAlert,
} from '../types/agentguard';
import { SimulatedAlertCard } from './SimulatedAlertCard';

interface ActivityAlertsViewProps {
  agents: AgentProfile[];
  logs: ActivityLog[];
  alerts: OwnerAlert[];
  channel: NotificationChannel;
  onChangeChannel: (ch: NotificationChannel) => void;
  onSimulate: (
    agentId: string,
    scenario: AttackScenario,
    custom?: {
      action?: string;
      endpoint?: string;
      scopeUsed?: AgentScope;
      volume?: number;
      region?: string;
      userAgent?: string;
    }
  ) => Promise<void>;
  onResolveAlert: (alertId: string, action: 'confirm_mine' | 'pause_agent' | 'revoke_token') => Promise<void>;
  busyAction: string | null;
}

export function ActivityAlertsView({
  agents,
  logs,
  alerts,
  channel,
  onChangeChannel,
  onSimulate,
  onResolveAlert,
  busyAction,
}: ActivityAlertsViewProps) {
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.id ?? '');
  const [filterSeverity, setFilterSeverity] = useState<'All' | 'Anomalies' | 'Normal'>('All');
  const [streamRunning, setStreamRunning] = useState(false);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(alerts[0]?.id ?? null);

  // Custom event parameters
  const [customAction, setCustomAction] = useState('read_comments');
  const [customEndpoint, setCustomEndpoint] = useState('/v1/media/read');
  const [customScope, setCustomScope] = useState<AgentScope>('read_posts');
  const [customVolume, setCustomVolume] = useState(18);
  const [customRegion, setCustomRegion] = useState('US-West (Oregon)');
  const [customUA, setCustomUA] = useState('AgentSDK/2.4 (Node/22)');

  const selectedAgent = agents.find((a) => a.id === selectedAgentId) ?? agents[0];
  const activeAlert = alerts.find((a) => a.id === selectedAlertId) ?? alerts[0] ?? null;

  useEffect(() => {
    if (!streamRunning || !selectedAgent || selectedAgent.status !== 'Active') return;
    const timer = setInterval(() => {
      onSimulate(selectedAgent.id, 'normal');
    }, 3200);
    return () => clearInterval(timer);
  }, [streamRunning, selectedAgent, onSimulate]);

  const filteredLogs = logs.filter((l) => {
    if (filterSeverity === 'Anomalies') return l.analysis.severity !== 'Normal';
    if (filterSeverity === 'Normal') return l.analysis.severity === 'Normal';
    return true;
  });

  const handleCustomSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgent) return;
    await onSimulate(selectedAgent.id, 'normal', {
      action: customAction,
      endpoint: customEndpoint,
      scopeUsed: customScope,
      volume: customVolume,
      region: customRegion,
      userAgent: customUA,
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Activity Simulator & Owner Alerts
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Inject synthetic attack patterns or custom telemetry to test anomaly scoring and owner response workflows.
          </p>
        </div>

        {selectedAgent && (
          <button
            type="button"
            onClick={() => setStreamRunning((v) => !v)}
            disabled={selectedAgent.status !== 'Active'}
            className={`rounded-lg border px-4 py-2 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
              streamRunning
                ? 'border-amber-500/50 bg-amber-500/15 text-amber-300'
                : 'border-slate-700 bg-[#111827] text-slate-200 hover:border-slate-600'
            }`}
          >
            {streamRunning ? 'Stop Live Normal Stream' : 'Start Live Normal Stream'}
          </button>
        )}
      </div>

      {/* Attack Injection Deck */}
      {selectedAgent && (
        <section className="rounded-xl border border-slate-800 bg-[#111827] p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="sim-agent-select" className="text-xs font-medium text-slate-300">
                Target Mock Agent:
              </label>
              <select
                id="sim-agent-select"
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
            <span className="font-mono text-xs text-slate-400">
              Token: {selectedAgent.tokenId}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {[
              {
                id: 'stolen_token' as const,
                title: 'Stolen Token Replay',
                desc: 'Same OAuth token used from Frankfurt/Singapore with python-requests or curl.',
              },
              {
                id: 'prompt_injection' as const,
                title: 'Prompt-Injection Hijack',
                desc: 'Same IP & User-Agent, but agent executes off-purpose bulk DM or data export.',
              },
              {
                id: 'scope_creep' as const,
                title: 'Scope Creep',
                desc: 'Agent calls an unapproved scope (e.g., delete or follow) not in its registry.',
              },
              {
                id: 'burst_exfiltration' as const,
                title: 'Burst / Exfiltration',
                desc: 'Sudden 2.5x–3.8x read volume spike exceeding learned mean ± k·std range.',
              },
              {
                id: 'owner_approved_shift' as const,
                title: 'Owner-Approved Shift',
                desc: 'New scope/endpoint matching Owner Change Log; routes to confirmation prompt.',
              },
              {
                id: 'normal' as const,
                title: 'Normal Baseline Event',
                desc: 'Routine 24/7 operation inside learned baseline and approved scopes.',
              },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                disabled={busyAction !== null || selectedAgent.status !== 'Active'}
                onClick={() => onSimulate(selectedAgent.id, item.id)}
                className="text-left rounded-lg border border-slate-800 bg-[#0B0F17] p-3.5 transition-colors hover:border-sky-500/50 disabled:opacity-45"
              >
                <div className="text-xs font-semibold text-slate-100">{item.title}</div>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-400">{item.desc}</p>
              </button>
            ))}
          </div>

          {/* Custom Event Builder */}
          <form
            onSubmit={handleCustomSimulate}
            className="border-t border-slate-800 pt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-7 items-end"
          >
            <div>
              <label className="block text-[11px] text-slate-400">Action</label>
              <input
                type="text"
                value={customAction}
                onChange={(e) => setCustomAction(e.target.value)}
                className="mt-1 w-full rounded border border-slate-700 bg-[#0B0F17] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-400">Endpoint</label>
              <input
                type="text"
                value={customEndpoint}
                onChange={(e) => setCustomEndpoint(e.target.value)}
                className="mt-1 w-full rounded border border-slate-700 bg-[#0B0F17] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-400">Scope Used</label>
              <select
                value={customScope}
                onChange={(e) => setCustomScope(e.target.value as AgentScope)}
                className="mt-1 w-full rounded border border-slate-700 bg-[#0B0F17] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              >
                <option value="read_posts">read_posts</option>
                <option value="post_content">post_content</option>
                <option value="read_dm">read_dm</option>
                <option value="send_dm">send_dm</option>
                <option value="follow">follow</option>
                <option value="delete">delete</option>
              </select>
            </div>
            <div>
              <label className="block text-[11px] text-slate-400">Volume / hr</label>
              <input
                type="number"
                min={1}
                max={2000}
                value={customVolume}
                onChange={(e) => setCustomVolume(Number(e.target.value))}
                className="mt-1 w-full rounded border border-slate-700 bg-[#0B0F17] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-400">Region</label>
              <input
                type="text"
                value={customRegion}
                onChange={(e) => setCustomRegion(e.target.value)}
                className="mt-1 w-full rounded border border-slate-700 bg-[#0B0F17] px-2.5 py-1.5 text-xs text-slate-100"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-400">User-Agent</label>
              <input
                type="text"
                value={customUA}
                onChange={(e) => setCustomUA(e.target.value)}
                className="mt-1 w-full rounded border border-slate-700 bg-[#0B0F17] px-2.5 py-1.5 font-mono text-xs text-slate-100"
              />
            </div>
            <button
              type="submit"
              disabled={busyAction !== null || selectedAgent.status !== 'Active'}
              className="rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-45 whitespace-nowrap shrink-0"
            >
              Send Custom Event
            </button>
          </form>
        </section>
      )}

      {/* Alerts Split: Simulated Delivery Card + Alert History Feed */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <div className="xl:col-span-5">
          <SimulatedAlertCard
            alert={activeAlert}
            channel={channel}
            onChangeChannel={onChangeChannel}
            onResolveAlert={onResolveAlert}
            busyAlertId={busyAction?.startsWith('resolve_') ? busyAction.replace('resolve_', '') : null}
          />
        </div>

        <section className="xl:col-span-7 rounded-xl border border-slate-800 bg-[#111827] p-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3.5">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Alert History</h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Select any alert to inspect evidence and take action.
              </p>
            </div>
            <span className="font-mono text-xs tabular-nums text-slate-400">
              {alerts.length} alerts
            </span>
          </div>

          {alerts.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-400">
              No security alerts triggered yet.
            </div>
          ) : (
            <div className="mt-3 max-h-[360px] divide-y divide-slate-800 overflow-y-auto pr-1">
              {alerts.map((alert) => {
                const isSelected = activeAlert?.id === alert.id;
                const sevClass =
                  alert.severity === 'Critical'
                    ? 'text-red-400'
                    : alert.severity === 'Confirm' || alert.severity === 'Warning'
                      ? 'text-amber-400'
                      : 'text-slate-300';

                return (
                  <button
                    key={alert.id}
                    type="button"
                    onClick={() => setSelectedAlertId(alert.id)}
                    className={`w-full text-left py-3 px-3 rounded-lg transition-colors ${
                      isSelected ? 'bg-[#172133]' : 'hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div className="flex items-center gap-2">
                        <span className={`font-semibold ${sevClass}`}>
                          {alert.classification}
                        </span>
                        <span className="text-slate-600">·</span>
                        <span className="font-medium text-slate-200">{alert.agentName}</span>
                      </div>
                      <div className="flex items-center gap-3 font-mono tabular-nums text-slate-400">
                        <span>Risk {alert.riskScore}</span>
                        <span>{alert.status}</span>
                      </div>
                    </div>
                    <p className="mt-1 text-xs text-slate-400 line-clamp-2">{alert.summary}</p>
                  </button>
                );
              })}
            </div>
          )}
        </section>
      </div>

      {/* Filterable Activity Log */}
      <section className="rounded-xl border border-slate-800 bg-[#111827]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-100">
            Full Simulated Activity Stream
          </h2>
          <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#0B0F17] p-1">
            {(['All', 'Anomalies', 'Normal'] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setFilterSeverity(tab)}
                className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${
                  filterSeverity === tab
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-[#0D131F] text-slate-400">
              <tr>
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Agent</th>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Scope</th>
                <th className="px-4 py-3 font-medium text-right">Volume</th>
                <th className="px-4 py-3 font-medium">IP / Region</th>
                <th className="px-4 py-3 font-medium text-right">Risk</th>
                <th className="px-4 py-3 font-medium">Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredLogs.slice(0, 40).map((log) => {
                const agentName = agents.find((a) => a.id === log.agentId)?.name ?? log.agentId;
                const clsColor =
                  log.analysis.severity === 'Critical'
                    ? 'text-red-400'
                    : log.analysis.severity === 'Warning' || log.analysis.severity === 'Confirm'
                      ? 'text-amber-400'
                      : 'text-emerald-400';

                return (
                  <tr key={log.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono tabular-nums text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-200 whitespace-nowrap">
                      {agentName}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300 whitespace-nowrap">
                      {log.action} ({log.endpoint})
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-300 whitespace-nowrap">
                      {log.scopeUsed}
                    </td>
                    <td className="px-4 py-3 text-right font-mono tabular-nums text-slate-200">
                      {log.volume}
                    </td>
                    <td className="px-4 py-3 text-slate-400 whitespace-nowrap">
                      {log.region} · {log.ip}
                    </td>
                    <td className={`px-4 py-3 text-right font-mono font-semibold tabular-nums ${clsColor}`}>
                      {log.analysis.riskScore}
                    </td>
                    <td className="px-4 py-3 text-slate-300 max-w-md">
                      <span className={`font-medium ${clsColor}`}>
                        {log.analysis.classification}:
                      </span>{' '}
                      {log.analysis.explanation}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
