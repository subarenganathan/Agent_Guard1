import { useMemo, useState } from 'react';
import { computeToolHash } from '../engine/detection';
import type {
  AgentBaseline,
  AgentProfile,
  AgentScope,
  AgentStatus,
  ChangeType,
  OwnerChangeEntry,
} from '../types/agentguard';

interface AgentsChangesViewProps {
  agents: AgentProfile[];
  baselines: Record<string, AgentBaseline>;
  changeLogs: OwnerChangeEntry[];
  onOpenRegisterModal: () => void;
  onUpdateAgent: (
    agentId: string,
    patch: { status?: AgentStatus; autoRevokeEnabled?: boolean; autoRevokeThreshold?: number }
  ) => Promise<void>;
  onCreateChange: (payload: {
    agentId: string;
    changeType: ChangeType;
    title: string;
    description: string;
    toolDefinition: string;
    addedScopes: AgentScope[];
    addedEndpoints: string[];
    expectedVolumeMultiplier: number;
  }) => Promise<void>;
}

const ALL_SCOPES: AgentScope[] = [
  'read_posts',
  'post_content',
  'read_dm',
  'send_dm',
  'follow',
  'delete',
];

export function AgentsChangesView({
  agents,
  baselines,
  changeLogs,
  onOpenRegisterModal,
  onUpdateAgent,
  onCreateChange,
}: AgentsChangesViewProps) {
  const [agentId, setAgentId] = useState(agents[0]?.id ?? '');
  const [changeType, setChangeType] = useState<ChangeType>('new_tool');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [toolDefinition, setToolDefinition] = useState(
    '{\n  "tool_name": "dm_inbox_reader",\n  "endpoint": "/v1/dm/inbox",\n  "scope": "read_dm"\n}'
  );
  const [addedScopes, setAddedScopes] = useState<AgentScope[]>(['read_dm']);
  const [addedEndpointsText, setAddedEndpointsText] = useState('/v1/dm/inbox');
  const [expectedVolumeMultiplier, setExpectedVolumeMultiplier] = useState(1.5);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const liveHashPreview = useMemo(() => {
    const addedEndpoints = addedEndpointsText
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.startsWith('/'));
    const raw = `${agentId}:${changeType}:${title}:${toolDefinition}:${addedScopes.join(',')}:${addedEndpoints.join(',')}`;
    return computeToolHash(raw);
  }, [agentId, changeType, title, toolDefinition, addedScopes, addedEndpointsText]);

  const toggleAddedScope = (scope: AgentScope) => {
    setAddedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    );
  };

  const handleCreateChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!agentId || !title.trim() || !description.trim()) {
      setError('Select an agent and provide a change title and description.');
      return;
    }

    const addedEndpoints = addedEndpointsText
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.startsWith('/'));

    setSubmitting(true);
    try {
      await onCreateChange({
        agentId,
        changeType,
        title: title.trim(),
        description: description.trim(),
        toolDefinition,
        addedScopes,
        addedEndpoints,
        expectedVolumeMultiplier,
      });
      setTitle('');
      setDescription('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to log owner change.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Agent Registry & Owner Change Log
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Manage delegated OAuth tokens, baseline bounds, and owner-approved tool or instruction changes.
          </p>
        </div>
        <button
          type="button"
          onClick={onOpenRegisterModal}
          className="rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 whitespace-nowrap shrink-0"
        >
          Register Agent
        </button>
      </div>

      {/* Agent Registry Table */}
      <section className="rounded-xl border border-slate-800 bg-[#111827]">
        <div className="border-b border-slate-800 px-5 py-4">
          <h2 className="text-sm font-semibold text-slate-100">Registered AI Agents</h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Each agent operates under least-privilege scopes, an automated baseline range, and optional auto-revocation.
          </p>
        </div>

        <div className="divide-y divide-slate-800">
          {agents.map((agent) => {
            const baseline = baselines[agent.id];
            const statusText =
              agent.status === 'Active'
                ? 'text-emerald-400'
                : agent.status === 'Paused'
                  ? 'text-amber-400'
                  : 'text-red-400';

            return (
              <div key={agent.id} className="p-5">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="space-y-2 max-w-2xl">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-base font-semibold text-slate-100">{agent.name}</span>
                      <span className="text-slate-600">·</span>
                      <span className="text-xs text-slate-300">{agent.platform}</span>
                      <span className="text-slate-600">·</span>
                      <span className={`text-xs font-medium ${statusText}`}>{agent.status}</span>
                    </div>
                    <p className="text-xs leading-relaxed text-slate-400">{agent.purpose}</p>

                    <div className="grid grid-cols-1 gap-2 pt-1 text-xs sm:grid-cols-2">
                      <div>
                        <span className="text-slate-500">Token ID: </span>
                        <span className="font-mono text-slate-300">{agent.tokenId}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Schedule: </span>
                        <span className="text-slate-300">
                          {agent.allowedTimeWindow
                            ? `${agent.allowedTimeWindow.startHour}:00–${agent.allowedTimeWindow.endHour}:00 UTC`
                            : '24/7 Continuous (No human-hour rule)'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Approved Scopes: </span>
                        <span className="font-mono text-slate-300">
                          {agent.allowedScopes.join(', ')}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Approved Endpoints: </span>
                        <span className="font-mono text-slate-300">
                          {agent.allowedEndpoints.join(', ')}
                        </span>
                      </div>
                    </div>

                    {baseline && (
                      <div className="pt-1 text-xs text-slate-400">
                        <span className="text-slate-500">Learned Volume Baseline: </span>
                        <span className="font-mono tabular-nums text-slate-200">
                          {baseline.hourlyVolumeRange.lowerBound.toFixed(1)}–
                          {baseline.hourlyVolumeRange.upperBound.toFixed(1)} req/hr
                        </span>{' '}
                        (mean {baseline.hourlyVolumeRange.mean.toFixed(1)} ±{' '}
                        {baseline.hourlyVolumeRange.k}·{baseline.hourlyVolumeRange.std.toFixed(1)},{' '}
                        {baseline.learnedCount} normal samples)
                      </div>
                    )}
                  </div>

                  {/* Controls column */}
                  <div className="flex flex-col gap-3 rounded-lg border border-slate-800 bg-[#0B0F17] p-4 lg:w-72 shrink-0">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-400">Auto-Revoke Policy</span>
                      <label className="flex items-center gap-2 cursor-pointer text-slate-200">
                        <input
                          type="checkbox"
                          checked={agent.autoRevokeEnabled}
                          onChange={(e) =>
                            onUpdateAgent(agent.id, { autoRevokeEnabled: e.target.checked })
                          }
                          className="accent-sky-500"
                        />
                        {agent.autoRevokeEnabled ? 'Enabled' : 'Disabled'}
                      </label>
                    </div>

                    {agent.autoRevokeEnabled && (
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-xs text-slate-400">
                          <span>Revoke Threshold</span>
                          <span className="font-mono tabular-nums text-slate-200">
                            Risk &ge; {agent.autoRevokeThreshold}
                          </span>
                        </div>
                        <input
                          type="range"
                          min={60}
                          max={100}
                          value={agent.autoRevokeThreshold}
                          onChange={(e) =>
                            onUpdateAgent(agent.id, {
                              autoRevokeThreshold: Number(e.target.value),
                            })
                          }
                          className="w-full accent-sky-500"
                        />
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-2 border-t border-slate-800 pt-3">
                      {agent.status === 'Active' ? (
                        <>
                          <button
                            type="button"
                            onClick={() => onUpdateAgent(agent.id, { status: 'Paused' })}
                            className="flex-1 rounded-md border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-amber-500/40 hover:text-amber-300"
                          >
                            Pause
                          </button>
                          <button
                            type="button"
                            onClick={() => onUpdateAgent(agent.id, { status: 'Revoked' })}
                            className="flex-1 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-300 hover:bg-red-500/20"
                          >
                            Revoke
                          </button>
                        </>
                      ) : (
                        <button
                          type="button"
                          onClick={() => onUpdateAgent(agent.id, { status: 'Active' })}
                          className="w-full rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20"
                        >
                          Reactivate Agent & Issue Token
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Owner Change Log Split */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Form: Log Approved Change */}
        <section className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#111827] p-5">
          <h2 className="text-sm font-semibold text-slate-100">
            Record Owner-Approved Change
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-slate-400">
            Log intentional prompt instructions, new tools, or scopes. Shifts matching this ledger route to owner confirmation instead of firing a hard alert.
          </p>

          <form onSubmit={handleCreateChange} className="mt-4 space-y-4">
            {error && (
              <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                {error}
              </div>
            )}

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="block text-xs font-medium text-slate-300" htmlFor="chg-agent">
                  Target Agent
                </label>
                <select
                  id="chg-agent"
                  value={agentId}
                  onChange={(e) => setAgentId(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                >
                  {agents.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300" htmlFor="chg-type">
                  Change Category
                </label>
                <select
                  id="chg-type"
                  value={changeType}
                  onChange={(e) => setChangeType(e.target.value as ChangeType)}
                  className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                >
                  <option value="new_tool">New Tool Definition</option>
                  <option value="new_scope">New Scope Approval</option>
                  <option value="new_instruction">New Prompt Instruction</option>
                </select>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300" htmlFor="chg-title">
                Change Title
              </label>
              <input
                id="chg-title"
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g., Added DM Inbox Summarizer Tool"
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300" htmlFor="chg-desc">
                Owner Rationale
              </label>
              <input
                id="chg-desc"
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Why this behavior shift is expected"
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div>
              <div className="text-xs font-medium text-slate-300">
                Scopes Covered by Change (optional)
              </div>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {ALL_SCOPES.map((s) => {
                  const active = addedScopes.includes(s);
                  return (
                    <button
                      key={s}
                      type="button"
                      onClick={() => toggleAddedScope(s)}
                      className={`rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors ${
                        active
                          ? 'border-sky-500/50 bg-sky-500/15 text-sky-200'
                          : 'border-slate-800 bg-[#0B0F17] text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      {s}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div>
                <label className="block text-xs font-medium text-slate-300" htmlFor="chg-endpoints">
                  Endpoints Covered
                </label>
                <input
                  id="chg-endpoints"
                  type="text"
                  value={addedEndpointsText}
                  onChange={(e) => setAddedEndpointsText(e.target.value)}
                  className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 font-mono text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300" htmlFor="chg-mult">
                  Expected Volume Multiplier
                </label>
                <input
                  id="chg-mult"
                  type="number"
                  min={1}
                  max={5}
                  step={0.1}
                  value={expectedVolumeMultiplier}
                  onChange={(e) => setExpectedVolumeMultiplier(Number(e.target.value))}
                  className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 font-mono text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300" htmlFor="chg-def">
                Tool Definition / Prompt Spec (hashed via SHA-256)
              </label>
              <textarea
                id="chg-def"
                rows={3}
                value={toolDefinition}
                onChange={(e) => setToolDefinition(e.target.value)}
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 font-mono text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
              />
              <div className="mt-1.5 font-mono text-[11px] text-slate-400 break-all">
                Fingerprint: <span className="text-sky-400">{liveHashPreview}</span>
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
            >
              {submitting ? 'Recording Change…' : 'Record Owner Change & Hash Fingerprint'}
            </button>
          </form>
        </section>

        {/* Change Log Ledger */}
        <section className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#111827] p-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3.5">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Owner Change Ledger</h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Cryptographically fingerprinted changes authorized by the account owner.
              </p>
            </div>
            <span className="font-mono text-xs tabular-nums text-slate-400">
              {changeLogs.length} entries
            </span>
          </div>

          {changeLogs.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-400">
              No owner changes recorded yet.
            </div>
          ) : (
            <div className="mt-4 divide-y divide-slate-800">
              {changeLogs.map((chg) => {
                const targetName =
                  agents.find((a) => a.id === chg.agentId)?.name ?? chg.agentId;
                return (
                  <div key={chg.id} className="py-4 first:pt-0 last:pb-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-semibold text-slate-100">
                          {chg.title}
                        </span>
                        <span className="text-slate-600">·</span>
                        <span className="text-xs text-sky-400 font-medium">{targetName}</span>
                        <span className="text-slate-600">·</span>
                        <span className="font-mono text-xs text-slate-400">{chg.changeType}</span>
                      </div>
                      <span
                        className={`text-xs font-medium ${
                          chg.confirmedByOwner ? 'text-emerald-400' : 'text-amber-400'
                        }`}
                      >
                        {chg.confirmedByOwner ? 'Confirmed by Owner' : 'Awaiting First Observed Shift'}
                      </span>
                    </div>

                    <p className="mt-1.5 text-xs text-slate-400">{chg.description}</p>

                    <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-400 font-mono">
                      <span>SHA-256: {chg.toolHash.slice(0, 18)}…</span>
                      {chg.addedScopes.length > 0 && (
                        <span>Scopes: {chg.addedScopes.join(', ')}</span>
                      )}
                      {chg.addedEndpoints.length > 0 && (
                        <span>Endpoints: {chg.addedEndpoints.join(', ')}</span>
                      )}
                      <span>
                        Logged {new Date(chg.createdAt).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
