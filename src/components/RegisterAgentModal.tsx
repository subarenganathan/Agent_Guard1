import { useState } from 'react';
import { X } from 'lucide-react';
import type { AgentPlatform, AgentScope } from '../types/agentguard';

interface RegisterAgentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreateAgent: (payload: {
    name: string;
    platform: AgentPlatform;
    purpose: string;
    allowedScopes: AgentScope[];
    allowedEndpoints: string[];
    maxActionsPerHour: number;
    allowedTimeWindow: { startHour: number; endHour: number } | null;
    autoRevokeEnabled: boolean;
    autoRevokeThreshold: number;
  }) => Promise<void>;
}

const ALL_SCOPES: { id: AgentScope; label: string }[] = [
  { id: 'read_posts', label: 'read_posts' },
  { id: 'post_content', label: 'post_content' },
  { id: 'read_dm', label: 'read_dm' },
  { id: 'send_dm', label: 'send_dm' },
  { id: 'follow', label: 'follow' },
  { id: 'delete', label: 'delete' },
];

export function RegisterAgentModal({
  isOpen,
  onClose,
  onCreateAgent,
}: RegisterAgentModalProps) {
  const [name, setName] = useState('');
  const [platform, setPlatform] = useState<AgentPlatform>('Instagram');
  const [purpose, setPurpose] = useState('');
  const [selectedScopes, setSelectedScopes] = useState<AgentScope[]>(['read_posts', 'post_content']);
  const [endpointsText, setEndpointsText] = useState('/v1/media/read, /v1/comments/reply');
  const [maxActionsPerHour, setMaxActionsPerHour] = useState(40);
  const [useTimeWindow, setUseTimeWindow] = useState(false);
  const [startHour, setStartHour] = useState(8);
  const [endHour, setEndHour] = useState(20);
  const [autoRevokeEnabled, setAutoRevokeEnabled] = useState(true);
  const [autoRevokeThreshold, setAutoRevokeThreshold] = useState(85);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const toggleScope = (scope: AgentScope) => {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!name.trim() || !purpose.trim() || selectedScopes.length === 0) {
      setError('Please enter a name, purpose, and select at least one allowed scope.');
      return;
    }

    const allowedEndpoints = endpointsText
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.startsWith('/'));

    setSubmitting(true);
    try {
      await onCreateAgent({
        name: name.trim(),
        platform,
        purpose: purpose.trim(),
        allowedScopes: selectedScopes,
        allowedEndpoints,
        maxActionsPerHour,
        allowedTimeWindow: useTimeWindow ? { startHour, endHour } : null,
        autoRevokeEnabled,
        autoRevokeThreshold,
      });
      setName('');
      setPurpose('');
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to register agent.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="register-agent-title"
    >
      <div className="w-full max-w-xl rounded-xl border border-slate-800 bg-[#111827] shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
          <div>
            <h2 id="register-agent-title" className="text-base font-semibold text-slate-100">
              Register New AI Agent
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Issues a mock OAuth token ID and initializes a 24/7 behavioral baseline.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close modal"
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 p-6">
          {error && (
            <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-slate-300" htmlFor="agent-name">
                Agent Name
              </label>
              <input
                id="agent-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Community Mod Bot"
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300" htmlFor="agent-platform">
                Delegated Account
              </label>
              <select
                id="agent-platform"
                value={platform}
                onChange={(e) => setPlatform(e.target.value as AgentPlatform)}
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
              >
                <option value="Instagram">Instagram (Simulated)</option>
                <option value="Gmail">Gmail (Simulated)</option>
                <option value="X / Twitter">X / Twitter (Simulated)</option>
                <option value="Slack">Slack (Simulated)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300" htmlFor="agent-purpose">
              Intended Purpose (Plain English)
            </label>
            <input
              id="agent-purpose"
              type="text"
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              placeholder="e.g., Reads post comments and replies to product questions"
              className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-sky-500 focus:outline-none"
            />
          </div>

          <div>
            <div className="text-xs font-medium text-slate-300">Allowed OAuth Scopes</div>
            <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3">
              {ALL_SCOPES.map((s) => {
                const checked = selectedScopes.includes(s.id);
                return (
                  <label
                    key={s.id}
                    className={`flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-xs font-mono transition-colors ${
                      checked
                        ? 'border-sky-500/50 bg-sky-500/10 text-sky-200'
                        : 'border-slate-800 bg-[#0B0F17] text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleScope(s.id)}
                      className="accent-sky-500"
                    />
                    {s.label}
                  </label>
                );
              })}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className="block text-xs font-medium text-slate-300" htmlFor="agent-endpoints">
                Allowed Endpoints (comma-separated)
              </label>
              <input
                id="agent-endpoints"
                type="text"
                value={endpointsText}
                onChange={(e) => setEndpointsText(e.target.value)}
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 font-mono text-xs text-slate-100 focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300" htmlFor="agent-max-vol">
                Max Actions / Hour
              </label>
              <input
                id="agent-max-vol"
                type="number"
                min={5}
                max={1000}
                value={maxActionsPerHour}
                onChange={(e) => setMaxActionsPerHour(Number(e.target.value))}
                className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 font-mono text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 border-t border-slate-800 pt-4 sm:grid-cols-2">
            <div>
              <label className="flex items-center gap-2 text-xs font-medium text-slate-300">
                <input
                  type="checkbox"
                  checked={useTimeWindow}
                  onChange={(e) => setUseTimeWindow(e.target.checked)}
                  className="accent-sky-500"
                />
                Enforce optional time window (off = 24/7)
              </label>
              {useTimeWindow && (
                <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
                  <input
                    type="number"
                    min={0}
                    max={23}
                    value={startHour}
                    onChange={(e) => setStartHour(Number(e.target.value))}
                    className="w-16 rounded border border-slate-700 bg-[#0B0F17] px-2 py-1 font-mono text-slate-100"
                  />
                  <span>to</span>
                  <input
                    type="number"
                    min={0}
                    max={23}
                    value={endHour}
                    onChange={(e) => setEndHour(Number(e.target.value))}
                    className="w-16 rounded border border-slate-700 bg-[#0B0F17] px-2 py-1 font-mono text-slate-100"
                  />
                  <span>UTC</span>
                </div>
              )}
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs font-medium text-slate-300">
                <input
                  type="checkbox"
                  checked={autoRevokeEnabled}
                  onChange={(e) => setAutoRevokeEnabled(e.target.checked)}
                  className="accent-sky-500"
                />
                Auto-revoke token if risk exceeds
              </label>
              {autoRevokeEnabled && (
                <div className="mt-2 flex items-center gap-3">
                  <input
                    type="range"
                    min={60}
                    max={100}
                    value={autoRevokeThreshold}
                    onChange={(e) => setAutoRevokeThreshold(Number(e.target.value))}
                    className="w-full accent-sky-500"
                  />
                  <span className="font-mono text-xs tabular-nums text-slate-200">
                    {autoRevokeThreshold}
                  </span>
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 border-t border-slate-800 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50"
            >
              {submitting ? 'Registering…' : 'Create Agent & Issue Token'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
