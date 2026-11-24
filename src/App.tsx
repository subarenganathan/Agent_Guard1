import { useCallback, useEffect, useState } from 'react';
import { ActivityAlertsView } from './components/ActivityAlertsView';
import { AgentsChangesView } from './components/AgentsChangesView';
import { ArchitectureView } from './components/ArchitectureView';
import { EvaluationView } from './components/EvaluationView';
import { OverviewView } from './components/OverviewView';
import { RegisterAgentModal } from './components/RegisterAgentModal';
import { TopBar, type NavTab } from './components/TopBar';
import type {
  AgentPlatform,
  AgentScope,
  AgentStatus,
  AppStateResponse,
  AttackScenario,
  ChangeType,
  EvaluationResult,
  NotificationChannel,
} from './types/agentguard';

export default function App() {
  const [state, setState] = useState<AppStateResponse | null>(null);
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [registerModalOpen, setRegisterModalOpen] = useState(false);
  const [evaluation, setEvaluation] = useState<EvaluationResult | null>(null);
  const [evalRunning, setEvalRunning] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [bannerMessage, setBannerMessage] = useState<{
    type: 'info' | 'error';
    text: string;
  } | null>(null);

  const loadState = useCallback(async () => {
    try {
      const res = await fetch('/api/state');
      if (!res.ok) throw new Error('Failed to load AgentGuard state');
      const data: AppStateResponse = await res.json();
      setState(data);
    } catch (err) {
      setBannerMessage({
        type: 'error',
        text: err instanceof Error ? err.message : 'Unable to reach AgentGuard API.',
      });
    }
  }, []);

  useEffect(() => {
    loadState();
  }, [loadState]);

  const showToast = (type: 'info' | 'error', text: string) => {
    setBannerMessage({ type, text });
  };

  const handleCreateAgent = async (payload: {
    name: string;
    platform: AgentPlatform;
    purpose: string;
    allowedScopes: AgentScope[];
    allowedEndpoints: string[];
    maxActionsPerHour: number;
    allowedTimeWindow: { startHour: number; endHour: number } | null;
    autoRevokeEnabled: boolean;
    autoRevokeThreshold: number;
  }) => {
    const res = await fetch('/api/agents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? 'Failed to register agent');
    await loadState();
    showToast('info', `Registered ${body.agent.name} with token ${body.agent.tokenId}.`);
  };

  const handleUpdateAgent = async (
    agentId: string,
    patch: { status?: AgentStatus; autoRevokeEnabled?: boolean; autoRevokeThreshold?: number }
  ) => {
    setBusyAction(`agent_${agentId}`);
    try {
      const res = await fetch(`/api/agents/${agentId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? 'Failed to update agent');
      await loadState();
      if (patch.status) {
        showToast('info', `${body.agent.name} status set to ${body.agent.status}.`);
      }
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to update agent');
    } finally {
      setBusyAction(null);
    }
  };

  const handleCreateChange = async (payload: {
    agentId: string;
    changeType: ChangeType;
    title: string;
    description: string;
    toolDefinition: string;
    addedScopes: AgentScope[];
    addedEndpoints: string[];
    expectedVolumeMultiplier: number;
  }) => {
    const res = await fetch('/api/changes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error ?? 'Failed to record owner change');
    await loadState();
    showToast(
      'info',
      `Recorded "${body.change.title}" (SHA-256 ${body.change.toolHash.slice(0, 12)}…).`
    );
  };

  const handleSimulate = useCallback(
    async (
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
    ) => {
      setBusyAction(`sim_${scenario}`);
      try {
        const res = await fetch('/api/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ agentId, scenario, custom }),
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error ?? 'Simulation failed');
        await loadState();
        if (body.autoRevoked) {
          showToast(
            'error',
            `Auto-revoked ${body.agent.name} token (Risk ${body.log.analysis.riskScore}/100: ${body.log.analysis.classification}).`
          );
        } else if (body.alert) {
          showToast(
            body.alert.severity === 'Confirm' ? 'info' : 'error',
            `${body.alert.classification} (Risk ${body.alert.riskScore}/100) detected on ${body.agent.name}.`
          );
        }
      } catch (err) {
        showToast('error', err instanceof Error ? err.message : 'Simulation error');
      } finally {
        setBusyAction(null);
      }
    },
    [loadState]
  );

  const handleResolveAlert = async (
    alertId: string,
    action: 'confirm_mine' | 'pause_agent' | 'revoke_token'
  ) => {
    setBusyAction(`resolve_${alertId}`);
    try {
      const res = await fetch(`/api/alerts/${alertId}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? 'Failed to resolve alert');
      await loadState();
      showToast('info', body.alert.resolvedAction ?? 'Alert updated.');
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to resolve alert');
    } finally {
      setBusyAction(null);
    }
  };

  const handleChangeChannel = async (preferredChannel: NotificationChannel) => {
    if (!state) return;
    setState({
      ...state,
      settings: { ...state.settings, preferredChannel },
    });
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preferredChannel }),
    });
  };

  const handleRunEvaluation = async (config: {
    trialsPerScenario: number;
    baselineEventsCount: number;
    ownerChangeRate: number;
  }) => {
    setEvalRunning(true);
    try {
      const res = await fetch('/api/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? 'Evaluation failed');
      setEvaluation(body);
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Benchmark failed');
    } finally {
      setEvalRunning(false);
    }
  };

  const handleResetDemo = async () => {
    setBusyAction('reset');
    try {
      const res = await fetch('/api/reset', { method: 'POST' });
      if (!res.ok) throw new Error('Failed to reset demo');
      const data: AppStateResponse = await res.json();
      setState(data);
      showToast('info', 'Demo telemetry restored to initial seeded state.');
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Reset error');
    } finally {
      setBusyAction(null);
    }
  };

  const openAlertsCount = state ? state.alerts.filter((a) => a.status === 'Open').length : 0;

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100">
      <TopBar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenRegisterModal={() => setRegisterModalOpen(true)}
        openAlertsCount={openAlertsCount}
      />

      <main className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 sm:py-8">
        {bannerMessage && (
          <div
            role="status"
            className={`mb-6 flex items-center justify-between gap-4 rounded-xl border px-4 py-3 text-xs ${
              bannerMessage.type === 'error'
                ? 'border-red-500/40 bg-red-500/10 text-red-200'
                : 'border-sky-500/40 bg-sky-500/10 text-sky-200'
            }`}
          >
            <span>{bannerMessage.text}</span>
            <button
              type="button"
              onClick={() => setBannerMessage(null)}
              className="font-medium underline underline-offset-2 hover:opacity-80 shrink-0"
            >
              Dismiss
            </button>
          </div>
        )}

        {!state ? (
          <div className="space-y-4">
            <div className="h-24 animate-pulse rounded-xl bg-slate-900/70 border border-slate-800" />
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <div className="h-44 animate-pulse rounded-xl bg-slate-900/70 border border-slate-800" />
              <div className="h-44 animate-pulse rounded-xl bg-slate-900/70 border border-slate-800" />
              <div className="h-44 animate-pulse rounded-xl bg-slate-900/70 border border-slate-800" />
            </div>
          </div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <OverviewView
                agents={state.agents}
                baselines={state.baselines}
                logs={state.logs}
                alerts={state.alerts}
                channel={state.settings.preferredChannel}
                onChangeChannel={handleChangeChannel}
                onSimulate={(agentId, scenario) => handleSimulate(agentId, scenario)}
                onUpdateAgentStatus={(agentId, status) => handleUpdateAgent(agentId, { status })}
                onResolveAlert={handleResolveAlert}
                onResetDemo={handleResetDemo}
                busyAction={busyAction}
              />
            )}

            {activeTab === 'agents' && (
              <AgentsChangesView
                agents={state.agents}
                baselines={state.baselines}
                changeLogs={state.changeLogs}
                onOpenRegisterModal={() => setRegisterModalOpen(true)}
                onUpdateAgent={handleUpdateAgent}
                onCreateChange={handleCreateChange}
              />
            )}

            {activeTab === 'activity' && (
              <ActivityAlertsView
                agents={state.agents}
                logs={state.logs}
                alerts={state.alerts}
                channel={state.settings.preferredChannel}
                onChangeChannel={handleChangeChannel}
                onSimulate={handleSimulate}
                onResolveAlert={handleResolveAlert}
                busyAction={busyAction}
              />
            )}

            {activeTab === 'evaluation' && (
              <EvaluationView
                evaluation={evaluation}
                onRunEvaluation={handleRunEvaluation}
                running={evalRunning}
              />
            )}

            {activeTab === 'architecture' && <ArchitectureView />}
          </>
        )}
      </main>

      <RegisterAgentModal
        isOpen={registerModalOpen}
        onClose={() => setRegisterModalOpen(false)}
        onCreateAgent={handleCreateAgent}
      />
    </div>
  );
}
