import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  computeToolHash,
  createEmptyBaseline,
  runEvaluationBenchmark,
  scoreActivityEvent,
  updateBaselineWithEvent,
} from './src/engine/detection.ts';
import {
  buildSimulatedEvent,
  createSeededState,
  generateMockTokenId,
  nextId,
} from './src/engine/simulator.ts';
import type {
  ActivityEventInput,
  AgentPlatform,
  AgentProfile,
  AgentScope,
  AgentStatus,
  AppStateResponse,
  AttackScenario,
  ChangeType,
  EvaluationConfig,
  NotificationChannel,
  OwnerAlert,
  OwnerChangeEntry,
} from './src/types/agentguard.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VALID_SCOPES: AgentScope[] = [
  'read_posts',
  'post_content',
  'read_dm',
  'send_dm',
  'follow',
  'delete',
];

const VALID_PLATFORMS: AgentPlatform[] = ['Instagram', 'Gmail', 'X / Twitter', 'Slack'];

const VALID_SCENARIOS: AttackScenario[] = [
  'normal',
  'stolen_token',
  'prompt_injection',
  'scope_creep',
  'burst_exfiltration',
  'owner_approved_shift',
];

// In-memory store seeded with realistic demo telemetry
let state: AppStateResponse = createSeededState();

function sanitizeString(val: unknown, maxLen = 200): string {
  if (typeof val !== 'string') return '';
  return val.trim().slice(0, maxLen);
}

function parseScopes(input: unknown): AgentScope[] {
  if (!Array.isArray(input)) return [];
  return input.filter((s): s is AgentScope => VALID_SCOPES.includes(s as AgentScope));
}

function parseEndpoints(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return input
    .map((e) => sanitizeString(e, 120))
    .filter((e) => e.startsWith('/'));
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // --- Health & State ---
  app.get('/api/state', (_req, res) => {
    res.json(state);
  });

  // --- Agent Registry ---
  app.post('/api/agents', (req, res) => {
    const name = sanitizeString(req.body?.name, 80);
    const platformRaw = sanitizeString(req.body?.platform, 40) as AgentPlatform;
    const platform = VALID_PLATFORMS.includes(platformRaw) ? platformRaw : 'Instagram';
    const purpose = sanitizeString(req.body?.purpose, 240);
    const allowedScopes = parseScopes(req.body?.allowedScopes);
    const allowedEndpoints = parseEndpoints(req.body?.allowedEndpoints);
    const maxActionsPerHour = Math.max(5, Math.min(1000, Number(req.body?.maxActionsPerHour) || 40));
    const autoRevokeEnabled = Boolean(req.body?.autoRevokeEnabled ?? state.settings.defaultAutoRevokeEnabled);
    const autoRevokeThreshold = Math.max(
      50,
      Math.min(100, Number(req.body?.autoRevokeThreshold) || state.settings.defaultAutoRevokeThreshold)
    );

    if (!name || !purpose || allowedScopes.length === 0) {
      res.status(400).json({
        error: 'Agent name, purpose, and at least one allowed scope are required.',
      });
      return;
    }

    let allowedTimeWindow: AgentProfile['allowedTimeWindow'] = null;
    if (
      req.body?.allowedTimeWindow &&
      typeof req.body.allowedTimeWindow.startHour === 'number' &&
      typeof req.body.allowedTimeWindow.endHour === 'number'
    ) {
      allowedTimeWindow = {
        startHour: Math.max(0, Math.min(23, Math.floor(req.body.allowedTimeWindow.startHour))),
        endHour: Math.max(0, Math.min(23, Math.floor(req.body.allowedTimeWindow.endHour))),
      };
    }

    const keywords = purpose
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((w) => w.length >= 3);

    const agent: AgentProfile = {
      id: nextId('agent'),
      name,
      platform,
      purpose,
      purposeKeywords: keywords.length > 0 ? keywords : ['read', 'post'],
      allowedScopes,
      allowedEndpoints:
        allowedEndpoints.length > 0 ? allowedEndpoints : ['/v1/media/read', '/v1/comments/reply'],
      maxActionsPerHour,
      allowedTimeWindow,
      tokenId: generateMockTokenId(platform),
      status: 'Active',
      riskScore: 0,
      autoRevokeEnabled,
      autoRevokeThreshold,
      baselineLearningTarget: 15,
      createdAt: new Date().toISOString(),
    };

    let baseline = createEmptyBaseline(agent, state.settings.kStdMultiplier);
    // Optional pre-learn N normal events if requested so new agents have immediate baselines
    const prelearnCount = Math.max(0, Math.min(15, Number(req.body?.prelearnEvents ?? 10)));
    for (let i = prelearnCount; i >= 1; i--) {
      const evt = buildSimulatedEvent(
        agent,
        'normal',
        baseline,
        new Date(Date.now() - i * 180_000).toISOString()
      );
      baseline = updateBaselineWithEvent(
        baseline,
        evt,
        agent.baselineLearningTarget,
        state.settings.kStdMultiplier
      );
    }

    state.agents.unshift(agent);
    state.baselines[agent.id] = baseline;

    res.status(201).json({ agent, baseline });
  });

  app.patch('/api/agents/:id', (req, res) => {
    const agent = state.agents.find((a) => a.id === req.params.id);
    if (!agent) {
      res.status(404).json({ error: 'Agent not found.' });
      return;
    }

    if (req.body?.status) {
      const nextStatus = sanitizeString(req.body.status, 20) as AgentStatus;
      if (['Active', 'Paused', 'Revoked'].includes(nextStatus)) {
        agent.status = nextStatus;
        if (nextStatus === 'Active') {
          agent.tokenId = agent.tokenId.startsWith('revoked_')
            ? generateMockTokenId(agent.platform)
            : agent.tokenId;
          agent.riskScore = Math.min(agent.riskScore, 25);
        }
      }
    }

    if (typeof req.body?.autoRevokeEnabled === 'boolean') {
      agent.autoRevokeEnabled = req.body.autoRevokeEnabled;
    }

    if (typeof req.body?.autoRevokeThreshold === 'number') {
      agent.autoRevokeThreshold = Math.max(50, Math.min(100, Math.round(req.body.autoRevokeThreshold)));
    }

    res.json({ agent });
  });

  // --- Owner Change Log ---
  app.post('/api/changes', (req, res) => {
    const agentId = sanitizeString(req.body?.agentId, 80);
    const agent = state.agents.find((a) => a.id === agentId);
    if (!agent) {
      res.status(404).json({ error: 'Target agent not found.' });
      return;
    }

    const changeTypeRaw = sanitizeString(req.body?.changeType, 30) as ChangeType;
    const changeType: ChangeType = ['new_instruction', 'new_tool', 'new_scope'].includes(changeTypeRaw)
      ? changeTypeRaw
      : 'new_instruction';

    const title = sanitizeString(req.body?.title, 120);
    const description = sanitizeString(req.body?.description, 320);
    const toolDefinition = sanitizeString(req.body?.toolDefinition, 2000);
    const addedScopes = parseScopes(req.body?.addedScopes);
    const addedEndpoints = parseEndpoints(req.body?.addedEndpoints);
    const expectedVolumeMultiplier = Math.max(
      1,
      Math.min(5, Number(req.body?.expectedVolumeMultiplier) || 1.4)
    );

    if (!title || !description) {
      res.status(400).json({ error: 'Change title and description are required.' });
      return;
    }

    const hashSource = `${agent.id}:${changeType}:${title}:${toolDefinition}:${addedScopes.join(',')}:${addedEndpoints.join(',')}`;
    const entry: OwnerChangeEntry = {
      id: nextId('chg'),
      agentId: agent.id,
      changeType,
      title,
      description,
      toolDefinition: toolDefinition || undefined,
      toolHash: computeToolHash(hashSource),
      addedScopes,
      addedEndpoints,
      expectedVolumeMultiplier,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 48 * 3600_000).toISOString(),
      confirmedByOwner: false,
    };

    state.changeLogs.unshift(entry);
    res.status(201).json({ change: entry });
  });

  // --- Activity Simulator & Anomaly Detection ---
  app.post('/api/simulate', (req, res) => {
    const agentId = sanitizeString(req.body?.agentId, 80);
    const agent = state.agents.find((a) => a.id === agentId);
    if (!agent) {
      res.status(404).json({ error: 'Agent not found.' });
      return;
    }

    if (agent.status !== 'Active') {
      res.status(409).json({
        error: `Agent "${agent.name}" is ${agent.status}. Reactivate the agent before simulating new traffic.`,
      });
      return;
    }

    const scenarioRaw = sanitizeString(req.body?.scenario, 40) as AttackScenario;
    const scenario: AttackScenario = VALID_SCENARIOS.includes(scenarioRaw) ? scenarioRaw : 'normal';

    const baseline = state.baselines[agent.id] ?? createEmptyBaseline(agent, state.settings.kStdMultiplier);

    let eventInput: ActivityEventInput = buildSimulatedEvent(agent, scenario, baseline);

    // Allow optional parameter overrides for custom simulations
    if (req.body?.custom) {
      const c = req.body.custom;
      eventInput = {
        ...eventInput,
        action: sanitizeString(c.action, 80) || eventInput.action,
        endpoint: sanitizeString(c.endpoint, 120) || eventInput.endpoint,
        scopeUsed: VALID_SCOPES.includes(c.scopeUsed) ? c.scopeUsed : eventInput.scopeUsed,
        volume: typeof c.volume === 'number' ? Math.max(1, Math.min(5000, c.volume)) : eventInput.volume,
        region: sanitizeString(c.region, 80) || eventInput.region,
        userAgent: sanitizeString(c.userAgent, 120) || eventInput.userAgent,
      };
    }

    const analysis = scoreActivityEvent(eventInput, agent, baseline, state.changeLogs);
    const logId = nextId('log');
    const logEntry = {
      ...eventInput,
      id: logId,
      analysis,
    };

    state.logs.unshift(logEntry);
    if (state.logs.length > 250) {
      state.logs = state.logs.slice(0, 250);
    }

    // Update baseline only for clean normal behavior so attacks never poison the baseline
    if (analysis.classification === 'Normal' && analysis.riskScore < 35) {
      state.baselines[agent.id] = updateBaselineWithEvent(
        baseline,
        eventInput,
        agent.baselineLearningTarget,
        state.settings.kStdMultiplier
      );
      agent.riskScore = Math.round(agent.riskScore * 0.6 + analysis.riskScore * 0.4);
    } else {
      agent.riskScore = analysis.riskScore;
    }

    let createdAlert: OwnerAlert | null = null;
    let autoRevoked = false;

    if (analysis.severity !== 'Normal') {
      if (
        !analysis.requiresOwnerConfirmation &&
        agent.autoRevokeEnabled &&
        analysis.riskScore >= agent.autoRevokeThreshold
      ) {
        autoRevoked = true;
        agent.status = 'Revoked';
        agent.tokenId = `revoked_${agent.tokenId}`;
      }

      createdAlert = {
        id: nextId('alt'),
        agentId: agent.id,
        agentName: agent.name,
        platform: agent.platform,
        logId,
        timestamp: eventInput.timestamp,
        riskScore: analysis.riskScore,
        classification: analysis.classification,
        severity: analysis.severity,
        status: autoRevoked ? 'Auto-Revoked' : 'Open',
        summary: analysis.explanation,
        evidence: analysis.firedSignals.map((s) => s.detail),
        matchedChangeId: analysis.matchedChangeId,
        matchedChangeTitle: analysis.matchedChangeTitle,
        autoRevoked,
        resolvedAt: autoRevoked ? new Date().toISOString() : undefined,
        resolvedAction: autoRevoked
          ? `Auto-revoked token (risk ${analysis.riskScore} >= threshold ${agent.autoRevokeThreshold})`
          : undefined,
      };
      state.alerts.unshift(createdAlert);
    }

    res.status(201).json({
      log: logEntry,
      alert: createdAlert,
      agent,
      baseline: state.baselines[agent.id],
      autoRevoked,
    });
  });

  // --- Alert Resolution Actions ---
  app.post('/api/alerts/:id/resolve', (req, res) => {
    const alert = state.alerts.find((a) => a.id === req.params.id);
    if (!alert) {
      res.status(404).json({ error: 'Alert not found.' });
      return;
    }

    const action = sanitizeString(req.body?.action, 30);
    const agent = state.agents.find((a) => a.id === alert.agentId);
    const log = state.logs.find((l) => l.id === alert.logId);

    if (action === 'confirm_mine') {
      alert.status = 'Confirmed';
      alert.resolvedAt = new Date().toISOString();
      alert.resolvedAction = 'Yes, this was me — baseline & permissions updated';

      if (alert.matchedChangeId) {
        const chg = state.changeLogs.find((c) => c.id === alert.matchedChangeId);
        if (chg) chg.confirmedByOwner = true;
      }

      if (agent && log) {
        if (!agent.allowedScopes.includes(log.scopeUsed)) {
          agent.allowedScopes.push(log.scopeUsed);
        }
        if (!agent.allowedEndpoints.includes(log.endpoint)) {
          agent.allowedEndpoints.push(log.endpoint);
        }
        const currentBaseline =
          state.baselines[agent.id] ?? createEmptyBaseline(agent, state.settings.kStdMultiplier);
        state.baselines[agent.id] = updateBaselineWithEvent(
          currentBaseline,
          log,
          agent.baselineLearningTarget,
          state.settings.kStdMultiplier
        );
        agent.riskScore = 15;
        if (agent.status === 'Paused') {
          agent.status = 'Active';
        }
      }
    } else if (action === 'pause_agent') {
      alert.status = 'Paused';
      alert.resolvedAt = new Date().toISOString();
      alert.resolvedAction = 'Owner paused agent';
      if (agent) agent.status = 'Paused';
    } else if (action === 'revoke_token') {
      alert.status = 'Revoked';
      alert.resolvedAt = new Date().toISOString();
      alert.resolvedAction = 'Owner revoked OAuth token';
      if (agent) {
        agent.status = 'Revoked';
        if (!agent.tokenId.startsWith('revoked_')) {
          agent.tokenId = `revoked_${agent.tokenId}`;
        }
      }
    } else {
      res.status(400).json({ error: 'Invalid resolution action.' });
      return;
    }

    res.json({ alert, agent, baseline: agent ? state.baselines[agent.id] : undefined });
  });

  // --- Evaluation Benchmark Mode ---
  app.post('/api/evaluate', (req, res) => {
    const trialsPerScenario = Math.max(5, Math.min(200, Number(req.body?.trialsPerScenario) || 30));
    const baselineEventsCount = Math.max(
      10,
      Math.min(40, Number(req.body?.baselineEventsCount) || 15)
    );
    const ownerChangeRate = Math.max(
      0,
      Math.min(1, Number(req.body?.ownerChangeRate ?? 0.8))
    );
    const seed = typeof req.body?.seed === 'number' ? req.body.seed : Date.now();

    const config: EvaluationConfig = {
      trialsPerScenario,
      baselineEventsCount,
      ownerChangeRate,
      seed,
    };

    const result = runEvaluationBenchmark(config);
    res.json(result);
  });

  // --- Settings & Reset ---
  app.post('/api/settings', (req, res) => {
    if (typeof req.body?.defaultAutoRevokeEnabled === 'boolean') {
      state.settings.defaultAutoRevokeEnabled = req.body.defaultAutoRevokeEnabled;
    }
    if (typeof req.body?.defaultAutoRevokeThreshold === 'number') {
      state.settings.defaultAutoRevokeThreshold = Math.max(
        50,
        Math.min(100, Math.round(req.body.defaultAutoRevokeThreshold))
      );
    }
    const channel = sanitizeString(req.body?.preferredChannel, 16) as NotificationChannel;
    if (['push', 'email', 'sms'].includes(channel)) {
      state.settings.preferredChannel = channel;
    }
    res.json({ settings: state.settings });
  });

  app.post('/api/reset', (_req, res) => {
    state = createSeededState();
    res.json(state);
  });

  // --- Vite / Static Frontend Serving ---
  const isProd = process.env.NODE_ENV === 'production';
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distDir)) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    }
  }

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, '0.0.0.0', () => {
    console.log(`AgentGuard server running at http://localhost:${port}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start AgentGuard server:', err);
  process.exit(1);
});
