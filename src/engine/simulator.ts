import type {
  ActivityEventInput,
  ActivityLog,
  AgentBaseline,
  AgentProfile,
  AppStateResponse,
  AttackScenario,
  GlobalSettings,
  OwnerAlert,
  OwnerChangeEntry,
} from '../types/agentguard';
import {
  computeToolHash,
  createEmptyBaseline,
  DEFAULT_K_STD,
  scoreActivityEvent,
  updateBaselineWithEvent,
} from './detection';

let uidCounter = 1000;
export function nextId(prefix: string): string {
  uidCounter += 1;
  return `${prefix}_${Date.now().toString(36)}_${uidCounter}`;
}

export function generateMockTokenId(platform: string): string {
  const short = platform.toLowerCase().replace(/[^a-z]/g, '').slice(0, 3) || 'agt';
  const rand = Math.random().toString(16).slice(2, 10);
  return `oauth_tok_${short}_${rand}`;
}

const AGENT_NORMAL_PROFILES: Record<
  string,
  {
    actions: { action: string; endpoint: string; scopeUsed: AgentProfile['allowedScopes'][number]; volMin: number; volMax: number }[];
    ip: string;
    region: string;
    userAgent: string;
  }
> = {
  agent_insta_reply: {
    actions: [
      { action: 'read_comments', endpoint: '/v1/media/read', scopeUsed: 'read_posts', volMin: 12, volMax: 22 },
      { action: 'reply_comment', endpoint: '/v1/comments/reply', scopeUsed: 'post_content', volMin: 8, volMax: 16 },
    ],
    ip: '34.211.88.14',
    region: 'US-West (Oregon)',
    userAgent: 'InstaConcierge-SDK/2.4 (Node/22)',
  },
  agent_gmail_triage: {
    actions: [
      { action: 'read_inbox_threads', endpoint: '/v1/gmail/messages', scopeUsed: 'read_dm', volMin: 18, volMax: 30 },
      { action: 'label_priority', endpoint: '/v1/gmail/labels', scopeUsed: 'read_posts', volMin: 14, volMax: 24 },
    ],
    ip: '35.197.42.109',
    region: 'US-East (Virginia)',
    userAgent: 'InboxTriage-Worker/1.9 (Python/3.12)',
  },
  agent_brand_pulse: {
    actions: [
      { action: 'publish_scheduled_post', endpoint: '/v1/media/publish', scopeUsed: 'post_content', volMin: 4, volMax: 10 },
      { action: 'fetch_post_metrics', endpoint: '/v1/media/read', scopeUsed: 'read_posts', volMin: 9, volMax: 17 },
    ],
    ip: '52.38.119.202',
    region: 'US-West (Oregon)',
    userAgent: 'BrandPulse-Scheduler/3.1 (Node/22)',
  },
};

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomPick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

export function buildSimulatedEvent(
  agent: AgentProfile,
  scenario: AttackScenario,
  baseline?: AgentBaseline,
  timestampOverride?: string
): ActivityEventInput {
  const ts = timestampOverride ?? new Date().toISOString();
  const profile = AGENT_NORMAL_PROFILES[agent.id];

  const baseIp = profile?.ip ?? '34.210.55.20';
  const baseRegion =
    profile?.region ??
    (baseline && Object.keys(baseline.knownRegions).length > 0
      ? Object.keys(baseline.knownRegions)[0]
      : 'US-West (Oregon)');
  const baseUA =
    profile?.userAgent ??
    (baseline && Object.keys(baseline.knownUserAgents).length > 0
      ? Object.keys(baseline.knownUserAgents)[0]
      : `${agent.name.replace(/\s+/g, '')}-SDK/2.0 (Node/22)`);

  const normalAction = profile
    ? randomPick(profile.actions)
    : {
        action: 'read_authorized_feed',
        endpoint: agent.allowedEndpoints[0] ?? '/v1/media/read',
        scopeUsed: agent.allowedScopes[0] ?? 'read_posts',
        volMin: Math.max(4, Math.round(agent.maxActionsPerHour * 0.25)),
        volMax: Math.max(10, Math.round(agent.maxActionsPerHour * 0.55)),
      };

  switch (scenario) {
    case 'normal':
      return {
        timestamp: ts,
        agentId: agent.id,
        tokenId: agent.tokenId,
        action: normalAction.action,
        endpoint: normalAction.endpoint,
        scopeUsed: normalAction.scopeUsed,
        volume: randomInt(normalAction.volMin, normalAction.volMax),
        ip: baseIp,
        region: baseRegion,
        userAgent: baseUA,
        scenarioLabel: 'normal',
      };

    case 'stolen_token': {
      const foreign = randomPick([
        { ip: '185.220.101.47', region: 'Frankfurt, DE', ua: 'python-requests/2.31.0' },
        { ip: '103.42.90.18', region: 'Singapore, SG', ua: 'curl/8.5.0' },
        { ip: '91.199.118.210', region: 'Warsaw, PL', ua: 'Go-http-client/2.0' },
      ]);
      return {
        timestamp: ts,
        agentId: agent.id,
        tokenId: agent.tokenId,
        action: normalAction.action,
        endpoint: normalAction.endpoint,
        scopeUsed: normalAction.scopeUsed,
        volume: randomInt(normalAction.volMin, normalAction.volMax + 6),
        ip: foreign.ip,
        region: foreign.region,
        userAgent: foreign.ua,
        scenarioLabel: 'stolen_token',
      };
    }

    case 'prompt_injection': {
      const isGmail = agent.platform === 'Gmail';
      return {
        timestamp: ts,
        agentId: agent.id,
        tokenId: agent.tokenId,
        action: isGmail ? 'bulk_forward_archive' : 'bulk_send_dm',
        endpoint: isGmail ? '/v1/account/export' : '/v1/dm/send',
        scopeUsed: agent.allowedScopes.includes('send_dm') ? 'send_dm' : 'send_dm',
        volume: randomInt(
          Math.round(agent.maxActionsPerHour * 0.9),
          Math.round(agent.maxActionsPerHour * 1.45)
        ),
        ip: baseIp,
        region: baseRegion,
        userAgent: baseUA,
        scenarioLabel: 'prompt_injection',
      };
    }

    case 'scope_creep': {
      const unapprovedCandidates: AgentProfile['allowedScopes'] = [
        'delete',
        'send_dm',
        'follow',
        'read_dm',
        'post_content',
      ];
      const unapprovedScope =
        unapprovedCandidates.find((s) => !agent.allowedScopes.includes(s)) ?? 'delete';
      const scopeEndpointMap: Record<string, { action: string; endpoint: string }> = {
        delete: { action: 'delete_media_item', endpoint: '/v1/media/delete' },
        send_dm: { action: 'send_direct_message', endpoint: '/v1/dm/send' },
        follow: { action: 'follow_user_profile', endpoint: '/v1/users/follow' },
        read_dm: { action: 'read_dm_inbox', endpoint: '/v1/dm/inbox' },
        post_content: { action: 'publish_post', endpoint: '/v1/media/publish' },
        read_posts: { action: 'read_feed', endpoint: '/v1/media/read' },
      };
      const mapped = scopeEndpointMap[unapprovedScope];
      return {
        timestamp: ts,
        agentId: agent.id,
        tokenId: agent.tokenId,
        action: mapped.action,
        endpoint: mapped.endpoint,
        scopeUsed: unapprovedScope,
        volume: randomInt(6, 14),
        ip: baseIp,
        region: baseRegion,
        userAgent: baseUA,
        scenarioLabel: 'scope_creep',
      };
    }

    case 'burst_exfiltration':
      return {
        timestamp: ts,
        agentId: agent.id,
        tokenId: agent.tokenId,
        action: 'bulk_read_exfiltration',
        endpoint: agent.allowedEndpoints[0] ?? '/v1/media/read',
        scopeUsed: agent.allowedScopes[0] ?? 'read_posts',
        volume: randomInt(
          Math.round(agent.maxActionsPerHour * 2.2),
          Math.round(agent.maxActionsPerHour * 3.8)
        ),
        ip: baseIp,
        region: baseRegion,
        userAgent: baseUA,
        scenarioLabel: 'burst_exfiltration',
      };

    case 'owner_approved_shift':
      return {
        timestamp: ts,
        agentId: agent.id,
        tokenId: agent.tokenId,
        action: 'read_dm_inbox',
        endpoint: '/v1/dm/inbox',
        scopeUsed: 'read_dm',
        volume: randomInt(16, 26),
        ip: baseIp,
        region: baseRegion,
        userAgent: baseUA,
        scenarioLabel: 'owner_approved_shift',
      };
  }
}

/**
 * Creates a realistic initial dataset so AgentGuard opens with learned
 * baselines, normal 24/7 activity logs, an active Owner Change Log entry,
 * one pending confirmation prompt, and one active security alert.
 */
export function createSeededState(): AppStateResponse {
  const now = Date.now();
  const hoursAgo = (h: number) => new Date(now - h * 3600_000).toISOString();
  const minsAgo = (m: number) => new Date(now - m * 60_000).toISOString();

  const agents: AgentProfile[] = [
    {
      id: 'agent_insta_reply',
      name: 'InstaReply Concierge',
      platform: 'Instagram',
      purpose: 'Reads post comments and posts helpful customer support replies.',
      purposeKeywords: ['read', 'comment', 'reply', 'post', 'media'],
      allowedScopes: ['read_posts', 'post_content'],
      allowedEndpoints: ['/v1/media/read', '/v1/comments/reply'],
      maxActionsPerHour: 45,
      allowedTimeWindow: null,
      tokenId: 'oauth_tok_ins_8f42a9c1',
      status: 'Active',
      riskScore: 12,
      autoRevokeEnabled: true,
      autoRevokeThreshold: 88,
      baselineLearningTarget: 15,
      createdAt: hoursAgo(96),
    },
    {
      id: 'agent_gmail_triage',
      name: 'InboxTriage Assistant',
      platform: 'Gmail',
      purpose: 'Reads incoming customer inquiry threads and applies priority labels.',
      purposeKeywords: ['read', 'inbox', 'gmail', 'label', 'triage'],
      allowedScopes: ['read_dm', 'read_posts'],
      allowedEndpoints: ['/v1/gmail/messages', '/v1/gmail/labels'],
      maxActionsPerHour: 60,
      allowedTimeWindow: null,
      tokenId: 'oauth_tok_gma_3c19e7b4',
      status: 'Active',
      riskScore: 44,
      autoRevokeEnabled: true,
      autoRevokeThreshold: 85,
      baselineLearningTarget: 15,
      createdAt: hoursAgo(120),
    },
    {
      id: 'agent_brand_pulse',
      name: 'BrandPulse Publisher',
      platform: 'Instagram',
      purpose: 'Publishes scheduled campaign posts and fetches engagement summaries.',
      purposeKeywords: ['publish', 'post', 'media', 'metrics', 'read'],
      allowedScopes: ['read_posts', 'post_content'],
      allowedEndpoints: ['/v1/media/publish', '/v1/media/read'],
      maxActionsPerHour: 35,
      allowedTimeWindow: null,
      tokenId: 'oauth_tok_ins_5d70c2e8',
      status: 'Active',
      riskScore: 81,
      autoRevokeEnabled: false,
      autoRevokeThreshold: 85,
      baselineLearningTarget: 15,
      createdAt: hoursAgo(144),
    },
  ];

  const changeLogs: OwnerChangeEntry[] = [
    {
      id: 'chg_seed_1',
      agentId: 'agent_gmail_triage',
      changeType: 'new_tool',
      title: 'Added Draft Reply Preview Tool',
      description: 'Enabled draft_reply_preview tool so InboxTriage can summarize DM/email threads into drafts.',
      toolDefinition: JSON.stringify(
        {
          tool_name: 'draft_reply_preview',
          endpoint: '/v1/gmail/drafts',
          scope: 'post_content',
          rate_cap_multiplier: 1.4,
        },
        null,
        2
      ),
      toolHash: computeToolHash('draft_reply_preview:/v1/gmail/drafts:post_content:1.4'),
      addedScopes: ['post_content'],
      addedEndpoints: ['/v1/gmail/drafts'],
      expectedVolumeMultiplier: 1.4,
      createdAt: hoursAgo(3),
      expiresAt: new Date(now + 45 * 3600_000).toISOString(),
      confirmedByOwner: false,
    },
    {
      id: 'chg_seed_2',
      agentId: 'agent_insta_reply',
      changeType: 'new_instruction',
      title: 'Black Friday Comment Volume Guidance',
      description: 'Updated prompt instructions to answer holiday shipping FAQs with slightly higher cadence.',
      toolDefinition: 'instruction: prioritize shipping FAQ replies up to 1.3x baseline rate',
      toolHash: computeToolHash('instruction:black_friday_shipping_faq:1.3'),
      addedScopes: [],
      addedEndpoints: [],
      expectedVolumeMultiplier: 1.3,
      createdAt: hoursAgo(18),
      expiresAt: new Date(now + 30 * 3600_000).toISOString(),
      confirmedByOwner: true,
    },
  ];

  const settings: GlobalSettings = {
    defaultAutoRevokeEnabled: true,
    defaultAutoRevokeThreshold: 88,
    preferredChannel: 'push',
    kStdMultiplier: DEFAULT_K_STD,
  };

  const baselines: Record<string, AgentBaseline> = {};
  const logs: ActivityLog[] = [];
  const alerts: OwnerAlert[] = [];

  // Learn baselines from 15 normal 24/7 events per agent
  for (const agent of agents) {
    let baseline = createEmptyBaseline(agent, settings.kStdMultiplier);
    for (let i = 15; i >= 1; i--) {
      const evt = buildSimulatedEvent(agent, 'normal', baseline, minsAgo(90 + i * 28));
      const analysis = scoreActivityEvent(evt, agent, baseline, changeLogs);
      baseline = updateBaselineWithEvent(baseline, evt, agent.baselineLearningTarget, settings.kStdMultiplier);
      if (i <= 3) {
        logs.push({
          ...evt,
          id: nextId('log'),
          analysis,
        });
      }
    }
    baselines[agent.id] = baseline;
  }

  // Inject 1 owner-approved behavioral shift on InboxTriage (routes to Pending Confirmation)
  const gmailAgent = agents[1];
  const gmailShiftEvt: ActivityEventInput = {
    timestamp: minsAgo(14),
    agentId: gmailAgent.id,
    tokenId: gmailAgent.tokenId,
    action: 'create_draft_preview',
    endpoint: '/v1/gmail/drafts',
    scopeUsed: 'post_content',
    volume: 29,
    ip: '35.197.42.109',
    region: 'US-East (Virginia)',
    userAgent: 'InboxTriage-Worker/1.9 (Python/3.12)',
    scenarioLabel: 'owner_approved_shift',
  };
  const gmailAnalysis = scoreActivityEvent(
    gmailShiftEvt,
    gmailAgent,
    baselines[gmailAgent.id],
    changeLogs
  );
  const gmailLogId = nextId('log');
  logs.push({ ...gmailShiftEvt, id: gmailLogId, analysis: gmailAnalysis });
  gmailAgent.riskScore = gmailAnalysis.riskScore;
  alerts.push({
    id: nextId('alt'),
    agentId: gmailAgent.id,
    agentName: gmailAgent.name,
    platform: gmailAgent.platform,
    logId: gmailLogId,
    timestamp: gmailShiftEvt.timestamp,
    riskScore: gmailAnalysis.riskScore,
    classification: gmailAnalysis.classification,
    severity: gmailAnalysis.severity,
    status: 'Open',
    summary: gmailAnalysis.explanation,
    evidence: gmailAnalysis.firedSignals.map((s) => s.detail),
    matchedChangeId: gmailAnalysis.matchedChangeId,
    matchedChangeTitle: gmailAnalysis.matchedChangeTitle,
    autoRevoked: false,
  });

  // Inject 1 unapproved Stolen Token anomaly on BrandPulse Publisher
  const brandAgent = agents[2];
  const stolenEvt: ActivityEventInput = {
    timestamp: minsAgo(4),
    agentId: brandAgent.id,
    tokenId: brandAgent.tokenId,
    action: 'fetch_post_metrics',
    endpoint: '/v1/media/read',
    scopeUsed: 'read_posts',
    volume: 19,
    ip: '185.220.101.47',
    region: 'Frankfurt, DE',
    userAgent: 'python-requests/2.31.0',
    scenarioLabel: 'stolen_token',
  };
  const brandAnalysis = scoreActivityEvent(
    stolenEvt,
    brandAgent,
    baselines[brandAgent.id],
    changeLogs
  );
  const brandLogId = nextId('log');
  logs.push({ ...stolenEvt, id: brandLogId, analysis: brandAnalysis });
  brandAgent.riskScore = brandAnalysis.riskScore;
  alerts.push({
    id: nextId('alt'),
    agentId: brandAgent.id,
    agentName: brandAgent.name,
    platform: brandAgent.platform,
    logId: brandLogId,
    timestamp: stolenEvt.timestamp,
    riskScore: brandAnalysis.riskScore,
    classification: brandAnalysis.classification,
    severity: brandAnalysis.severity,
    status: 'Open',
    summary: brandAnalysis.explanation,
    evidence: brandAnalysis.firedSignals.map((s) => s.detail),
    matchedChangeId: null,
    matchedChangeTitle: null,
    autoRevoked: false,
  });

  // Sort logs and alerts newest first
  logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  alerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return {
    agents,
    baselines,
    changeLogs,
    logs,
    alerts,
    settings,
  };
}
