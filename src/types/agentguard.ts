export type AgentScope =
  | 'read_posts'
  | 'post_content'
  | 'read_dm'
  | 'send_dm'
  | 'follow'
  | 'delete';

export type AgentStatus = 'Active' | 'Paused' | 'Revoked';

export type AgentPlatform = 'Instagram' | 'Gmail' | 'X / Twitter' | 'Slack';

export type ChangeType = 'new_instruction' | 'new_tool' | 'new_scope';

export type AttackScenario =
  | 'normal'
  | 'stolen_token'
  | 'prompt_injection'
  | 'scope_creep'
  | 'burst_exfiltration'
  | 'owner_approved_shift';

export type AttackClassification =
  | 'Normal'
  | 'Pending Confirmation'
  | 'Likely stolen token'
  | 'Likely hijacked agent'
  | 'Scope creep';

export type AlertSeverity = 'Normal' | 'Confirm' | 'Warning' | 'Critical';

export type AlertStatus = 'Open' | 'Confirmed' | 'Paused' | 'Revoked' | 'Auto-Revoked';

export type NotificationChannel = 'push' | 'email' | 'sms';

export interface AllowedTimeWindow {
  startHour: number; // 0-23 UTC/local
  endHour: number;   // 0-23 UTC/local
}

export interface AgentProfile {
  id: string;
  name: string;
  platform: AgentPlatform;
  purpose: string;
  purposeKeywords: string[];
  allowedScopes: AgentScope[];
  allowedEndpoints: string[];
  maxActionsPerHour: number;
  allowedTimeWindow: AllowedTimeWindow | null; // Optional; agents run 24/7 by default
  tokenId: string;
  status: AgentStatus;
  riskScore: number;
  autoRevokeEnabled: boolean;
  autoRevokeThreshold: number;
  baselineLearningTarget: number; // First N normal events used to establish baseline
  createdAt: string;
}

export interface VolumeRange {
  mean: number;
  std: number;
  k: number; // Multiplier for mean ± k * std
  lowerBound: number;
  upperBound: number;
  sampleCount: number;
}

export interface AgentBaseline {
  agentId: string;
  learnedCount: number;
  isReady: boolean;
  actionDistribution: Record<string, number>;
  knownEndpoints: Record<string, number>;
  knownRegions: Record<string, number>;
  knownUserAgents: Record<string, number>;
  hourlyVolumeRange: VolumeRange;
  useTimeOfDayRule: boolean; // False by default because AI agents operate 24/7
  lastUpdated: string;
}

export interface OwnerChangeEntry {
  id: string;
  agentId: string;
  changeType: ChangeType;
  title: string;
  description: string;
  toolDefinition?: string;
  toolHash: string;
  addedScopes: AgentScope[];
  addedEndpoints: string[];
  expectedVolumeMultiplier: number;
  createdAt: string;
  expiresAt: string;
  confirmedByOwner: boolean;
}

export interface ActivityEventInput {
  id?: string;
  timestamp: string;
  agentId: string;
  tokenId: string;
  action: string;
  endpoint: string;
  scopeUsed: AgentScope;
  volume: number;
  ip: string;
  region: string;
  userAgent: string;
  scenarioLabel?: AttackScenario;
}

export interface FiredSignal {
  signal:
    | 'scope_violation'
    | 'endpoint_novelty'
    | 'volume_deviation'
    | 'identity_shift'
    | 'unapproved_change'
    | 'time_window_violation'
    | 'owner_change_match';
  label: string;
  score: number; // 0-100 sub-score
  weight: number;
  detail: string;
}

export interface AnomalyAnalysis {
  riskScore: number; // 0-100
  classification: AttackClassification;
  severity: AlertSeverity;
  componentScores: {
    scopeViolation: number;
    endpointNovelty: number;
    volumeDeviation: number;
    identityShift: number;
    unapprovedChange: number;
  };
  matchedChangeId: string | null;
  matchedChangeTitle: string | null;
  behavioralShiftDetected: boolean;
  firedSignals: FiredSignal[];
  explanation: string;
  requiresOwnerConfirmation: boolean;
  latencyMs: number;
}

export interface ActivityLog extends ActivityEventInput {
  id: string;
  analysis: AnomalyAnalysis;
}

export interface OwnerAlert {
  id: string;
  agentId: string;
  agentName: string;
  platform: AgentPlatform;
  logId: string;
  timestamp: string;
  riskScore: number;
  classification: AttackClassification;
  severity: AlertSeverity;
  status: AlertStatus;
  summary: string;
  evidence: string[];
  matchedChangeId: string | null;
  matchedChangeTitle: string | null;
  autoRevoked: boolean;
  resolvedAt?: string;
  resolvedAction?: string;
}

export interface GlobalSettings {
  defaultAutoRevokeEnabled: boolean;
  defaultAutoRevokeThreshold: number;
  preferredChannel: NotificationChannel;
  kStdMultiplier: number;
}

export interface AppStateResponse {
  agents: AgentProfile[];
  baselines: Record<string, AgentBaseline>;
  changeLogs: OwnerChangeEntry[];
  logs: ActivityLog[];
  alerts: OwnerAlert[];
  settings: GlobalSettings;
}

export interface EvaluationConfig {
  trialsPerScenario: number;
  baselineEventsCount: number;
  ownerChangeRate: number; // Fraction (0..1) of benign shifts backed by Owner Change Log
  seed?: number;
}

export interface MethodMetrics {
  methodId: 'static_threshold' | 'human_ueba' | 'agentguard_owner_aware';
  methodName: string;
  description: string;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  detectionRate: number; // Recall = TP / (TP + FN)
  falsePositiveRate: number; // FPR = FP / (FP + TN)
  precision: number; // TP / (TP + FP)
  f1Score: number;
  meanLatencyMs: number;
  perScenarioDetection: Record<string, number>;
}

export interface EvaluationResult {
  config: EvaluationConfig;
  totalEventsEvaluated: number;
  attackEventsCount: number;
  benignEventsCount: number;
  methods: MethodMetrics[];
  generatedAt: string;
  csvReport: string;
}
