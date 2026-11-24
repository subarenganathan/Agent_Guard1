/**
 * ============================================================================
 * AgentGuard Detection & Evaluation Engine (Standalone Research Module)
 * ============================================================================
 *
 * This module encapsulates all behavioral baselining, owner-change correlation,
 * multi-signal anomaly scoring, attack classification, and comparative benchmark
 * evaluation logic for AgentGuard.
 *
 * Design Principles:
 * 1. 24/7 Agent-Native Baselining: Unlike human UEBA systems, AI agents operate
 *    continuously. Time-of-day heuristics are disabled by default unless an owner
 *    explicitly restricts an agent's allowed time window.
 * 2. Range-Based Statistical Modeling: Hourly action volume is modeled as a
 *    dynamic interval [mean - k*std, mean + k*std] (with a variance floor)
 *    learned from the first N normal observations, avoiding brittle static caps.
 * 3. Owner-Aware Change Correlation (Novelty): Behavioral shifts are evaluated
 *    against a cryptographically fingerprinted Owner Change Log. A shift
 *    unbacked by a recent owner change triggers a hard security alert; a shift
 *    matching a recent owner change is downgraded to an owner confirmation
 *    prompt ("Yes, this was me") rather than a hard alert or auto-revocation.
 * 4. Identity vs. Behavior Decomposition: Separates identity-plane signals
 *    (IP region, User-Agent) from behavior-plane signals (scopes, endpoints,
 *    volume, purpose alignment) to distinguish Stolen Tokens from Prompt-
 *    Injection Hijacks and Scope Creep.
 */

import type {
  ActivityEventInput,
  AgentBaseline,
  AgentProfile,
  AgentScope,
  AlertSeverity,
  AnomalyAnalysis,
  AttackClassification,
  EvaluationConfig,
  EvaluationResult,
  FiredSignal,
  MethodMetrics,
  OwnerChangeEntry,
} from '../types/agentguard';

// ----------------------------------------------------------------------------
// 1. Cryptographic Tool & Change Fingerprinting (Pure-TS SHA-256)
// ----------------------------------------------------------------------------

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/**
 * Computes a deterministic SHA-256 hex fingerprint for an agent tool
 * definition or owner change specification. Zero external dependencies so
 * the detection module executes identically on Node.js and browser runtimes.
 */
export function computeToolHash(payload: string): string {
  const utf8 = new TextEncoder().encode(payload.trim());
  const bitLen = utf8.length * 8;
  const paddedLen = Math.ceil((utf8.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(utf8);
  padded[utf8.length] = 0x80;

  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(paddedLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((val) => val.toString(16).padStart(8, '0'))
    .join('');
}

// ----------------------------------------------------------------------------
// 2. Behavioral Baseline Engine (Range-Based, 24/7 Agent-Native)
// ----------------------------------------------------------------------------

export const DEFAULT_K_STD = 2.5;
const MIN_STD_FLOOR = 1.5;

export function createEmptyBaseline(agent: AgentProfile, k = DEFAULT_K_STD): AgentBaseline {
  return {
    agentId: agent.id,
    learnedCount: 0,
    isReady: false,
    actionDistribution: {},
    knownEndpoints: {},
    knownRegions: {},
    knownUserAgents: {},
    hourlyVolumeRange: {
      mean: 0,
      std: MIN_STD_FLOOR,
      k,
      lowerBound: 0,
      upperBound: Math.max(5, agent.maxActionsPerHour * 0.6),
      sampleCount: 0,
    },
    useTimeOfDayRule: agent.allowedTimeWindow !== null,
    lastUpdated: new Date().toISOString(),
  };
}

/**
 * Incrementally updates an agent's behavioral baseline using Welford's online
 * variance algorithm for hourly volume and categorical frequency counters for
 * actions, endpoints, regions, and user-agents.
 */
export function updateBaselineWithEvent(
  baseline: AgentBaseline,
  event: ActivityEventInput,
  learningTarget = 15,
  k = DEFAULT_K_STD
): AgentBaseline {
  const next: AgentBaseline = {
    ...baseline,
    actionDistribution: { ...baseline.actionDistribution },
    knownEndpoints: { ...baseline.knownEndpoints },
    knownRegions: { ...baseline.knownRegions },
    knownUserAgents: { ...baseline.knownUserAgents },
    hourlyVolumeRange: { ...baseline.hourlyVolumeRange },
    lastUpdated: event.timestamp,
  };

  next.actionDistribution[event.action] = (next.actionDistribution[event.action] ?? 0) + 1;
  next.knownEndpoints[event.endpoint] = (next.knownEndpoints[event.endpoint] ?? 0) + 1;
  next.knownRegions[event.region] = (next.knownRegions[event.region] ?? 0) + 1;
  next.knownUserAgents[event.userAgent] = (next.knownUserAgents[event.userAgent] ?? 0) + 1;

  const nPrev = next.hourlyVolumeRange.sampleCount;
  const nNext = nPrev + 1;
  const prevMean = next.hourlyVolumeRange.mean;
  const prevStd = next.hourlyVolumeRange.std;

  // Reconstruct M2 from stored std to support pure incremental updates
  const prevM2 = nPrev > 1 ? Math.pow(prevStd, 2) * (nPrev - 1) : 0;
  const delta = event.volume - prevMean;
  const newMean = prevMean + delta / nNext;
  const delta2 = event.volume - newMean;
  const newM2 = prevM2 + delta * delta2;
  const rawStd = nNext > 1 ? Math.sqrt(Math.max(0, newM2 / (nNext - 1))) : MIN_STD_FLOOR;
  const boundedStd = Math.max(MIN_STD_FLOOR, rawStd);

  next.hourlyVolumeRange = {
    mean: Number(newMean.toFixed(2)),
    std: Number(boundedStd.toFixed(2)),
    k,
    lowerBound: Number(Math.max(0, newMean - k * boundedStd).toFixed(2)),
    upperBound: Number((newMean + k * boundedStd).toFixed(2)),
    sampleCount: nNext,
  };

  next.learnedCount = baseline.learnedCount + 1;
  next.isReady = next.learnedCount >= Math.min(learningTarget, 5);
  return next;
}

export function learnBaselineFromHistory(
  agent: AgentProfile,
  normalEvents: ActivityEventInput[],
  k = DEFAULT_K_STD
): AgentBaseline {
  let baseline = createEmptyBaseline(agent, k);
  for (const evt of normalEvents.slice(0, agent.baselineLearningTarget)) {
    baseline = updateBaselineWithEvent(baseline, evt, agent.baselineLearningTarget, k);
  }
  return baseline;
}

// ----------------------------------------------------------------------------
// 3. Owner Change Log Correlation
// ----------------------------------------------------------------------------

/**
 * Checks whether an observed behavioral shift matches a recent, unexpired entry
 * in the Owner Change Log.
 *
 * Security Invariant: Identity shifts (unfamiliar region + user-agent) are
 * never excused by an owner change entry, because an OAuth token leak from a
 * foreign host cannot be explained by a prompt or tool update.
 */
export function findMatchingOwnerChange(
  event: ActivityEventInput,
  agent: AgentProfile,
  baseline: AgentBaseline,
  changeLogs: OwnerChangeEntry[]
): OwnerChangeEntry | null {
  const eventTime = new Date(event.timestamp).getTime();
  const activeChanges = changeLogs
    .filter((entry) => {
      if (entry.agentId !== agent.id) return false;
      const created = new Date(entry.createdAt).getTime();
      const expires = new Date(entry.expiresAt).getTime();
      return eventTime >= created - 60_000 && eventTime <= expires;
    })
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  if (activeChanges.length === 0) return null;

  const isNovelScope = !agent.allowedScopes.includes(event.scopeUsed);
  const isNovelEndpoint =
    !agent.allowedEndpoints.includes(event.endpoint) ||
    (baseline.isReady && !(event.endpoint in baseline.knownEndpoints));
  const isVolumeSpike =
    baseline.isReady && event.volume > baseline.hourlyVolumeRange.upperBound;

  for (const entry of activeChanges) {
    const scopeMatched = !isNovelScope || entry.addedScopes.includes(event.scopeUsed);
    const endpointMatched =
      !isNovelEndpoint ||
      entry.addedEndpoints.includes(event.endpoint) ||
      entry.changeType === 'new_tool' ||
      entry.changeType === 'new_instruction';
    const volumeMatched =
      !isVolumeSpike ||
      event.volume <= Math.max(baseline.hourlyVolumeRange.upperBound, agent.maxActionsPerHour) * entry.expectedVolumeMultiplier;

    if (
      (isNovelScope && entry.addedScopes.includes(event.scopeUsed)) ||
      (isNovelEndpoint && entry.addedEndpoints.includes(event.endpoint)) ||
      ((isNovelEndpoint || isVolumeSpike) &&
        (entry.changeType === 'new_instruction' || entry.changeType === 'new_tool') &&
        scopeMatched &&
        endpointMatched &&
        volumeMatched)
    ) {
      return entry;
    }
  }

  return null;
}

// ----------------------------------------------------------------------------
// 4. Multi-Signal Anomaly Scoring & Attack Classification
// ----------------------------------------------------------------------------

export const SIGNAL_WEIGHTS = {
  scopeViolation: 0.30,
  endpointNovelty: 0.20,
  volumeDeviation: 0.20,
  identityShift: 0.20,
  unapprovedChange: 0.10,
} as const;

const HIGH_RISK_EXFIL_PATTERNS = ['export', 'dump', 'bulk', 'backup', 'scrape'];

function isPurposeAligned(action: string, endpoint: string, agent: AgentProfile): boolean {
  const text = `${action} ${endpoint}`.toLowerCase();
  if (HIGH_RISK_EXFIL_PATTERNS.some((p) => text.includes(p))) {
    // Only aligned if purpose explicitly mentions export/backup
    return agent.purposeKeywords.some((kw) => HIGH_RISK_EXFIL_PATTERNS.includes(kw.toLowerCase()));
  }
  if (agent.allowedEndpoints.includes(endpoint)) return true;
  return agent.purposeKeywords.some((kw) => text.includes(kw.toLowerCase()));
}

/**
 * Primary AgentGuard scoring function.
 * Combines five interpretable sub-scores into a 0–100 risk score, classifies
 * the attack pattern, and generates human-readable evidence for the owner.
 */
export function scoreActivityEvent(
  event: ActivityEventInput,
  agent: AgentProfile,
  baseline: AgentBaseline,
  changeLogs: OwnerChangeEntry[]
): AnomalyAnalysis {
  const t0 = performance.now();
  const firedSignals: FiredSignal[] = [];

  // --- Signal 1: Scope Violation (0-100) ---
  const scopeApproved = agent.allowedScopes.includes(event.scopeUsed);
  let scopeViolation = 0;
  if (!scopeApproved) {
    // Elevated severity for destructive or outbound scopes
    const highImpactScopes: AgentScope[] = ['delete', 'send_dm', 'follow'];
    scopeViolation = highImpactScopes.includes(event.scopeUsed) ? 100 : 80;
  }

  // --- Signal 2: Endpoint & Purpose Novelty (0-100) ---
  const endpointAllowed = agent.allowedEndpoints.includes(event.endpoint);
  const endpointSeenInBaseline = !baseline.isReady || event.endpoint in baseline.knownEndpoints;
  const actionSeenInBaseline = !baseline.isReady || event.action in baseline.actionDistribution;
  const purposeAligned = isPurposeAligned(event.action, event.endpoint, agent);

  let endpointNovelty = 0;
  if (!endpointAllowed && !purposeAligned) {
    endpointNovelty = 95;
  } else if (!endpointAllowed) {
    endpointNovelty = 75;
  } else if (!endpointSeenInBaseline || !actionSeenInBaseline) {
    endpointNovelty = purposeAligned ? 45 : 80;
  }

  // --- Signal 3: Volume Deviation vs. mean ± k·std (0-100) ---
  let volumeDeviation = 0;
  const { mean, std, upperBound, sampleCount } = baseline.hourlyVolumeRange;
  const effectiveStd = Math.max(MIN_STD_FLOOR, std);
  const zScore = sampleCount >= 3 ? (event.volume - mean) / effectiveStd : 0;

  if (sampleCount >= 3 && event.volume > upperBound) {
    const excessZ = Math.max(0, zScore - baseline.hourlyVolumeRange.k);
    volumeDeviation = Math.min(100, Math.round(55 + excessZ * 15));
  } else if (event.volume > agent.maxActionsPerHour) {
    const ratio = event.volume / Math.max(1, agent.maxActionsPerHour);
    volumeDeviation = Math.min(100, Math.round(60 + (ratio - 1) * 35));
  } else if (sampleCount >= 3 && zScore > 1.8) {
    volumeDeviation = Math.round(25 + (zScore - 1.8) * 20);
  }

  // --- Signal 4: Identity Shift (Region / IP & User-Agent) (0-100) ---
  const regionKnown =
    Object.keys(baseline.knownRegions).length === 0 || event.region in baseline.knownRegions;
  const uaKnown =
    Object.keys(baseline.knownUserAgents).length === 0 ||
    event.userAgent in baseline.knownUserAgents;

  let identityShift = 0;
  if (!regionKnown && !uaKnown) {
    identityShift = 100;
  } else if (!regionKnown || !uaKnown) {
    identityShift = 65;
  }

  // Optional time-of-day window (ONLY if owner explicitly configured one)
  let timeWindowViolation = false;
  if (agent.allowedTimeWindow) {
    const hour = new Date(event.timestamp).getUTCHours();
    const { startHour, endHour } = agent.allowedTimeWindow;
    const withinWindow =
      startHour <= endHour
        ? hour >= startHour && hour <= endHour
        : hour >= startHour || hour <= endHour;
    if (!withinWindow) {
      timeWindowViolation = true;
      firedSignals.push({
        signal: 'time_window_violation',
        label: 'Outside Optional Time Window',
        score: 60,
        weight: 0.1,
        detail: `Activity occurred at ${String(hour).padStart(2, '0')}:00 UTC, outside configured ${startHour}:00–${endHour}:00 window.`,
      });
    }
  }

  // --- Signal 5: Owner Change Log Correlation ---
  const behavioralShiftDetected =
    scopeViolation > 0 || endpointNovelty >= 45 || volumeDeviation >= 50;
  const matchedChange =
    behavioralShiftDetected && identityShift < 65
      ? findMatchingOwnerChange(event, agent, baseline, changeLogs)
      : null;

  let unapprovedChange = 0;
  if (behavioralShiftDetected && !matchedChange) {
    unapprovedChange = 100;
  } else if (identityShift >= 65) {
    unapprovedChange = 100;
  }

  // Build explicit fired signals list for explainability
  if (scopeViolation > 0) {
    firedSignals.push({
      signal: 'scope_violation',
      label: 'Unapproved Scope Used',
      score: scopeViolation,
      weight: SIGNAL_WEIGHTS.scopeViolation,
      detail: `Agent requested scope "${event.scopeUsed}", which is not in approved scopes [${agent.allowedScopes.join(', ')}].`,
    });
  }
  if (endpointNovelty > 0) {
    firedSignals.push({
      signal: 'endpoint_novelty',
      label: 'Novel Endpoint / Purpose Drift',
      score: endpointNovelty,
      weight: SIGNAL_WEIGHTS.endpointNovelty,
      detail: `Action "${event.action}" on ${event.endpoint} deviates from baseline endpoints or stated purpose.`,
    });
  }
  if (volumeDeviation > 0) {
    firedSignals.push({
      signal: 'volume_deviation',
      label: 'Volume Outside Baseline Range',
      score: volumeDeviation,
      weight: SIGNAL_WEIGHTS.volumeDeviation,
      detail: `Volume ${event.volume} req/hr exceeds learned range [${baseline.hourlyVolumeRange.lowerBound}–${upperBound}] (mean ${mean} ± ${baseline.hourlyVolumeRange.k}·${effectiveStd.toFixed(1)}, z=${zScore.toFixed(2)}).`,
    });
  }
  if (identityShift > 0) {
    firedSignals.push({
      signal: 'identity_shift',
      label: 'Token Identity / Environment Shift',
      score: identityShift,
      weight: SIGNAL_WEIGHTS.identityShift,
      detail: `Unrecognized ${!regionKnown && !uaKnown ? 'region & user-agent' : !regionKnown ? 'region' : 'user-agent'}: ${event.region} (${event.ip}) via "${event.userAgent}".`,
    });
  }
  if (matchedChange) {
    firedSignals.push({
      signal: 'owner_change_match',
      label: 'Matched Owner Change Log',
      score: 0,
      weight: 0,
      detail: `Matches owner-approved change "${matchedChange.title}" (${matchedChange.changeType}, hash ${matchedChange.toolHash.slice(0, 10)}…). Routed for confirmation.`,
    });
  } else if (unapprovedChange > 0) {
    firedSignals.push({
      signal: 'unapproved_change',
      label: 'No Matching Owner Change',
      score: unapprovedChange,
      weight: SIGNAL_WEIGHTS.unapprovedChange,
      detail: 'Behavioral or identity shift occurred without any corresponding entry in the Owner Change Log.',
    });
  }

  // --- Weighted Score Fusion + Severity Escalation ---
  let rawScore =
    scopeViolation * SIGNAL_WEIGHTS.scopeViolation +
    endpointNovelty * SIGNAL_WEIGHTS.endpointNovelty +
    volumeDeviation * SIGNAL_WEIGHTS.volumeDeviation +
    identityShift * SIGNAL_WEIGHTS.identityShift +
    unapprovedChange * SIGNAL_WEIGHTS.unapprovedChange +
    (timeWindowViolation ? 12 : 0);

  // Critical single-plane escalations so subtle single-vector attacks are never drowned out
  if (identityShift >= 100) {
    rawScore = Math.max(rawScore, 78);
  } else if (identityShift >= 65 && (endpointNovelty > 0 || volumeDeviation > 0)) {
    rawScore = Math.max(rawScore, 72);
  }

  if (!matchedChange) {
    if (scopeViolation >= 80 && endpointNovelty >= 75) {
      rawScore = Math.max(rawScore, 76);
    } else if (scopeViolation >= 80) {
      rawScore = Math.max(rawScore, 64);
    }
    if (endpointNovelty >= 90 && volumeDeviation >= 55) {
      rawScore = Math.max(rawScore, 84);
    }
    if (volumeDeviation >= 85) {
      rawScore = Math.max(rawScore, 68);
    }
  } else {
    // Owner-approved change: cap risk into the "Confirmation" band (36-52) instead of hard alert
    rawScore = Math.min(52, Math.max(36, Math.round(rawScore * 0.65)));
  }

  const riskScore = Math.min(100, Math.max(0, Math.round(rawScore)));

  // --- Attack Classification ---
  let classification: AttackClassification = 'Normal';
  let severity: AlertSeverity = 'Normal';
  let requiresOwnerConfirmation = false;

  if (matchedChange && identityShift < 65) {
    classification = 'Pending Confirmation';
    severity = 'Confirm';
    requiresOwnerConfirmation = true;
  } else if (identityShift >= 65) {
    classification = 'Likely stolen token';
    severity = riskScore >= 75 ? 'Critical' : 'Warning';
  } else if (
    scopeViolation >= 80 &&
    volumeDeviation < 65 &&
    !HIGH_RISK_EXFIL_PATTERNS.some((p) => `${event.action} ${event.endpoint}`.toLowerCase().includes(p))
  ) {
    classification = 'Scope creep';
    severity = riskScore >= 80 ? 'Critical' : 'Warning';
  } else if (riskScore >= 45 || endpointNovelty >= 75 || volumeDeviation >= 65) {
    classification = 'Likely hijacked agent';
    severity = riskScore >= 75 ? 'Critical' : 'Warning';
  }

  // --- Plain-Language Explanation ---
  let explanation = 'Activity matches learned 24/7 behavioral baseline and token identity.';
  if (classification === 'Pending Confirmation' && matchedChange) {
    explanation = `Behavior shifted (${event.action} at ${event.volume} req/hr), matching your recent "${matchedChange.title}" change. Please confirm this was intentional.`;
  } else if (classification === 'Likely stolen token') {
    explanation = `Token ${event.tokenId} was used from an unfamiliar environment (${event.region}, ${event.userAgent}) without an approved change.`;
  } else if (classification === 'Scope creep') {
    explanation = `Agent attempted unapproved scope "${event.scopeUsed}" on ${event.endpoint} with no matching owner change.`;
  } else if (classification === 'Likely hijacked agent') {
    explanation = `Same token identity (${event.region}), but off-purpose behavior (${event.action}, ${event.volume} req/hr) indicates possible prompt-injection hijack or data exfiltration.`;
  }

  const latencyMs = Number(Math.max(0.18, performance.now() - t0).toFixed(3));

  return {
    riskScore,
    classification,
    severity,
    componentScores: {
      scopeViolation,
      endpointNovelty,
      volumeDeviation,
      identityShift,
      unapprovedChange,
    },
    matchedChangeId: matchedChange?.id ?? null,
    matchedChangeTitle: matchedChange?.title ?? null,
    behavioralShiftDetected,
    firedSignals,
    explanation,
    requiresOwnerConfirmation,
    latencyMs,
  };
}

// ----------------------------------------------------------------------------
// 5. Comparative Evaluation Engine (For Research Paper Benchmarking)
// ----------------------------------------------------------------------------

function createSeededRng(seed: number) {
  let state = seed >>> 0 || 1337;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

function pick<T>(arr: readonly T[], rng: () => number): T {
  return arr[Math.floor(rng() * arr.length)];
}

/**
 * Runs N randomized simulations per scenario and compares:
 * (a) Simple Static Threshold
 * (b) Human-Style UEBA (Business-hours + Geo/IP)
 * (c) AgentGuard Owner-Aware Engine
 */
export function runEvaluationBenchmark(config: EvaluationConfig): EvaluationResult {
  const trials = Math.max(5, Math.min(200, config.trialsPerScenario));
  const baselineCount = Math.max(10, Math.min(40, config.baselineEventsCount));
  const rng = createSeededRng(config.seed ?? Date.now());

  const evalAgent: AgentProfile = {
    id: 'eval-agent-1',
    name: 'EvalSocialAgent',
    platform: 'Instagram',
    purpose: 'Read posts and reply to comments',
    purposeKeywords: ['read', 'post', 'comment', 'reply', 'media'],
    allowedScopes: ['read_posts', 'post_content'],
    allowedEndpoints: ['/v1/media/read', '/v1/comments/reply', '/v1/media/publish'],
    maxActionsPerHour: 45,
    allowedTimeWindow: null, // 24/7 operation
    tokenId: 'oauth_tok_eval_881a',
    status: 'Active',
    riskScore: 0,
    autoRevokeEnabled: false,
    autoRevokeThreshold: 85,
    baselineLearningTarget: baselineCount,
    createdAt: new Date().toISOString(),
  };

  // Build baseline from N normal 24/7 events
  const normalBaselineEvents: ActivityEventInput[] = [];
  const baseRegions = ['US-West (Oregon)', 'US-West (California)'];
  const baseUAs = ['AgentSDK/2.4 (Node/22)'];
  const baseIPs = ['34.210.44.12', '54.187.19.84'];

  for (let i = 0; i < baselineCount; i++) {
    const hour = Math.floor(rng() * 24);
    const ts = new Date(Date.UTC(2026, 10, 20, hour, Math.floor(rng() * 60), 0)).toISOString();
    normalBaselineEvents.push({
      timestamp: ts,
      agentId: evalAgent.id,
      tokenId: evalAgent.tokenId,
      action: rng() > 0.35 ? 'read_feed' : 'reply_comment',
      endpoint: rng() > 0.35 ? '/v1/media/read' : '/v1/comments/reply',
      scopeUsed: rng() > 0.35 ? 'read_posts' : 'post_content',
      volume: Math.round(12 + rng() * 10), // 12–22 req/hr normal
      ip: pick(baseIPs, rng),
      region: pick(baseRegions, rng),
      userAgent: baseUAs[0],
      scenarioLabel: 'normal',
    });
  }

  const baseline = learnBaselineFromHistory(evalAgent, normalBaselineEvents);

  // Create synthetic test suite across 6 scenarios
  interface EvalCase {
    scenario: string;
    isAttack: boolean;
    event: ActivityEventInput;
    changeLogs: OwnerChangeEntry[];
  }

  const cases: EvalCase[] = [];
  const foreignRegions = ['Frankfurt, DE', 'Singapore, SG', 'Sao Paulo, BR', 'Moscow, RU'];
  const foreignUAs = ['python-requests/2.31.0', 'curl/8.5.0', 'Go-http-client/2.0'];
  const foreignIPs = ['185.220.101.4', '103.42.90.18', '177.54.120.9'];

  for (let i = 0; i < trials; i++) {
    const baseTs = new Date(Date.UTC(2026, 10, 22, Math.floor(rng() * 24), Math.floor(rng() * 60), 0));

    // 1. Normal 24/7 operation (benign)
    cases.push({
      scenario: 'normal',
      isAttack: false,
      changeLogs: [],
      event: {
        timestamp: baseTs.toISOString(),
        agentId: evalAgent.id,
        tokenId: evalAgent.tokenId,
        action: rng() > 0.4 ? 'read_feed' : 'reply_comment',
        endpoint: rng() > 0.4 ? '/v1/media/read' : '/v1/comments/reply',
        scopeUsed: rng() > 0.4 ? 'read_posts' : 'post_content',
        volume: Math.round(11 + rng() * 12),
        ip: pick(baseIPs, rng),
        region: pick(baseRegions, rng),
        userAgent: baseUAs[0],
      },
    });

    // 2. Benign Owner-Approved Behavioral Shift (tests false-positive suppression)
    const hasOwnerChange = rng() <= config.ownerChangeRate;
    const approvedChange: OwnerChangeEntry[] = hasOwnerChange
      ? [
          {
            id: `chg-eval-${i}`,
            agentId: evalAgent.id,
            changeType: 'new_scope',
            title: 'Approved DM Campaign Tool',
            description: 'Owner authorized temporary DM read tool & higher throughput',
            toolDefinition: '{"tool":"dm_digest","scope":"read_dm"}',
            toolHash: computeToolHash(`dm_digest_${i}`),
            addedScopes: ['read_dm'],
            addedEndpoints: ['/v1/dm/inbox'],
            expectedVolumeMultiplier: 1.5,
            createdAt: new Date(baseTs.getTime() - 3600_000).toISOString(),
            expiresAt: new Date(baseTs.getTime() + 86400_000).toISOString(),
            confirmedByOwner: false,
          },
        ]
      : [];

    if (hasOwnerChange) {
      cases.push({
        scenario: 'owner_approved_shift',
        isAttack: false,
        changeLogs: approvedChange,
        event: {
          timestamp: baseTs.toISOString(),
          agentId: evalAgent.id,
          tokenId: evalAgent.tokenId,
          action: 'read_dm_inbox',
          endpoint: '/v1/dm/inbox',
          scopeUsed: 'read_dm',
          volume: Math.round(28 + rng() * 14),
          ip: pick(baseIPs, rng),
          region: pick(baseRegions, rng),
          userAgent: baseUAs[0],
        },
      });
    }

    // 3. Stolen Token (new region + new UA, moderate/normal volume)
    cases.push({
      scenario: 'stolen_token',
      isAttack: true,
      changeLogs: [],
      event: {
        timestamp: baseTs.toISOString(),
        agentId: evalAgent.id,
        tokenId: evalAgent.tokenId,
        action: 'read_feed',
        endpoint: '/v1/media/read',
        scopeUsed: 'read_posts',
        volume: Math.round(14 + rng() * 16), // Stays under static volume cap!
        ip: pick(foreignIPs, rng),
        region: pick(foreignRegions, rng),
        userAgent: pick(foreignUAs, rng),
      },
    });

    // 4. Prompt-Injection Hijack (same identity, off-purpose action)
    cases.push({
      scenario: 'prompt_injection',
      isAttack: true,
      changeLogs: [],
      event: {
        timestamp: new Date(Date.UTC(2026, 10, 22, 10 + Math.floor(rng() * 7), 15, 0)).toISOString(), // daytime so human UEBA misses time rule
        agentId: evalAgent.id,
        tokenId: evalAgent.tokenId,
        action: rng() > 0.5 ? 'bulk_send_dm' : 'account_data_export',
        endpoint: rng() > 0.5 ? '/v1/dm/send' : '/v1/account/export',
        scopeUsed: rng() > 0.5 ? 'send_dm' : 'read_posts',
        volume: Math.round(26 + rng() * 16), // Often below static limit 45
        ip: baseIPs[0],
        region: baseRegions[0],
        userAgent: baseUAs[0],
      },
    });

    // 5. Scope Creep (unapproved scope, same identity, normal volume)
    cases.push({
      scenario: 'scope_creep',
      isAttack: true,
      changeLogs: [],
      event: {
        timestamp: new Date(Date.UTC(2026, 10, 22, 11 + Math.floor(rng() * 6), 30, 0)).toISOString(),
        agentId: evalAgent.id,
        tokenId: evalAgent.tokenId,
        action: rng() > 0.5 ? 'delete_media' : 'follow_account',
        endpoint: rng() > 0.5 ? '/v1/media/delete' : '/v1/users/follow',
        scopeUsed: rng() > 0.5 ? 'delete' : 'follow',
        volume: Math.round(8 + rng() * 10),
        ip: baseIPs[0],
        region: baseRegions[0],
        userAgent: baseUAs[0],
      },
    });

    // 6. Burst / Exfiltration (sudden high-volume reads from normal identity)
    cases.push({
      scenario: 'burst_exfiltration',
      isAttack: true,
      changeLogs: [],
      event: {
        timestamp: new Date(Date.UTC(2026, 10, 22, 14, Math.floor(rng() * 60), 0)).toISOString(),
        agentId: evalAgent.id,
        tokenId: evalAgent.tokenId,
        action: 'bulk_read_posts',
        endpoint: '/v1/media/read',
        scopeUsed: 'read_posts',
        volume: Math.round(52 + rng() * 90),
        ip: baseIPs[0],
        region: baseRegions[0],
        userAgent: baseUAs[0],
      },
    });
  }

  // Evaluate each of the 3 methods on identical cases
  const evaluateMethod = (
    methodId: MethodMetrics['methodId'],
    methodName: string,
    description: string,
    detector: (c: EvalCase) => { alerted: boolean; latencyMs: number }
  ): MethodMetrics => {
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;
    let totalLatency = 0;

    const scenarioCounts: Record<string, { total: number; detected: number }> = {};

    for (const c of cases) {
      if (!scenarioCounts[c.scenario]) {
        scenarioCounts[c.scenario] = { total: 0, detected: 0 };
      }
      scenarioCounts[c.scenario].total += 1;

      const { alerted, latencyMs } = detector(c);
      totalLatency += latencyMs;

      if (alerted) {
        scenarioCounts[c.scenario].detected += 1;
      }

      if (c.isAttack && alerted) tp++;
      else if (c.isAttack && !alerted) fn++;
      else if (!c.isAttack && alerted) fp++;
      else tn++;
    }

    const detectionRate = tp + fn > 0 ? tp / (tp + fn) : 0;
    const falsePositiveRate = fp + tn > 0 ? fp / (fp + tn) : 0;
    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const f1Score =
      precision + detectionRate > 0
        ? (2 * precision * detectionRate) / (precision + detectionRate)
        : 0;

    const perScenarioDetection: Record<string, number> = {};
    for (const [scenario, counts] of Object.entries(scenarioCounts)) {
      perScenarioDetection[scenario] = Number(
        ((counts.detected / Math.max(1, counts.total)) * 100).toFixed(1)
      );
    }

    return {
      methodId,
      methodName,
      description,
      tp,
      fp,
      tn,
      fn,
      detectionRate: Number((detectionRate * 100).toFixed(1)),
      falsePositiveRate: Number((falsePositiveRate * 100).toFixed(1)),
      precision: Number((precision * 100).toFixed(1)),
      f1Score: Number((f1Score * 100).toFixed(1)),
      meanLatencyMs: Number((totalLatency / Math.max(1, cases.length)).toFixed(3)),
      perScenarioDetection,
    };
  };

  // Method A: Simple Static Threshold
  const staticMetrics = evaluateMethod(
    'static_threshold',
    'Static Threshold Baseline',
    'Flags only if hourly volume > maxActionsPerHour or scope is not in initial registry.',
    (c) => {
      const t0 = performance.now();
      const volumeFlag = c.event.volume > evalAgent.maxActionsPerHour;
      const scopeFlag = !evalAgent.allowedScopes.includes(c.event.scopeUsed);
      const alerted = volumeFlag || scopeFlag;
      return { alerted, latencyMs: Math.max(0.05, performance.now() - t0) };
    }
  );

  // Method B: Human-Style UEBA (9am-6pm business hours + Geo/IP only)
  const humanUebaMetrics = evaluateMethod(
    'human_ueba',
    'Human-Style UEBA Rules',
    'Applies human 08:00–19:00 UTC business-hour window + IP/region checks; ignores agent purpose & change log.',
    (c) => {
      const t0 = performance.now();
      const hour = new Date(c.event.timestamp).getUTCHours();
      const offHours = hour < 8 || hour > 19;
      const foreignRegion = !(c.event.region in baseline.knownRegions);
      const alerted = offHours || foreignRegion;
      return { alerted, latencyMs: Math.max(0.09, performance.now() - t0) };
    }
  );

  // Method C: AgentGuard Owner-Aware Engine
  const agentGuardMetrics = evaluateMethod(
    'agentguard_owner_aware',
    'AgentGuard Owner-Aware',
    '24/7 mean ± k·std baseline + identity/behavior decomposition + Owner Change Log confirmation routing.',
    (c) => {
      const analysis = scoreActivityEvent(c.event, evalAgent, baseline, c.changeLogs);
      // Hard alerts only fire on Warning/Critical; Confirm prompts suppress false positives!
      const alerted = analysis.severity === 'Warning' || analysis.severity === 'Critical';
      return { alerted, latencyMs: analysis.latencyMs };
    }
  );

  const methods = [staticMetrics, humanUebaMetrics, agentGuardMetrics];

  const csvHeader = [
    'method',
    'tp',
    'fp',
    'tn',
    'fn',
    'detection_rate_pct',
    'false_positive_rate_pct',
    'precision_pct',
    'f1_score_pct',
    'mean_latency_ms',
    'normal_alarm_pct',
    'approved_shift_alarm_pct',
    'stolen_token_det_pct',
    'prompt_injection_det_pct',
    'scope_creep_det_pct',
    'burst_exfiltration_det_pct',
  ].join(',');

  const csvRows = methods.map((m) =>
    [
      `"${m.methodName}"`,
      m.tp,
      m.fp,
      m.tn,
      m.fn,
      m.detectionRate,
      m.falsePositiveRate,
      m.precision,
      m.f1Score,
      m.meanLatencyMs,
      m.perScenarioDetection['normal'] ?? 0,
      m.perScenarioDetection['owner_approved_shift'] ?? 0,
      m.perScenarioDetection['stolen_token'] ?? 0,
      m.perScenarioDetection['prompt_injection'] ?? 0,
      m.perScenarioDetection['scope_creep'] ?? 0,
      m.perScenarioDetection['burst_exfiltration'] ?? 0,
    ].join(',')
  );

  return {
    config,
    totalEventsEvaluated: cases.length,
    attackEventsCount: cases.filter((c) => c.isAttack).length,
    benignEventsCount: cases.filter((c) => !c.isAttack).length,
    methods,
    generatedAt: new Date().toISOString(),
    csvReport: [csvHeader, ...csvRows].join('\n'),
  };
}
