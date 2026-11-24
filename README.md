# AgentGuard — Owner-Aware Behavioral Anomaly Alerting for Delegated AI Agents

AgentGuard monitors AI agents that hold delegated OAuth access to user accounts (such as Instagram, Gmail, X, or Slack) using **simulated** telemetry and mock OAuth tokens.

## Architecture

- **`src/engine/detection.ts`**: Standalone, zero-dependency detection and benchmark evaluation module containing:
  - **Pure-TS SHA-256 Fingerprinting (`computeToolHash`)**: Generates deterministic hashes for owner-approved tool definitions and instructions.
  - **24/7 Range-Based Baseline Engine (`updateBaselineWithEvent`, `learnBaselineFromHistory`)**: Uses Welford's online variance algorithm over the first $N$ normal events to store hourly volume as `[mean - k·σ, mean + k·σ]` (`k = 2.5`, `σ ≥ 1.5`) alongside action, endpoint, region, and User-Agent distributions. Time-of-day heuristics are disabled by default because AI agents run 24/7.
  - **Owner Change Log Correlation (`findMatchingOwnerChange`)**: Matches observed behavioral shifts against recent owner-approved changes (`new_instruction`, `new_tool`, `new_scope`). Matched shifts (with intact identity) are routed to **Pending Confirmation** (`"Yes, this was me"`) instead of firing hard alerts. Unmatched shifts amplify anomaly severity. Identity shifts (foreign region/User-Agent) are never excused by owner changes.
  - **Multi-Signal Scoring (`scoreActivityEvent`)**: Computes a `0–100` risk score across five weighted signals (`scopeViolation` 0.30, `endpointNovelty` 0.20, `volumeDeviation` 0.20, `identityShift` 0.20, `unapprovedChange` 0.10) and classifies events into `Normal`, `Pending Confirmation`, `Likely stolen token`, `Likely hijacked agent`, or `Scope creep`.
  - **Comparative Evaluation (`runEvaluationBenchmark`)**: Simulates randomized attack trials across 6 scenarios comparing Static Thresholds, Human-Style UEBA, and AgentGuard Owner-Aware Detection, exporting Detection Rate, False Positive Rate, Precision, F1 Score, Mean Latency, and CSV reports.
- **`src/engine/simulator.ts`**: Generates mock agent telemetry, attack injections, and seeded initial demo data.
- **`server.ts`**: Express API server serving `/api/*` endpoints and Vite/static frontend on port `3000`.
- **`src/components/*`**: Dark security dashboard UI (`Overview`, `Agents & Changes`, `Activity & Alerts`, `Evaluation`, `Architecture`).
