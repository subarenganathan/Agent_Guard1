export function ArchitectureView() {
  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Architecture &amp; Detection Algorithm Reference
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Technical specification for AgentGuard’s modular detection engine (<span className="font-mono text-slate-300">src/engine/detection.ts</span>) and owner-aware scoring pipeline.
        </p>
      </div>

      {/* System Architecture Overview */}
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-4">
        <h2 className="text-base font-semibold text-slate-100">
          01. System Architecture
        </h2>
        <p className="text-sm leading-relaxed text-slate-300">
          AgentGuard separates delegated AI agent monitoring into five decoupled layers running across an Express API backend and a React dashboard:
        </p>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {[
            {
              title: '1. Agent Registry & Policy Store',
              body: 'Stores each delegated agent’s purpose keywords, least-privilege OAuth scopes, allowed API endpoints, hourly cap, optional time window, and mock OAuth token ID.',
            },
            {
              title: '2. 24/7 Behavioral Baseline Engine',
              body: 'Learns normal activity distributions from the first N normal observations using Welford’s online mean/variance algorithm, storing volume as [mean − k·σ, mean + k·σ].',
            },
            {
              title: '3. Owner Change Log Ledger',
              body: 'Captures intentional prompt updates, new tool definitions, and new scopes. Each change receives a deterministic SHA-256 fingerprint for auditability.',
            },
            {
              title: '4. Multi-Signal Scoring & Action Loop',
              body: 'Decomposes identity vs. behavior shifts, routes owner-matched shifts to confirmation ("Yes, this was me"), and supports instant pause or token revocation.',
            },
          ].map((card) => (
            <div
              key={card.title}
              className="rounded-lg border border-slate-800 bg-[#0B0F17] p-4"
            >
              <div className="text-xs font-semibold text-sky-300">{card.title}</div>
              <p className="mt-1.5 text-xs leading-relaxed text-slate-400">{card.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Mathematical Scoring Model */}
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-4">
        <h2 className="text-base font-semibold text-slate-100">
          02. Anomaly Scoring &amp; Signal Decomposition
        </h2>
        <p className="text-sm leading-relaxed text-slate-300">
          Every incoming telemetry event <span className="font-mono text-slate-200">e</span> is evaluated against the agent’s policy <span className="font-mono text-slate-200">A</span>, learned baseline <span className="font-mono text-slate-200">B</span>, and active Owner Change Log entries <span className="font-mono text-slate-200">C</span>:
        </p>

        <div className="rounded-lg border border-slate-800 bg-[#0B0F17] p-4 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed">
          RiskScore(e) = 0.30 · S_scope + 0.20 · S_endpoint + 0.20 · S_volume + 0.20 · S_identity + 0.10 · S_unapproved
        </div>

        <ul className="space-y-2.5 text-xs leading-relaxed text-slate-300">
          <li>
            <span className="font-semibold text-slate-100">Scope Violation (S_scope, 30%):</span> Fires at 80–100 if <span className="font-mono">e.scopeUsed</span> is absent from <span className="font-mono">A.allowedScopes</span> (weighted higher for destructive/outbound scopes such as <span className="font-mono">delete</span> or <span className="font-mono">send_dm</span>).
          </li>
          <li>
            <span className="font-semibold text-slate-100">Endpoint &amp; Purpose Novelty (S_endpoint, 20%):</span> Measures whether <span className="font-mono">e.endpoint</span> and <span className="font-mono">e.action</span> align with registered endpoints, baseline history, and the agent’s stated purpose keywords (flagging bulk DM or data export on read/reply agents).
          </li>
          <li>
            <span className="font-semibold text-slate-100">Volume Deviation (S_volume, 20%):</span> Computes the z-score against the learned 24/7 interval <span className="font-mono">[μ − k·σ, μ + k·σ]</span> with <span className="font-mono">k = 2.5</span> and a minimum variance floor <span className="font-mono">σ ≥ 1.5</span>, eliminating brittle single-number static thresholds.
          </li>
          <li>
            <span className="font-semibold text-slate-100">Identity Shift (S_identity, 20%):</span> Detects unseen IP regions and User-Agent signatures relative to <span className="font-mono">B.knownRegions</span> and <span className="font-mono">B.knownUserAgents</span>.
          </li>
          <li>
            <span className="font-semibold text-slate-100">Unapproved Change Flag (S_unapproved, 10% + gating):</span> If a behavioral shift occurs with no matching entry in <span className="font-mono">C</span>, full anomaly severity applies. If it matches a recent owner-approved change (and identity is unchanged), risk is routed to <span className="font-medium text-amber-300">Pending Confirmation</span> instead of a hard alert.
          </li>
        </ul>
      </section>

      {/* Attack Classification Taxonomy */}
      <section className="rounded-xl border border-slate-800 bg-[#111827] p-6 space-y-4">
        <h2 className="text-base font-semibold text-slate-100">
          03. Attack Classification Logic
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2.5 pr-4 font-medium">Classification</th>
                <th className="py-2.5 pr-4 font-medium">Primary Signals</th>
                <th className="py-2.5 font-medium">Owner Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300">
              <tr>
                <td className="py-3 pr-4 font-semibold text-red-400 whitespace-nowrap">
                  Likely stolen token
                </td>
                <td className="py-3 pr-4">
                  Identity-plane shift (new region/IP + new User-Agent), even when action and volume look normal. Never excused by Owner Change Log.
                </td>
                <td className="py-3">Hard alert / Auto-revoke token</td>
              </tr>
              <tr>
                <td className="py-3 pr-4 font-semibold text-red-400 whitespace-nowrap">
                  Likely hijacked agent
                </td>
                <td className="py-3 pr-4">
                  Same token identity (expected IP &amp; User-Agent), but off-purpose actions (e.g., bulk DM send, data export) or burst read exfiltration.
                </td>
                <td className="py-3">Hard alert / Pause or Revoke</td>
              </tr>
              <tr>
                <td className="py-3 pr-4 font-semibold text-amber-400 whitespace-nowrap">
                  Scope creep
                </td>
                <td className="py-3 pr-4">
                  Agent requests an unapproved OAuth scope without an accompanying Owner Change Log entry.
                </td>
                <td className="py-3">Warning / Owner review</td>
              </tr>
              <tr>
                <td className="py-3 pr-4 font-semibold text-amber-300 whitespace-nowrap">
                  Pending Confirmation
                </td>
                <td className="py-3 pr-4">
                  Behavioral shift matches a recent SHA-256 fingerprinted entry in the Owner Change Log with intact identity.
                </td>
                <td className="py-3">Soft prompt ("Yes, this was me")</td>
              </tr>
              <tr>
                <td className="py-3 pr-4 font-semibold text-emerald-400 whitespace-nowrap">
                  Normal
                </td>
                <td className="py-3 pr-4">
                  Within learned 24/7 range, approved scopes/endpoints, and baseline identity profile.
                </td>
                <td className="py-3">Updates online baseline</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
