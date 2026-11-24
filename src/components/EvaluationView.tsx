import { Download, Play } from 'lucide-react';
import { useState } from 'react';
import type { EvaluationResult } from '../types/agentguard';

interface EvaluationViewProps {
  evaluation: EvaluationResult | null;
  onRunEvaluation: (config: {
    trialsPerScenario: number;
    baselineEventsCount: number;
    ownerChangeRate: number;
  }) => Promise<void>;
  running: boolean;
}

const SCENARIO_LABELS: { key: string; label: string; kind: 'Benign' | 'Attack' }[] = [
  { key: 'normal', label: 'Normal 24/7 Ops (False Alarm %)', kind: 'Benign' },
  { key: 'owner_approved_shift', label: 'Owner-Approved Shift (False Alarm %)', kind: 'Benign' },
  { key: 'stolen_token', label: 'Stolen Token Detection %', kind: 'Attack' },
  { key: 'prompt_injection', label: 'Prompt-Injection Hijack Detection %', kind: 'Attack' },
  { key: 'scope_creep', label: 'Scope Creep Detection %', kind: 'Attack' },
  { key: 'burst_exfiltration', label: 'Burst / Exfiltration Detection %', kind: 'Attack' },
];

export function EvaluationView({
  evaluation,
  onRunEvaluation,
  running,
}: EvaluationViewProps) {
  const [trialsPerScenario, setTrialsPerScenario] = useState(40);
  const [baselineEventsCount, setBaselineEventsCount] = useState(15);
  const [ownerChangeRate, setOwnerChangeRate] = useState(0.8);

  const handleRun = async (e: React.FormEvent) => {
    e.preventDefault();
    await onRunEvaluation({
      trialsPerScenario,
      baselineEventsCount,
      ownerChangeRate,
    });
  };

  const handleDownloadCsv = () => {
    if (!evaluation) return;
    const blob = new Blob([evaluation.csvReport], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `agentguard_evaluation_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Research Evaluation Mode
          </h1>
          <p className="mt-1 text-sm text-slate-400">
            Benchmark Static Thresholds, Human-Style UEBA, and AgentGuard Owner-Aware Detection across randomized attack trials.
          </p>
        </div>

        {evaluation && (
          <button
            type="button"
            onClick={handleDownloadCsv}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-[#111827] px-4 py-2 text-xs font-semibold text-slate-200 transition-colors hover:border-sky-500/50 hover:text-sky-300 whitespace-nowrap shrink-0"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            Export CSV Report
          </button>
        )}
      </div>

      {/* Benchmark Configuration Form */}
      <form
        onSubmit={handleRun}
        className="rounded-xl border border-slate-800 bg-[#111827] p-5 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 items-end"
      >
        <div>
          <label className="block text-xs font-medium text-slate-300" htmlFor="eval-trials">
            Trials per Attack Scenario (N)
          </label>
          <input
            id="eval-trials"
            type="number"
            min={5}
            max={200}
            value={trialsPerScenario}
            onChange={(e) => setTrialsPerScenario(Number(e.target.value))}
            className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 font-mono text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-300" htmlFor="eval-baseline">
            Baseline Learning Window
          </label>
          <input
            id="eval-baseline"
            type="number"
            min={10}
            max={40}
            value={baselineEventsCount}
            onChange={(e) => setBaselineEventsCount(Number(e.target.value))}
            className="mt-1.5 w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 font-mono text-sm text-slate-100 focus:border-sky-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-300" htmlFor="eval-chg-rate">
            Owner-Approved Shift Rate ({Math.round(ownerChangeRate * 100)}%)
          </label>
          <input
            id="eval-chg-rate"
            type="range"
            min={0}
            max={1}
            step={0.1}
            value={ownerChangeRate}
            onChange={(e) => setOwnerChangeRate(Number(e.target.value))}
            className="mt-3 w-full accent-sky-500"
          />
        </div>

        <button
          type="submit"
          disabled={running}
          className="flex items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2.5 text-xs font-semibold text-white transition-colors hover:bg-sky-500 disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          <Play className="h-3.5 w-3.5" aria-hidden="true" />
          {running ? 'Running Benchmark…' : 'Run Automated Benchmark'}
        </button>
      </form>

      {!evaluation ? (
        <div className="rounded-xl border border-slate-800 bg-[#111827] py-16 text-center text-sm text-slate-400">
          Click <span className="font-semibold text-slate-200">Run Automated Benchmark</span> above to simulate all 6 scenarios and compare the 3 detection methods.
        </div>
      ) : (
        <>
          {/* Summary Context Line */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
            <span>
              Total Events:{' '}
              <span className="font-mono tabular-nums text-slate-200">
                {evaluation.totalEventsEvaluated}
              </span>
            </span>
            <span className="text-slate-600">·</span>
            <span>
              Attack Trials:{' '}
              <span className="font-mono tabular-nums text-slate-200">
                {evaluation.attackEventsCount}
              </span>
            </span>
            <span className="text-slate-600">·</span>
            <span>
              Benign Trials (incl. 24/7 &amp; Approved Shifts):{' '}
              <span className="font-mono tabular-nums text-slate-200">
                {evaluation.benignEventsCount}
              </span>
            </span>
          </div>

          {/* Primary Metrics Comparison Table */}
          <section className="rounded-xl border border-slate-800 bg-[#111827] overflow-hidden">
            <div className="border-b border-slate-800 px-5 py-4">
              <h2 className="text-sm font-semibold text-slate-100">
                Method Comparison Results
              </h2>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 bg-[#0D131F] text-slate-400">
                  <tr>
                    <th className="px-4 py-3 font-medium">Detection Method</th>
                    <th className="px-4 py-3 font-medium text-right">Detection Rate</th>
                    <th className="px-4 py-3 font-medium text-right">False Positive Rate</th>
                    <th className="px-4 py-3 font-medium text-right">Precision</th>
                    <th className="px-4 py-3 font-medium text-right">F1 Score</th>
                    <th className="px-4 py-3 font-medium text-right">Mean Latency</th>
                    <th className="px-4 py-3 font-medium text-right">TP / FP / TN / FN</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {evaluation.methods.map((m) => {
                    const isAgentGuard = m.methodId === 'agentguard_owner_aware';
                    return (
                      <tr
                        key={m.methodId}
                        className={isAgentGuard ? 'bg-sky-500/8' : 'hover:bg-slate-800/30'}
                      >
                        <td className="px-4 py-3.5">
                          <div className={`font-semibold ${isAgentGuard ? 'text-sky-300' : 'text-slate-200'}`}>
                            {m.methodName}
                          </div>
                          <div className="mt-0.5 text-[11px] text-slate-400 max-w-md">
                            {m.description}
                          </div>
                        </td>
                        <td className="px-4 py-3.5 text-right font-mono font-semibold tabular-nums text-emerald-400">
                          {m.detectionRate.toFixed(1)}%
                        </td>
                        <td
                          className={`px-4 py-3.5 text-right font-mono font-semibold tabular-nums ${
                            m.falsePositiveRate <= 5 ? 'text-emerald-400' : 'text-red-400'
                          }`}
                        >
                          {m.falsePositiveRate.toFixed(1)}%
                        </td>
                        <td className="px-4 py-3.5 text-right font-mono tabular-nums text-slate-200">
                          {m.precision.toFixed(1)}%
                        </td>
                        <td className="px-4 py-3.5 text-right font-mono font-semibold tabular-nums text-slate-100">
                          {m.f1Score.toFixed(1)}%
                        </td>
                        <td className="px-4 py-3.5 text-right font-mono tabular-nums text-slate-300">
                          {m.meanLatencyMs.toFixed(3)} ms
                        </td>
                        <td className="px-4 py-3.5 text-right font-mono tabular-nums text-slate-400 whitespace-nowrap">
                          {m.tp} / {m.fp} / {m.tn} / {m.fn}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>

          {/* Grouped Bar Chart + Scenario Breakdown */}
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
            {/* Grouped SVG Bar Chart */}
            <section className="xl:col-span-6 rounded-xl border border-slate-800 bg-[#111827] p-5">
              <h2 className="text-sm font-semibold text-slate-100">
                Key Metrics Bar Comparison
              </h2>
              <p className="mt-0.5 text-xs text-slate-400">
                Higher Detection Rate &amp; F1 Score and lower False Positive Rate indicate stronger accuracy.
              </p>

              <EvaluationBarChart methods={evaluation.methods} />
            </section>

            {/* Per-Scenario Detection Matrix */}
            <section className="xl:col-span-6 rounded-xl border border-slate-800 bg-[#111827] overflow-hidden">
              <div className="border-b border-slate-800 px-5 py-4">
                <h2 className="text-sm font-semibold text-slate-100">
                  Per-Scenario Alarm Rate Matrix
                </h2>
                <p className="mt-0.5 text-xs text-slate-400">
                  Benign scenarios should stay near 0%; attack scenarios should approach 100%.
                </p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-slate-800 bg-[#0D131F] text-slate-400">
                    <tr>
                      <th className="px-4 py-3 font-medium">Scenario</th>
                      <th className="px-4 py-3 font-medium text-right">Static</th>
                      <th className="px-4 py-3 font-medium text-right">Human UEBA</th>
                      <th className="px-4 py-3 font-medium text-right text-sky-300">AgentGuard</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/80">
                    {SCENARIO_LABELS.map((row) => (
                      <tr key={row.key} className="hover:bg-slate-800/30">
                        <td className="px-4 py-3">
                          <span className="text-slate-200 font-medium">{row.label}</span>
                        </td>
                        {evaluation.methods.map((m) => {
                          const val = m.perScenarioDetection[row.key] ?? 0;
                          const isGood =
                            row.kind === 'Benign' ? val <= 10 : val >= 85;
                          return (
                            <td
                              key={m.methodId}
                              className={`px-4 py-3 text-right font-mono tabular-nums font-medium ${
                                isGood ? 'text-emerald-400' : 'text-amber-400'
                              }`}
                            >
                              {val.toFixed(1)}%
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        </>
      )}
    </div>
  );
}

function EvaluationBarChart({ methods }: { methods: EvaluationResult['methods'] }) {
  const width = 560;
  const height = 250;
  const padLeft = 42;
  const padRight = 16;
  const padTop = 24;
  const padBottom = 42;
  const innerW = width - padLeft - padRight;
  const innerH = height - padTop - padBottom;

  const groups = [
    { key: 'detectionRate' as const, label: 'Detection Rate' },
    { key: 'falsePositiveRate' as const, label: 'False Positive Rate' },
    { key: 'f1Score' as const, label: 'F1 Score' },
  ];

  const colors = ['#64748B', '#F59E0B', '#38BDF8'];
  const groupW = innerW / groups.length;
  const barW = 28;
  const barGap = 8;

  return (
    <div className="mt-4 space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs text-slate-300">
        {methods.map((m, idx) => (
          <span key={m.methodId} className="flex items-center gap-1.5">
            <span
              className="inline-block h-2.5 w-2.5 rounded-xs"
              style={{ backgroundColor: colors[idx] }}
            />
            {m.methodName}
          </span>
        ))}
      </div>

      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="w-full h-auto"
        role="img"
        aria-label="Grouped comparison bar chart of Detection Rate, False Positive Rate, and F1 Score"
      >
        {[0, 25, 50, 75, 100].map((tick) => {
          const y = padTop + innerH - (tick / 100) * innerH;
          return (
            <g key={tick}>
              <line
                x1={padLeft}
                y1={y}
                x2={width - padRight}
                y2={y}
                stroke="#1E293B"
                strokeDasharray="2 3"
              />
              <text
                x={padLeft - 8}
                y={y + 3}
                textAnchor="end"
                className="fill-slate-500 font-mono text-[10px]"
              >
                {tick}%
              </text>
            </g>
          );
        })}

        {groups.map((g, gIdx) => {
          const totalGroupBarsW = methods.length * barW + (methods.length - 1) * barGap;
          const startX = padLeft + gIdx * groupW + (groupW - totalGroupBarsW) / 2;

          return (
            <g key={g.key}>
              {methods.map((m, mIdx) => {
                const val = m[g.key];
                const barH = Math.max(2, (val / 100) * innerH);
                const x = startX + mIdx * (barW + barGap);
                const y = padTop + innerH - barH;
                return (
                  <g key={m.methodId}>
                    <rect
                      x={x}
                      y={y}
                      width={barW}
                      height={barH}
                      rx={3}
                      fill={colors[mIdx]}
                    />
                    <text
                      x={x + barW / 2}
                      y={y - 5}
                      textAnchor="middle"
                      className="fill-slate-300 font-mono text-[9px]"
                    >
                      {val.toFixed(0)}
                    </text>
                  </g>
                );
              })}
              <text
                x={padLeft + gIdx * groupW + groupW / 2}
                y={height - 14}
                textAnchor="middle"
                className="fill-slate-300 text-[11px] font-medium"
              >
                {g.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
