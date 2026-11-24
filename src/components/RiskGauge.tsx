interface RiskGaugeProps {
  score: number;
  label?: string;
  size?: number;
}

export function RiskGauge({ score, label = 'Risk', size = 84 }: RiskGaugeProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const strokeWidth = 7;
  const radius = (size - strokeWidth) / 2;
  const circumference = Math.PI * radius; // semicircle arc length
  const dashOffset = circumference - (clamped / 100) * circumference;

  const strokeColor =
    clamped >= 70
      ? '#EF4444'
      : clamped >= 36
        ? '#F59E0B'
        : '#10B981';

  const textColor =
    clamped >= 70
      ? 'text-red-400'
      : clamped >= 36
        ? 'text-amber-400'
        : 'text-emerald-400';

  const centerX = size / 2;
  const centerY = size / 2 + 4;

  return (
    <div className="flex flex-col items-center shrink-0" style={{ width: size }}>
      <svg
        width={size}
        height={size * 0.62}
        viewBox={`0 0 ${size} ${size * 0.62}`}
        role="img"
        aria-label={`${label}: ${clamped} out of 100`}
      >
        <path
          d={`M ${strokeWidth / 2} ${centerY} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${centerY}`}
          fill="none"
          stroke="#1E293B"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />
        <path
          d={`M ${strokeWidth / 2} ${centerY} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${centerY}`}
          fill="none"
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{ transition: 'stroke-dashoffset 220ms cubic-bezier(0.16, 1, 0.3, 1)' }}
        />
      </svg>
      <div className="-mt-5 flex flex-col items-center">
        <span className={`font-mono text-lg font-semibold leading-none tabular-nums ${textColor}`}>
          {clamped}
        </span>
        <span className="mt-0.5 text-[11px] text-slate-400">{label}</span>
      </div>
    </div>
  );
}
