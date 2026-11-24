import { Mail, MessageSquare, Smartphone } from 'lucide-react';
import type { NotificationChannel, OwnerAlert } from '../types/agentguard';

interface SimulatedAlertCardProps {
  alert: OwnerAlert | null;
  channel: NotificationChannel;
  onChangeChannel: (ch: NotificationChannel) => void;
  onResolveAlert: (alertId: string, action: 'confirm_mine' | 'pause_agent' | 'revoke_token') => void;
  busyAlertId: string | null;
}

export function SimulatedAlertCard({
  alert,
  channel,
  onChangeChannel,
  onResolveAlert,
  busyAlertId,
}: SimulatedAlertCardProps) {
  const isBusy = alert ? busyAlertId === alert.id : false;

  const severityLabel =
    alert?.severity === 'Critical'
      ? 'Critical Alert'
      : alert?.severity === 'Confirm'
        ? 'Needs Your Confirmation'
        : 'Security Warning';

  const severityTextClass =
    alert?.severity === 'Critical'
      ? 'text-red-400'
      : alert?.severity === 'Confirm'
        ? 'text-amber-400'
        : 'text-amber-300';

  return (
    <div className="rounded-xl border border-slate-800 bg-[#111827] p-5">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3.5">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">
            Simulated Owner Alert Delivery
          </h3>
          <p className="mt-0.5 text-xs text-slate-400">
            Preview how AgentGuard notifies account owners in real time
          </p>
        </div>

        {/* Interactive channel segmented control */}
        <div className="flex items-center gap-1 rounded-lg bg-[#0B0F17] p-1 border border-slate-800">
          {(
            [
              { id: 'push', label: 'Push', icon: Smartphone },
              { id: 'email', label: 'Email', icon: Mail },
              { id: 'sms', label: 'SMS', icon: MessageSquare },
            ] as const
          ).map(({ id, label, icon: Icon }) => {
            const active = channel === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => onChangeChannel(id)}
                className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  active
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                {label}
              </button>
            );
          })}
        </div>
      </div>

      {!alert ? (
        <div className="py-10 text-center text-xs text-slate-400">
          All security alerts have been resolved. Inject a simulated attack to preview owner notifications.
        </div>
      ) : (
        <div className="mt-4 space-y-4">
          {/* Simulated device/channel frame */}
          <div className="rounded-lg border border-slate-800 bg-[#0B0F17] p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-2">
                <span className={`font-semibold ${severityTextClass}`}>
                  {severityLabel}
                </span>
                <span className="text-slate-600">·</span>
                <span className="text-slate-300 font-medium">{alert.agentName}</span>
                <span className="text-slate-600">·</span>
                <span className="text-slate-400">{alert.platform}</span>
              </div>
              <span className="font-mono text-xs tabular-nums text-slate-300">
                Risk {alert.riskScore}/100
              </span>
            </div>

            {channel === 'email' && (
              <div className="mt-2.5 border-b border-slate-800/80 pb-2 text-xs text-slate-400">
                <div>
                  <span className="text-slate-500">Subject:</span>{' '}
                  <span className="text-slate-200 font-medium">
                    [AgentGuard] {alert.classification} on {alert.agentName} (Risk {alert.riskScore}/100)
                  </span>
                </div>
              </div>
            )}

            {channel === 'sms' && (
              <div className="mt-2 text-[11px] font-mono text-slate-500">
                SMS from AgentGuard Security
              </div>
            )}

            <p className="mt-2.5 text-sm leading-relaxed text-slate-200">
              {alert.summary}
            </p>

            <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
              <span>
                Classification:{' '}
                <span className="font-medium text-slate-200">{alert.classification}</span>
              </span>
              <span className="text-slate-600">·</span>
              <span>
                Status: <span className="font-medium text-slate-200">{alert.status}</span>
              </span>
              <span className="text-slate-600">·</span>
              <span className="font-mono tabular-nums">
                {new Date(alert.timestamp).toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                })}
              </span>
            </div>

            {alert.evidence.length > 0 && (
              <ul className="mt-3 space-y-1 border-t border-slate-800/80 pt-3 text-xs text-slate-400">
                {alert.evidence.slice(0, 3).map((item, idx) => (
                  <li key={idx} className="leading-relaxed">
                    • {item}
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Action buttons */}
          {alert.status === 'Open' ? (
            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onResolveAlert(alert.id, 'confirm_mine')}
                className="rounded-lg bg-emerald-600/20 border border-emerald-500/40 px-3.5 py-2 text-xs font-semibold text-emerald-300 transition-colors hover:bg-emerald-600/30 disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                Yes, this was me
              </button>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onResolveAlert(alert.id, 'pause_agent')}
                className="rounded-lg bg-amber-600/20 border border-amber-500/40 px-3.5 py-2 text-xs font-semibold text-amber-300 transition-colors hover:bg-amber-600/30 disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                Pause agent
              </button>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => onResolveAlert(alert.id, 'revoke_token')}
                className="rounded-lg bg-red-600/20 border border-red-500/40 px-3.5 py-2 text-xs font-semibold text-red-300 transition-colors hover:bg-red-600/30 disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                Revoke token
              </button>
            </div>
          ) : (
            <div className="text-xs text-slate-400">
              Resolved: <span className="text-slate-200">{alert.resolvedAction ?? alert.status}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
