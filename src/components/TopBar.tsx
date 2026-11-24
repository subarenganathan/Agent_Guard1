export type NavTab =
  | 'overview'
  | 'agents'
  | 'activity'
  | 'evaluation'
  | 'architecture';

interface TopBarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  onOpenRegisterModal: () => void;
  openAlertsCount: number;
}

const NAV_ITEMS: { id: NavTab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'agents', label: 'Agents & Changes' },
  { id: 'activity', label: 'Activity & Alerts' },
  { id: 'evaluation', label: 'Evaluation' },
  { id: 'architecture', label: 'Architecture' },
];

export function TopBar({
  activeTab,
  onSelectTab,
  onOpenRegisterModal,
  openAlertsCount,
}: TopBarProps) {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-[#0B0F17]/95 backdrop-blur-sm">
      <div className="mx-auto flex max-w-[1400px] items-center justify-between gap-8 px-4 py-3.5 sm:px-6">
        {/* Zone 1: Single-element brand wordmark */}
        <button
          type="button"
          onClick={() => onSelectTab('overview')}
          className="text-left text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded"
        >
          AgentGuard
        </button>

        {/* Zone 2: Clean single-line typography navigation */}
        <nav
          aria-label="Primary"
          className="hidden md:flex items-center gap-6 text-sm font-medium"
        >
          {NAV_ITEMS.map((item) => {
            const isActive = activeTab === item.id;
            const showCount = item.id === 'activity' && openAlertsCount > 0;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectTab(item.id)}
                className={`relative py-1 whitespace-nowrap shrink-0 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 rounded ${
                  isActive
                    ? 'text-slate-100'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <span>
                  {item.label}
                  {showCount ? ` (${openAlertsCount})` : ''}
                </span>
                {isActive && (
                  <span
                    aria-hidden="true"
                    className="absolute inset-x-0 -bottom-[15px] h-0.5 bg-sky-500"
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: Single primary action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onOpenRegisterModal}
            className="rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-sky-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 whitespace-nowrap shrink-0"
          >
            Register Agent
          </button>
        </div>
      </div>

      {/* Mobile navigation strip */}
      <nav
        aria-label="Mobile"
        className="flex md:hidden items-center gap-4 overflow-x-auto border-t border-slate-800/70 px-4 py-2 text-xs font-medium"
      >
        {NAV_ITEMS.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onSelectTab(item.id)}
              className={`py-1 whitespace-nowrap shrink-0 transition-colors ${
                isActive ? 'text-sky-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.label}
              {item.id === 'activity' && openAlertsCount > 0 ? ` (${openAlertsCount})` : ''}
            </button>
          );
        })}
      </nav>
    </header>
  );
}
