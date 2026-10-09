import { appRoutes } from "../config/appRoutes";

// Page title + description, taken from the route registry so the header,
// sidebar and global search always agree. `children` renders page actions
// or summary figures on the right.
export default function PageHeader({ routeId, description, children }) {
  const route = appRoutes.find((r) => r.id === routeId);
  const Icon = route?.Icon;

  return (
    <header className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
      <div className="min-w-0">
        <h1 className="flex items-center gap-2.5 text-xl sm:text-2xl font-semibold tracking-tight leading-tight text-[color:var(--text-primary)]">
          {Icon && (
            <span className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 grid place-items-center flex-shrink-0">
              <Icon className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            </span>
          )}
          {route?.title}
        </h1>
        <p className="ui-body text-[color:var(--text-secondary)] mt-1">
          {description || route?.description}
        </p>
      </div>
      {children && (
        <div className="flex flex-wrap items-center gap-2 sm:gap-3">
          {children}
        </div>
      )}
    </header>
  );
}
