"use client";

import * as React from "react";

import { Globe2Icon, Loader2Icon, RefreshCwIcon, XIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { usePoll } from "@/hooks/use-poll";
import { api } from "@/lib/api";
import type { EgressCheck, EgressReport } from "@/lib/types";
import { cn } from "@/lib/utils";

type EgressIpContextValue = {
  enabled: boolean;
  isLoading: boolean;
  report: EgressReport | null;
  error: string | null;
  setEnabled: (enabled: boolean) => Promise<void>;
  probeEgress: () => Promise<EgressReport>;
  dismiss: () => Promise<void>;
};

const EgressIpContext = React.createContext<EgressIpContextValue | null>(null);

// Each poll sends a real request to the echo endpoint, so this stays opt-in
// and off by default: on an engagement, an unattended heartbeat to a public
// service is traffic the operator did not ask for.
export function EgressIpProvider({ children }: { children: React.ReactNode }) {
  const [enabled, setEnabledState] = React.useState(false);
  const [report, setReport] = React.useState<EgressReport | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [isLoading, setIsLoading] = React.useState(false);

  const probeForProxy = React.useCallback(async (globalProxy: string) => {
    setError(null);
    setIsLoading(true);
    try {
      const nextReport = await api.testEgressProxy({ global_proxy: globalProxy });
      setReport(nextReport);
      return nextReport;
    } catch (cause) {
      setReport(null);
      const message = cause instanceof Error ? cause.message : "unknown error";
      setError(message);
      throw cause;
    } finally {
      setIsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    let cancelled = false;
    api
      .settings()
      .then((settings) => {
        if (cancelled) return;
        const nextEnabled = !!settings.show_egress_ip;
        const nextProxy = settings.global_proxy ?? "";
        setEnabledState(nextEnabled);
        if (nextEnabled) void probeForProxy(nextProxy);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [probeForProxy]);

  // `leading: false` matters here: each run sends a real request to the echo endpoint,
  // and the effect above already probes once when the banner is switched on. On an
  // engagement an unattended heartbeat to a public service is traffic the operator did
  // not ask for, so mounting must not gain an extra probe. The visibility gate then
  // cuts the probes sent while nobody is looking; the one it sends on the way back is
  // for a banner someone is reading.
  usePoll(
    async () => {
      const settings = await api.settings();
      await probeForProxy(settings.global_proxy ?? "");
    },
    10000,
    { enabled, leading: false },
  );

  const setEnabled = React.useCallback(
    async (nextEnabled: boolean) => {
      const settings = await api.setSettings({ show_egress_ip: nextEnabled });
      const nextProxy = settings.global_proxy ?? "";
      setEnabledState(nextEnabled);
      if (nextEnabled) {
        await probeForProxy(nextProxy);
      } else {
        setReport(null);
        setError(null);
      }
    },
    [probeForProxy],
  );

  // Re-read settings first, so a proxy saved on the settings page is always the
  // one the navbar probe uses.
  const probeEgress = React.useCallback(async () => {
    const settings = await api.settings();
    const nextProxy = settings.global_proxy ?? "";
    return probeForProxy(nextProxy);
  }, [probeForProxy]);

  const dismiss = React.useCallback(() => setEnabled(false), [setEnabled]);

  const value = React.useMemo(
    () => ({ enabled, isLoading, report, error, setEnabled, probeEgress, dismiss }),
    [dismiss, enabled, error, isLoading, probeEgress, report, setEnabled],
  );

  return <EgressIpContext.Provider value={value}>{children}</EgressIpContext.Provider>;
}

export function useEgressIp() {
  const context = React.useContext(EgressIpContext);
  if (!context) throw new Error("useEgressIp must be used within EgressIpProvider");
  return context;
}

function checkMessage(check: EgressCheck | undefined) {
  if (!check) return "no result";
  if (check.skipped) return "not configured";
  if (check.result.ok) return check.result.exit_ip || "reachable";
  return "probe failed";
}

function IpValue({ label, check }: { label: string; check: EgressCheck | undefined }) {
  const failed = !!check && !check.skipped && !check.result.ok;
  return (
    <span className="min-w-0 truncate" title={`${label}: ${checkMessage(check)}`}>
      <span className="text-muted-foreground">{label}</span> {"· "}
      <span className={cn("font-mono", failed && "text-destructive")}>{checkMessage(check)}</span>
    </span>
  );
}

// EgressIpStatus is the one part of the navbar that changes with the probe
// state. Split out so each state is an early return rather than a ternary
// chain nested three deep.
function EgressIpStatus({
  isLoading,
  error,
  report,
}: {
  isLoading: boolean;
  error: string | null;
  report: EgressReport | null;
}) {
  if (isLoading) {
    return (
      <span className="flex items-center gap-1 text-muted-foreground">
        <Loader2Icon className="size-3 animate-spin" aria-hidden="true" /> Probing exit IP…
      </span>
    );
  }
  if (error) {
    return (
      <span className="truncate text-destructive" title={error}>
        Probe failed: {error}
      </span>
    );
  }
  if (!report) {
    return <span className="text-muted-foreground">No exit IP result yet</span>;
  }
  return (
    <div className="flex min-w-0 items-center gap-3">
      <IpValue label="Direct IP" check={report.checks.find((check) => check.key === "direct")} />
      <IpValue label="Proxy IP" check={report.checks.find((check) => check.key === "global")} />
    </div>
  );
}

export function EgressIpNavbar() {
  const { enabled, report, error, isLoading, probeEgress, dismiss } = useEgressIp();
  if (!enabled) return null;

  return (
    <div className="flex min-w-0 items-center justify-center gap-2 text-xs" role="status" aria-live="polite">
      <Globe2Icon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <EgressIpStatus isLoading={isLoading} error={error} report={report} />
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        onClick={() => void probeEgress()}
        disabled={isLoading}
        aria-label="Refresh exit IP"
      >
        <RefreshCwIcon className={cn("size-3.5", isLoading && "animate-spin")} aria-hidden="true" />
      </Button>
      <Button type="button" variant="ghost" size="icon-sm" onClick={() => void dismiss()} aria-label="Hide exit IP">
        <XIcon className="size-3.5" aria-hidden="true" />
      </Button>
    </div>
  );
}
