"use client";

import * as React from "react";

import { CheckIcon, Trash2Icon, WaypointsIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { ProxyPoolEntry, ProxySwitchLog, Settings } from "@/lib/types";

function healthTone(entry: ProxyPoolEntry): "default" | "secondary" | "destructive" | "outline" {
  if (!entry.enabled) return "outline";
  if (entry.health === "healthy") return "default";
  if (entry.health === "unhealthy-cooling") return "destructive";
  return "secondary";
}

function healthText(entry: ProxyPoolEntry): string {
  if (!entry.enabled) return "disabled";
  if (entry.health === "unhealthy-cooling") {
    return `cooling down · ${entry.consecutive_failures} consecutive failures`;
  }
  return entry.health;
}

export function ProxyPoolCard({
  settings,
  loaded,
  onSettingsSaved,
}: {
  settings: Settings | null;
  loaded: boolean;
  onSettingsSaved: (next: Settings) => void;
}) {
  const [entries, setEntries] = React.useState<ProxyPoolEntry[]>([]);
  const [activeID, setActiveID] = React.useState("");
  const [switchLog, setSwitchLog] = React.useState<ProxySwitchLog[]>([]);
  const [importText, setImportText] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  const reload = React.useCallback(async () => {
    const pool = await api.proxyPool();
    setEntries(pool.entries);
    setActiveID(pool.active_id);
    setSwitchLog(pool.switch_log);
  }, []);

  React.useEffect(() => {
    void reload().catch(() => undefined);
  }, [reload]);

  // Every mutation refetches instead of patching local state: the server may
  // switch the active entry as a side effect of a delete, disable or health
  // check, and a locally-patched list would not show that.
  const run = async (what: string, action: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await action();
      await reload();
    } catch (e) {
      toast.error(`${what} failed: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const saveSetting = (patch: Partial<Settings>, what: string) => {
    setBusy(true);
    api
      .setSettings(patch)
      .then(onSettingsSaved)
      .catch((e) => toast.error(`${what} failed: ${(e as Error).message}`))
      .finally(() => setBusy(false));
  };

  const doImport = () =>
    run("Import", async () => {
      const result = await api.importProxyPool({ text: importText });
      setImportText("");
      const added = result.entries.length - entries.length;
      if (result.errors.length) {
        toast.warning(`Imported ${Math.max(added, 0)}; ${result.errors.length} line(s) rejected: ${result.errors[0].error}`);
      } else {
        toast.success(`Imported ${Math.max(added, 0)} proxy entries`);
      }
    });

  const strategy = settings?.proxy_rotate_strategy ?? "sequential";

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <WaypointsIcon className="size-4" />
          Proxy pool
        </CardTitle>
        <CardDescription>
          Several egress proxies with health checks. Agents are handed one stable local address, so switching the active
          entry takes effect on the next request without rebuilding agents or MCP servers — and proxy credentials never
          reach the agent environment.
          <br />
          A failing proxy is cooled off after the configured number of consecutive failures and the pool switches to the
          next healthy member. When no healthy member is left, running tasks are <b>paused</b> and resumed automatically
          once one answers again.
          <br />
          Once the pool holds an entry it owns the active route: the single <b>Global proxy</b> field above becomes a
          read-only echo of the active entry.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          {entries.length === 0 && (
            <p className="text-muted-foreground text-xs">No entries — the global proxy field above is still in charge.</p>
          )}
          {entries.map((entry) => (
            <div key={entry.id} className="flex flex-wrap items-center gap-2 rounded-md border px-2 py-1.5 text-xs">
              <span className="font-mono">{entry.url}</span>
              {entry.id === activeID && <Badge variant="default">active</Badge>}
              <Badge variant={healthTone(entry)}>{healthText(entry)}</Badge>
              {entry.egress_ip && <span className="text-muted-foreground">exit {entry.egress_ip}</span>}
              {entry.latency_ms ? <span className="text-muted-foreground">{entry.latency_ms}ms</span> : null}
              {entry.last_error && (
                <span className="truncate text-destructive" title={entry.last_error}>
                  {entry.last_error}
                </span>
              )}
              <div className="ml-auto flex items-center gap-1">
                <Switch
                  aria-label={`Enable ${entry.url}`}
                  checked={entry.enabled}
                  disabled={!loaded || busy}
                  onCheckedChange={(v) => void run("Update", () => api.updateProxyPool(entry.id, { enabled: v }))}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  disabled={!loaded || busy}
                  onClick={() => void run("Test", () => api.testProxyPoolEntry(entry.id))}
                >
                  Test
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Activate ${entry.url}`}
                  disabled={!loaded || busy || entry.id === activeID}
                  onClick={() => void run("Activate", () => api.activateProxyPool(entry.id))}
                >
                  <CheckIcon className="size-3.5" />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Delete ${entry.url}`}
                  disabled={!loaded || busy}
                  onClick={() => void run("Delete", () => api.deleteProxyPool(entry.id))}
                >
                  <Trash2Icon className="size-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>

        <Label htmlFor="proxy-pool-import" className="text-sm font-normal text-muted-foreground">
          Add proxies (one per line)
        </Label>
        <Textarea
          id="proxy-pool-import"
          rows={3}
          placeholder={"http://user:pass@host:8080\nsocks5://host:1080"}
          value={importText}
          disabled={!loaded || busy}
          onChange={(e) => setImportText(e.target.value)}
        />
        <div className="flex items-center gap-2">
          <Button type="button" onClick={() => void doImport()} disabled={!loaded || busy || !importText.trim()}>
            Import
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!loaded || busy || entries.length === 0}
            onClick={() => void run("Health check", () => api.testAllProxyPool())}
          >
            Check all
          </Button>
        </div>

        <div className="flex flex-col gap-3 border-t pt-3">
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="proxy-rotate-failure" className="text-sm font-normal text-muted-foreground">
              Switch to the next healthy proxy on failure
            </Label>
            <Switch
              id="proxy-rotate-failure"
              checked={!!settings?.proxy_rotate_on_failure}
              disabled={!loaded || busy}
              onCheckedChange={(v) => saveSetting({ proxy_rotate_on_failure: v }, "Save")}
            />
          </div>
          <div className="flex items-center justify-between gap-4">
            <Label htmlFor="proxy-rotate-timed" className="text-sm font-normal text-muted-foreground">
              Rotate on a timer
            </Label>
            <Switch
              id="proxy-rotate-timed"
              checked={!!settings?.proxy_rotate_timed_enabled}
              disabled={!loaded || busy}
              onCheckedChange={(v) => saveSetting({ proxy_rotate_timed_enabled: v }, "Save")}
            />
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="flex flex-col gap-1">
              <Label htmlFor="proxy-rotate-interval" className="text-xs font-normal text-muted-foreground">
                Rotation interval (s)
              </Label>
              <Input
                id="proxy-rotate-interval"
                type="number"
                min={3}
                defaultValue={settings?.proxy_rotate_interval_seconds ?? 30}
                disabled={!loaded || busy}
                onBlur={(e) => saveSetting({ proxy_rotate_interval_seconds: Number(e.target.value) }, "Save")}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="proxy-health-threshold" className="text-xs font-normal text-muted-foreground">
                Failures before cooling off
              </Label>
              <Input
                id="proxy-health-threshold"
                type="number"
                min={1}
                defaultValue={settings?.proxy_health_fail_threshold ?? 3}
                disabled={!loaded || busy}
                onBlur={(e) => saveSetting({ proxy_health_fail_threshold: Number(e.target.value) }, "Save")}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="proxy-health-cooldown" className="text-xs font-normal text-muted-foreground">
                Cool-off (s)
              </Label>
              <Input
                id="proxy-health-cooldown"
                type="number"
                min={1}
                defaultValue={settings?.proxy_health_cooldown_seconds ?? 60}
                disabled={!loaded || busy}
                onBlur={(e) => saveSetting({ proxy_health_cooldown_seconds: Number(e.target.value) }, "Save")}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="proxy-reconnect-max" className="text-xs font-normal text-muted-foreground">
                Auto-resume attempts
              </Label>
              <Input
                id="proxy-reconnect-max"
                type="number"
                min={0}
                defaultValue={settings?.proxy_reconnect_max_attempts ?? 5}
                disabled={!loaded || busy}
                onBlur={(e) => saveSetting({ proxy_reconnect_max_attempts: Number(e.target.value) }, "Save")}
              />
            </div>
          </div>
          <p className="text-muted-foreground text-xs">
            Rotation order: <b>{strategy}</b>. Change it with the API field <code>proxy_rotate_strategy</code> (
            <code>sequential</code> or <code>random</code>).
          </p>
        </div>

        {switchLog.length > 0 && (
          <div className="flex flex-col gap-0.5 border-t pt-3 text-xs text-muted-foreground">
            <span className="font-medium">Recent switches</span>
            {switchLog.slice(0, 5).map((log) => (
              <span key={`${log.at}-${log.to}`} className="font-mono">
                {log.at} · {log.from || "(none)"} → {log.to || "(none)"} · {log.reason}
              </span>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
