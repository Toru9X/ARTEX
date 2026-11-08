"use client";

import * as React from "react";

import {
  CpuIcon,
  EyeOffIcon,
  FlaskConicalIcon,
  Globe2Icon,
  KeyboardIcon,
  RadioTowerIcon,
  SearchIcon,
  ShieldAlertIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { CHAT_SEND_MODE_OPTIONS, type ChatSendMode, setChatSendMode, useChatSendMode } from "@/lib/chat-send-mode";
import type { EgressCheck, Settings } from "@/lib/types";
import { cn } from "@/lib/utils";

import { useEgressIp } from "../../_components/egress-ip-banner";
import { BasicAuthCard } from "./_components/basic-auth-card";
import { ProxyPoolCard } from "./_components/proxy-pool-card";

// egressCheckText renders one probe row: the skip reason, the exit IP, or the
// most specific failure available. probes[] carries the per-address error,
// which says far more than the summary ("every probe address failed").
function egressCheckText(check: EgressCheck): string {
  if (check.skipped) return check.skip_reason ?? "skipped";
  if (check.result.ok) {
    return `${check.result.exit_ip} · ${check.result.via_label} · ${check.result.latency_ms}ms`;
  }
  return check.result.probes.at(-1)?.error || check.result.error || "failed";
}

export default function SystemSettingsPage() {
  const [trafficCapture, setTrafficCapture] = React.useState(false);
  const [agentTrafficBinding, setAgentTrafficBinding] = React.useState(false);
  const [webSearch, setWebSearch] = React.useState(false);
  const [backend, setBackend] = React.useState("ddgs");
  const [braveKeySet, setBraveKeySet] = React.useState(false);
  const [braveKeyInput, setBraveKeyInput] = React.useState("");
  const [tavilyKeySet, setTavilyKeySet] = React.useState(false);
  const [tavilyKeyInput, setTavilyKeyInput] = React.useState("");
  const [savingTavilyKey, setSavingTavilyKey] = React.useState(false);
  const [proxyInput, setProxyInput] = React.useState("");
  const [savingProxy, setSavingProxy] = React.useState(false);
  const [globalProxyInput, setGlobalProxyInput] = React.useState("");
  const [savingGlobalProxy, setSavingGlobalProxy] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [browserScreenshot, setBrowserScreenshot] = React.useState(false);
  const [deepSeekSearchKey, setDeepSeekSearchKey] = React.useState("");
  const [deepSeekSearchBaseURL, setDeepSeekSearchBaseURL] = React.useState("");
  const [deepSeekSearchModel, setDeepSeekSearchModel] = React.useState("");
  const [deepSeekKeySet, setDeepSeekKeySet] = React.useState(false);
  const [browserScreenshotTimestamp, setBrowserScreenshotTimestamp] = React.useState(false);
  const [intelligenceEnabled, setIntelligenceEnabled] = React.useState(false);
  const [credentialAgent, setCredentialAgent] = React.useState(false);
  const [credentialBinding, setCredentialBinding] = React.useState(false);
  const [savingIntelligence, setSavingIntelligence] = React.useState(false);
  const [savingCredentials, setSavingCredentials] = React.useState(false);
  const [taskAutoTitleEnabled, setTaskAutoTitleEnabled] = React.useState(false);
  const [chatAutoTitleEnabled, setChatAutoTitleEnabled] = React.useState(false);
  // The full settings object, so child cards can read fields the page itself
  // does not keep in its own state.
  const [settings, setSettings] = React.useState<Settings | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [savingKey, setSavingKey] = React.useState(false);
  const [pyInterp, setPyInterp] = React.useState("");
  const [workers, setWorkers] = React.useState("3");
  const [savingWorkers, setSavingWorkers] = React.useState(false);
  // Operation constraint injection scope (both on by default).
  const [injectPlanner, setInjectPlanner] = React.useState(true);
  const [injectWorker, setInjectWorker] = React.useState(true);
  // Experimental: noa context compaction (off by default).
  const [noaCompaction, setNoaCompaction] = React.useState(false);
  // OPSEC prompt block appended to every agent's system prompt (off by default).
  const [opsecEnabled, setOpsecEnabled] = React.useState(false);
  // Custom IP-echo endpoint for the egress probe (empty = built-in public ones).
  const [probeUrlInput, setProbeUrlInput] = React.useState("");
  const [savingProbeUrl, setSavingProbeUrl] = React.useState(false);
  const {
    enabled: showEgressIp,
    report: egressReport,
    isLoading: egressLoading,
    error: egressError,
    setEnabled: setShowEgressIp,
    probeEgress,
  } = useEgressIp();
  // Pure frontend preference: bypasses /api/settings, reads and writes localStorage directly.
  const sendMode = useChatSendMode();

  const apply = React.useCallback((s: Settings) => {
    setSettings(s);
    setTrafficCapture(!!s.traffic_capture);
    setAgentTrafficBinding(!!s.agent_traffic_binding);
    setWebSearch(!!s.web_search_enabled);
    setBackend(s.web_search_backend || "ddgs");
    setBraveKeySet(!!s.brave_key_set);
    setTavilyKeySet(!!s.tavily_key_set);
    setProxyInput(s.web_search_proxy ?? "");
    setGlobalProxyInput(s.global_proxy ?? "");
    setPyInterp(s.python_interpreter ?? "");
    setWorkers(String(s.workers ?? 3));
    setInjectPlanner(s.constraints_inject_planner !== false);
    setInjectWorker(s.constraints_inject_worker !== false);
    setNoaCompaction(!!s.noa_compaction);
    setOpsecEnabled(!!s.opsec_enabled);
    setProbeUrlInput(s.egress_probe_url ?? "");
    setBrowserScreenshot(!!s.browser_screenshot_enabled);
    setDeepSeekKeySet(!!s.deepseek_search_key_set);
    setDeepSeekSearchBaseURL(s.deepseek_search_base_url ?? "");
    setDeepSeekSearchModel(s.deepseek_search_model ?? "");
    setDeepSeekSearchKey("");
    setBrowserScreenshotTimestamp(!!s.browser_screenshot_timestamp_enabled);
    setIntelligenceEnabled(!!s.task_intelligence_enabled);
    setCredentialAgent(!!s.credential_agent_enabled);
    setCredentialBinding(!!s.credential_traffic_binding);
    setTaskAutoTitleEnabled(!!s.task_auto_title_enabled);
    setChatAutoTitleEnabled(!!s.chat_auto_title_enabled);
  }, []);

  const saveWorkers = () => {
    const n = Number(workers);
    if (!Number.isInteger(n) || n <= 0) {
      toast.error("Concurrency must be an integer greater than 0");
      return;
    }
    setSavingWorkers(true);
    api
      .setSettings({ workers: n })
      .then((s) => {
        apply(s);
        toast.success("Saved the concurrent worker agent count (applies to tasks started afterwards)");
      })
      .catch((e) => toast.error("Save failed: " + (e as Error).message))
      .finally(() => setSavingWorkers(false));
  };

  const savePython = () => {
    setSaving(true);
    api
      .setSettings({ python_interpreter: pyInterp.trim() })
      .then((s) => {
        apply(s);
        toast.success("Saved Python interpreter config");
      })
      .catch((e) => toast.error("Save failed: " + (e as Error).message))
      .finally(() => setSaving(false));
  };
  const detectPython = () => {
    setSaving(true);
    api
      .detectPython()
      .then((r) => setPyInterp(r.python_interpreter))
      .catch(() => undefined)
      .finally(() => setSaving(false));
  };

  React.useEffect(() => {
    api
      .settings()
      .then(apply)
      .catch(() => undefined)
      .finally(() => setLoaded(true));
  }, [apply]);

  const toggleTraffic = (v: boolean) => {
    setTrafficCapture(v); // optimistic
    setSaving(true);
    api
      .setSettings({ traffic_capture: v })
      .then(apply)
      .catch(() => setTrafficCapture(!v)) // revert on failure
      .finally(() => setSaving(false));
  };

  const toggleInjectPlanner = (v: boolean) => {
    setInjectPlanner(v); // optimistic
    api
      .setSettings({ constraints_inject_planner: v })
      .then(apply)
      .catch(() => setInjectPlanner(!v)); // revert on failure
  };

  const toggleAgentTrafficBinding = (v: boolean) => {
    setAgentTrafficBinding(v);
    setSaving(true);
    api
      .setSettings({ agent_traffic_binding: v })
      .then((s) => {
        apply(s);
        toast.success(v ? "Enabled automatic agent traffic binding" : "Disabled automatic agent traffic binding");
      })
      .catch((e) => {
        setAgentTrafficBinding(!v);
        toast.error(`Save failed: ${(e as Error).message}`);
      })
      .finally(() => setSaving(false));
  };

  const toggleInjectWorker = (v: boolean) => {
    setInjectWorker(v); // optimistic
    api
      .setSettings({ constraints_inject_worker: v })
      .then(apply)
      .catch(() => setInjectWorker(!v)); // revert on failure
  };

  const saveProbeUrl = () => {
    setSavingProbeUrl(true);
    api
      .setSettings({ egress_probe_url: probeUrlInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(probeUrlInput.trim() ? "Saved custom probe endpoint" : "Cleared it; using the built-in probes");
      })
      .catch((e) => toast.error(`Save failed: ${(e as Error).message}`))
      .finally(() => setSavingProbeUrl(false));
  };

  const toggleShowEgressIp = (v: boolean) => {
    void setShowEgressIp(v).catch((e) => toast.error(`Save failed: ${(e as Error).message}`));
  };

  const toggleOpsec = (v: boolean) => {
    setOpsecEnabled(v); // optimistic
    api
      .setSettings({ opsec_enabled: v })
      .then((s) => {
        apply(s);
        toast.success(v ? "Enabled OPSEC rules (applies from the next agent round)" : "Disabled OPSEC rules");
      })
      .catch((e) => {
        setOpsecEnabled(!v); // revert on failure
        toast.error(`Save failed: ${(e as Error).message}`);
      });
  };

  const toggleNoaCompaction = (v: boolean) => {
    setNoaCompaction(v); // optimistic
    api
      .setSettings({ noa_compaction: v })
      .then((s) => {
        apply(s);
        toast.success(
          v
            ? "Enabled noa context compaction (applies to runs started afterwards)"
            : "Disabled noa context compaction (built-in compaction restored)",
        );
      })
      .catch((e) => {
        setNoaCompaction(!v); // revert on failure
        toast.error(`Save failed: ${(e as Error).message}`);
      });
  };

  const toggleBrowserScreenshot = (v: boolean) => {
    setBrowserScreenshot(v); // optimistic
    setSaving(true);
    api
      .setSettings({ browser_screenshot_enabled: v })
      .then((settings) => {
        apply(settings);
        toast.success(v ? "Browser screenshots enabled" : "Browser screenshots disabled");
      })
      .catch((e) => {
        setBrowserScreenshot(!v); // revert on failure
        toast.error(`Save failed: ${(e as Error).message}`);
      })
      .finally(() => setSaving(false));
  };

  const toggleBrowserScreenshotTimestamp = (v: boolean) => {
    setBrowserScreenshotTimestamp(v); // optimistic
    setSaving(true);
    api
      .setSettings({ browser_screenshot_timestamp_enabled: v })
      .then((settings) => {
        apply(settings);
        toast.success(v ? "Capture-time overlay enabled" : "Capture-time overlay disabled");
      })
      .catch((e) => {
        setBrowserScreenshotTimestamp(!v); // revert on failure
        toast.error(`Save failed: ${(e as Error).message}`);
      })
      .finally(() => setSaving(false));
  };

  const toggleAutoTitle = (key: "task_auto_title_enabled" | "chat_auto_title_enabled", value: boolean) => {
    const setter = key === "task_auto_title_enabled" ? setTaskAutoTitleEnabled : setChatAutoTitleEnabled;
    setter(value); // optimistic
    api
      .setSettings(
        key === "task_auto_title_enabled" ? { task_auto_title_enabled: value } : { chat_auto_title_enabled: value },
      )
      .then(apply)
      .catch((e) => {
        setter(!value); // revert on failure
        toast.error(`Save failed: ${(e as Error).message}`);
      });
  };

  // The three intelligence switches are written together by the backend, so the
  // response is the single source of truth for all three after any one changes.
  const saveCredentialOptions = async (patch: Partial<Settings>) => {
    setSavingCredentials(true);
    try {
      apply(await api.setSettings(patch));
      toast.success("Credential settings saved");
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSavingCredentials(false);
    }
  };

  // Persist a web-search patch (enable and/or backend). Optimistic with refetch.
  const saveWebSearch = (patch: Partial<Settings>) => {
    setSaving(true);
    api
      .setSettings(patch)
      .then((s) => {
        apply(s);
        toast.success("Saved web search config");
      })
      .catch((e) => {
        toast.error("Save failed: " + (e as Error).message);
        api
          .settings()
          .then(apply)
          .catch(() => undefined);
      })
      .finally(() => setSaving(false));
  };

  const saveBraveKey = () => {
    setSavingKey(true);
    api
      .setSettings({ brave_search_api_key: braveKeyInput })
      .then((s) => {
        apply(s);
        setBraveKeyInput("");
        toast.success("Saved Brave API Key");
      })
      .catch((e) => toast.error("Save failed: " + (e as Error).message))
      .finally(() => setSavingKey(false));
  };

  const saveTavilyKey = () => {
    setSavingTavilyKey(true);
    api
      .setSettings({ tavily_search_api_key: tavilyKeyInput })
      .then((s) => {
        apply(s);
        setTavilyKeyInput("");
        toast.success("Saved Tavily API Key");
      })
      .catch((e) => toast.error("Save failed: " + (e as Error).message))
      .finally(() => setSavingTavilyKey(false));
  };

  const saveProxy = () => {
    setSavingProxy(true);
    api
      .setSettings({ web_search_proxy: proxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(proxyInput.trim() ? "Saved egress proxy" : "Cleared egress proxy (direct connection)");
      })
      .catch((e) => toast.error("Save failed: " + (e as Error).message))
      .finally(() => setSavingProxy(false));
  };

  const saveGlobalProxy = () => {
    setSavingGlobalProxy(true);
    api
      .setSettings({ global_proxy: globalProxyInput.trim() })
      .then((s) => {
        apply(s);
        toast.success(globalProxyInput.trim() ? "Saved global proxy" : "Cleared global proxy (direct connection)");
      })
      .catch((e) => toast.error("Save failed: " + (e as Error).message))
      .finally(() => setSavingGlobalProxy(false));
  };

  // Run a real "test" search ("test") against the CURRENT form values (backend +
  // proxy + entered key), falling back to saved values server-side. Toasts result.
  const runTest = () => {
    setTesting(true);
    api
      .testWebSearch({
        web_search_backend: backend,
        web_search_proxy: proxyInput.trim(),
        brave_search_api_key: braveKeyInput,
        tavily_search_api_key: tavilyKeyInput,
      })
      .then((r) => {
        if (r.ok) toast.success(`Search test succeeded · ${r.backend} returned ${r.count} results`);
        else toast.error("Search test failed: " + (r.error || "unknown error"));
      })
      .catch((e) => toast.error("Search test failed: " + (e as Error).message))
      .finally(() => setTesting(false));
  };

  // brave-free selected but no key stored and none being entered → tool stays off.
  const braveNeedsKey = webSearch && backend === "brave-free" && !braveKeySet;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">System settings</h1>
        <p className="text-muted-foreground text-sm">Global runtime switches</p>
      </div>

      {/* Multi-column instead of grid: the web search card is several times taller than the others and
          its height varies with the selected backend (brave/tavily key inputs are conditional). A grid
          would stretch the row to the tallest card and leave blank space beside the others, while columns
          balance-fill by content height. Card spacing uses mb rather than gap — in a multi-column layout
          column-gap only covers the gaps between columns; row spacing must come from the children. */}
      <div className="columns-1 gap-4 md:gap-6 lg:columns-2">
        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Traffic capture
            </CardTitle>
            <CardDescription>
              When enabled, every agent's HTTP traffic is stored in full through the recording proxy, and agents are
              injected with the traffic_search / traffic_get tools and proxy configuration (the prompt includes proxy
              notes).
              <br />
              When off (default) no traffic is recorded: the agent does <b>not</b> receive proxy configuration or
              traffic tools, and the prompt contains <b>no</b> proxy-related content. Agents are rebuilt immediately
              after switching.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="traffic-capture" className="text-sm font-normal text-muted-foreground">
              {trafficCapture ? "On · recording traffic and injecting proxy" : "Off · no recording, no proxy injection"}
            </Label>
            <Switch
              id="traffic-capture"
              checked={trafficCapture}
              disabled={!loaded || saving}
              onCheckedChange={toggleTraffic}
            />
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Automatic agent traffic binding
            </CardTitle>
            <CardDescription id="agent-traffic-binding-description">
              Off by default. When enabled, the report agent triggered on vulnerability creation reviews existing HTTP
              requests/responses and links the matching traffic before writing the report.
              <b>Reading packets and the extra tool calls increase token consumption.</b>
              <br />
              Reporting still works for TCP, uncaptured traffic, or when no traffic matches. This switch does not affect
              traffic capture, manual binding, or viewing saved evidence. It takes effect for the next round of agents;
              once disabled, new automatic bindings are rejected immediately.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="agent-traffic-binding" className="text-sm font-normal text-muted-foreground">
              {agentTrafficBinding ? "On · increases token consumption" : "Off · manual binding still available"}
            </Label>
            <Switch
              id="agent-traffic-binding"
              aria-describedby="agent-traffic-binding-description"
              checked={agentTrafficBinding}
              disabled={!loaded || saving}
              onCheckedChange={toggleAgentTrafficBinding}
            />
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Global proxy
            </CardTitle>
            <CardDescription>
              All agents' <b>target traffic</b> egresses through this proxy (hide the source IP / use a jump host).
              Supports <b>http / https / socks5</b>, optionally with <code>user:pass</code> authentication. Empty =
              direct connection.
              <br />
              With <b>traffic capture</b> on, it acts as the recording proxy's <b>upstream</b> (traffic is still stored
              in full, then egresses through this proxy); with capture off, it is injected directly into the agent's
              bash / WebFetch egress. Independent of the web search proxy and the LLM proxy.
              <br />
              <b>Note</b>: with <b>capture off</b>, socks5 relies on each CLI tool honoring <code>ALL_PROXY</code> (curl
              works; some tools may ignore it). If you mainly use socks5, enable traffic capture — on that path the MITM
              does the dialing itself, invisible to tools and reliably effective.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            <Label htmlFor="global-proxy" className="text-sm font-normal text-muted-foreground">
              Proxy address
            </Label>
            <div className="flex items-center gap-2">
              <Input
                id="global-proxy"
                autoComplete="off"
                placeholder="socks5://user:pass@host:1080 or http://host:port (empty = direct)"
                value={globalProxyInput}
                disabled={!loaded || savingGlobalProxy}
                onChange={(e) => setGlobalProxyInput(e.target.value)}
              />
              <Button type="button" onClick={saveGlobalProxy} disabled={!loaded || savingGlobalProxy}>
                Save
              </Button>
            </div>
            <p className="text-muted-foreground text-xs">
              {globalProxyInput.trim()
                ? "Configured · all target traffic egresses through this proxy"
                : "Not configured · target traffic egresses directly"}
            </p>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Globe2Icon className="size-4" />
              Egress check
            </CardTitle>
            <CardDescription>
              Saving a global proxy only validates its shape — a dead proxy saves fine. This sends a real request and
              reports two exit IPs: <b>(1)</b> going direct and <b>(2)</b> through the proxy. The address in the field
              above is tested even before you save it, so the result may differ from what the agent currently uses; the
              warnings say when that is the case.
              <br />A <b>custom endpoint</b> is usually an intranet echo service, so private ranges are allowed.
              Loopback and link-local are refused: inside a container those reach ARTEX itself and the cloud metadata
              service.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <Label htmlFor="egress-probe-url" className="text-sm font-normal text-muted-foreground">
              Custom IP probe service
            </Label>
            <div className="flex items-center gap-2">
              <Input
                id="egress-probe-url"
                autoComplete="off"
                placeholder="http://10.0.0.5:19000/ip (empty = built-in public probes)"
                value={probeUrlInput}
                disabled={!loaded || savingProbeUrl}
                onChange={(e) => setProbeUrlInput(e.target.value)}
              />
              <Button type="button" onClick={saveProbeUrl} disabled={!loaded || savingProbeUrl}>
                Save
              </Button>
            </div>

            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="show-egress-ip" className="text-sm font-normal text-muted-foreground">
                Show the exit IP in the navbar{showEgressIp ? " · On" : " · Off"}
              </Label>
              <Switch
                id="show-egress-ip"
                checked={showEgressIp}
                disabled={!loaded}
                onCheckedChange={toggleShowEgressIp}
              />
            </div>
            <p className="text-muted-foreground text-xs">
              Off by default: while on, the navbar re-probes every 10 seconds and each poll is a real outbound request.
            </p>

            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => void probeEgress().catch(() => undefined)}
                disabled={!loaded || egressLoading}
              >
                {egressLoading ? "Probing…" : "Run egress check"}
              </Button>
              {egressError && <span className="text-destructive text-xs">{egressError}</span>}
            </div>

            {egressReport && (
              <div className="flex flex-col gap-1 text-xs">
                {egressReport.checks.map((check) => (
                  <div key={check.key} className="flex items-baseline justify-between gap-2">
                    <span className="text-muted-foreground">{check.label}</span>
                    <span className={cn("font-mono", !check.skipped && !check.result.ok && "text-destructive")}>
                      {egressCheckText(check)}
                    </span>
                  </div>
                ))}
                {egressReport.warnings?.map((warning) => (
                  <p key={warning} className="text-amber-600 dark:text-amber-500">
                    {warning}
                  </p>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <ProxyPoolCard settings={settings} loaded={loaded} onSettingsSaved={apply} />

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlertIcon className="size-4" />
              Operation constraint injection
            </CardTitle>
            <CardDescription>
              When enabled, each task's <b>operation constraints</b> (the allow/deny entries maintained under "Operation
              constraints" in the task overview) are spliced into the corresponding agent's system prompt to bound the
              exploration scope (e.g. "only test the current port", "no brute forcing").
              <br />
              You can control injection into the <b>planner</b> and the <b>worker</b> separately ; both are on by
              default. Switching takes effect immediately (read on the next turn) without rebuilding agents. When off,
              the agent no longer sees the constraints.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="inject-planner" className="text-sm font-normal text-muted-foreground">
                Inject into planner{injectPlanner ? " · On" : " · Off"}
              </Label>
              <Switch
                id="inject-planner"
                checked={injectPlanner}
                disabled={!loaded}
                onCheckedChange={toggleInjectPlanner}
              />
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="inject-worker" className="text-sm font-normal text-muted-foreground">
                Inject into worker{injectWorker ? " · On" : " · Off"}
              </Label>
              <Switch
                id="inject-worker"
                checked={injectWorker}
                disabled={!loaded}
                onCheckedChange={toggleInjectWorker}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <EyeOffIcon className="size-4" />
              OPSEC rules
            </CardTitle>
            <CardDescription>
              When enabled, a fixed block of <b>operational safety rules</b> is appended to every agent's system prompt:
              reuse recorded traffic before issuing a fresh request, reach the target only through the recording proxy
              or the browser tools, never bypass certificate validation, and stop on a rate limit, CAPTCHA or WAF
              instead of hammering through.
              <br />
              The block lives <b>in code</b>, not in the editable prompt body, so editing a prompt under "Agents" cannot
              remove it. It does <b>not</b> widen the authorized scope. Switching takes effect from the next agent round
              without rebuilding agents.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="opsec-enabled" className="text-sm font-normal text-muted-foreground">
              Append OPSEC rules{opsecEnabled ? " · On" : " · Off"}
            </Label>
            <Switch id="opsec-enabled" checked={opsecEnabled} disabled={!loaded} onCheckedChange={toggleOpsec} />
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <FlaskConicalIcon className="size-4" />
              Experimental features
            </CardTitle>
            <CardDescription>
              Mechanisms still being validated, off by default. They may change agent behavior or affect stability;
              enable only after understanding the impact.
              <br />
              <b>noa context compaction</b>: the model actively compacts long conversation history (norma v0.4.0). When
              enabled, the four agent types integrated into the platform (<b>planner / worker / main agent / chat</b>)
              switch to noa-managed context in place of the built-in compaction, and the pre-compaction originals are
              archived under the task working directory for later review. Switching takes effect immediately (for runs
              started afterwards) without rebuilding agents; when disabled, the built-in compaction is restored
              immediately.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="noa-compaction" className="text-sm font-normal text-muted-foreground">
              noa context compaction{noaCompaction ? " · On" : " · Off"}
            </Label>
            <Switch
              id="noa-compaction"
              checked={noaCompaction}
              disabled={!loaded}
              onCheckedChange={toggleNoaCompaction}
            />
          </CardContent>
        </Card>

        <BasicAuthCard />

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="text-base">Browser screenshots</CardTitle>
            <CardDescription>
              Report screenshots and the capture-time overlay. Both switches apply to agent runs started afterwards.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-5">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="browser-screenshot" className="text-sm font-normal text-muted-foreground">
                Let the report agent use the browser MCP to save screenshots for the reproduction steps.
              </Label>
              <Switch
                id="browser-screenshot"
                checked={browserScreenshot}
                disabled={!loaded || saving}
                onCheckedChange={toggleBrowserScreenshot}
              />
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="browser-screenshot-timestamp" className="text-sm font-normal text-muted-foreground">
                Overlay the capture time on a screenshot preview. The stored file is never modified.
              </Label>
              <Switch
                id="browser-screenshot-timestamp"
                checked={browserScreenshotTimestamp}
                disabled={!loaded || saving}
                onCheckedChange={toggleBrowserScreenshotTimestamp}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="text-base">Auto title</CardTitle>
            <CardDescription>
              Generate a short title for agent-created tasks and from a chat's first message. The two switches are
              independent and both default to off.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-5">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="task-auto-title" className="text-sm font-normal text-muted-foreground">
                Task name — named when an agent creates the task; on failure the task stays unnamed.
              </Label>
              <Switch
                id="task-auto-title"
                checked={taskAutoTitleEnabled}
                disabled={!loaded}
                onCheckedChange={(value) => toggleAutoTitle("task_auto_title_enabled", value)}
              />
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="chat-auto-title" className="text-sm font-normal text-muted-foreground">
                Session title — named after the first message; the truncated message is shown until then, and kept on
                failure.
              </Label>
              <Switch
                id="chat-auto-title"
                checked={chatAutoTitleEnabled}
                disabled={!loaded}
                onCheckedChange={(value) => toggleAutoTitle("chat_auto_title_enabled", value)}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="text-base">Task intelligence</CardTitle>
            <CardDescription>
              Record the credentials, leads and sensitive data a task turns up, together with the evidence they came
              from.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-5">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="task-intelligence" className="text-sm font-normal text-muted-foreground">
                Agent recording — off by default. Agents report credentials, leads and sensitive data as they run, which
                adds prompt and report tokens. It only records; it does not start credential extraction. Turning it off
                also disables the two switches below; what was already recorded stays readable.
              </Label>
              <Switch
                id="task-intelligence"
                checked={intelligenceEnabled}
                disabled={!loaded || savingIntelligence || savingCredentials}
                onCheckedChange={async (value) => {
                  setSavingIntelligence(true);
                  try {
                    apply(await api.setSettings({ task_intelligence_enabled: value }));
                    toast.success(value ? "Intelligence recording enabled" : "Intelligence recording disabled");
                  } catch (error) {
                    toast.error(`Save failed: ${(error as Error).message}`);
                  } finally {
                    setSavingIntelligence(false);
                  }
                }}
              />
            </div>
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="credential-agent" className="text-sm font-normal text-muted-foreground">
                Credential extractor — off by default. Splits recorded credentials into username, password, token and
                cookie without changing the original report or its status. Parsable JSON needs no model; free text costs
                extra tokens. Requires agent recording above.
              </Label>
              <Switch
                id="credential-agent"
                checked={credentialAgent}
                disabled={!loaded || savingCredentials || savingIntelligence || !intelligenceEnabled}
                onCheckedChange={(value) => void saveCredentialOptions({ credential_agent_enabled: value })}
              />
            </div>
            {credentialAgent ? (
              <div className="flex items-center justify-between gap-4">
                <Label htmlFor="credential-traffic" className="text-sm font-normal text-muted-foreground">
                  Bind to traffic — off by default, available only while the extractor is on. Matches extracted
                  credentials against captured traffic and saves the matching excerpt. It never logs in, and a match is
                  not proof that the credential works. Existing bindings are kept when it is turned off.
                </Label>
                <Switch
                  id="credential-traffic"
                  checked={credentialBinding}
                  disabled={!loaded || savingCredentials}
                  onCheckedChange={(value) => void saveCredentialOptions({ credential_traffic_binding: value })}
                />
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <SearchIcon className="size-4" />
              Web search
            </CardTitle>
            <CardDescription>
              This is the web search <b>master switch + source config</b>. Only when it is enabled can{" "}
              <b>each agent's config</b> separately choose whether to enable
              <b>web_search</b> (returns only titles/links/snippets without fetching bodies; fetching is handled by
              WebFetch). Web search does <b>not</b> go through the recording proxy and is independent of traffic
              capture.
              <br />
              Sources: <b>DuckDuckGo (ddgs)</b> (no key needed), <b>Brave (free tier)</b> (requires a Brave API Key),{" "}
              <b>Tavily</b> (requires a Tavily API Key) or <b>DeepSeek</b> (reuses the current LLM config). When the
              master switch is off, the per-agent web search switches are unavailable.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4">
              <Label htmlFor="web-search" className="text-sm font-normal text-muted-foreground">
                {webSearch
                  ? "Master switch on · can be enabled per agent config"
                  : "Off · agents cannot enable web search"}
              </Label>
              <Switch
                id="web-search"
                checked={webSearch}
                disabled={!loaded || saving}
                onCheckedChange={(v) => {
                  setWebSearch(v); // optimistic
                  saveWebSearch({ web_search_enabled: v });
                }}
              />
            </div>

            {webSearch && (
              <div className="flex items-center justify-between gap-4">
                <Label className="text-sm font-normal text-muted-foreground">Search source</Label>
                <Select
                  value={backend}
                  disabled={!loaded || saving}
                  onValueChange={(v) => {
                    setBackend(v); // optimistic
                    saveWebSearch({ web_search_backend: v });
                  }}
                >
                  <SelectTrigger className="w-48 shrink-0">
                    <SelectValue placeholder="Choose a source" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ddgs">DuckDuckGo (ddgs · free, no key)</SelectItem>
                    <SelectItem value="brave-free">Brave (free tier · requires key)</SelectItem>
                    <SelectItem value="tavily">Tavily (requires key)</SelectItem>
                    <SelectItem value="deepseek">DeepSeek (official)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}

            {webSearch && backend === "deepseek" && (
              <div className="border-border/60 bg-muted/30 flex flex-col gap-2 rounded-md border p-3">
                <p className="text-sm font-medium">DeepSeek official web search</p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  This source directly reuses the <b>currently active LLM config</b>. It therefore supports{" "}
                  <b>official DeepSeek models only</b>, and that config <b>must use the anthropic protocol</b>—
                  DeepSeek's OpenAI-protocol endpoint does not support server-side search. This source may stop working
                  after switching LLM configs.
                </p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  Unlike other sources, the search runs <b>server-side on DeepSeek</b>: each search consumes an extra
                  model call (incurring token costs), search requests <b>do not go through the egress proxy above</b>{" "}
                  and are <b>not recorded as traffic</b>; results contain <b>titles and links only</b>
                  (no snippets); use WebFetch when you need the page body.
                </p>
                <p className="text-muted-foreground text-xs leading-relaxed">
                  Verify these conditions yourself; the system does not block on them. Use the "Test search" button
                  below to run a real search and check.
                </p>
                <div className="flex flex-col gap-2 border-t pt-3">
                  <Label htmlFor="deepseek-search-key" className="text-sm font-normal text-muted-foreground">
                    Dedicated DeepSeek credentials — leave a field empty to use the active LLM profile for it
                  </Label>
                  <Input
                    id="deepseek-search-key"
                    type="password"
                    autoComplete="off"
                    value={deepSeekSearchKey}
                    placeholder={
                      deepSeekKeySet ? "stored; leave empty to keep it" : "API key (empty = use the active LLM profile)"
                    }
                    onChange={(e) => setDeepSeekSearchKey(e.target.value)}
                  />
                  <Input
                    id="deepseek-search-base-url"
                    value={deepSeekSearchBaseURL}
                    placeholder="base URL (empty = use the active LLM profile)"
                    onChange={(e) => setDeepSeekSearchBaseURL(e.target.value)}
                  />
                  <Input
                    id="deepseek-search-model"
                    value={deepSeekSearchModel}
                    placeholder="model (empty = use the active LLM profile)"
                    onChange={(e) => setDeepSeekSearchModel(e.target.value)}
                  />
                  <Button
                    size="sm"
                    className="self-start"
                    disabled={saving}
                    onClick={() =>
                      saveWebSearch({
                        deepseek_search_api_key: deepSeekSearchKey,
                        deepseek_search_base_url: deepSeekSearchBaseURL,
                        deepseek_search_model: deepSeekSearchModel,
                      })
                    }
                  >
                    Save DeepSeek credentials
                  </Button>
                </div>
              </div>
            )}

            {webSearch && backend === "brave-free" && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="brave-key" className="text-sm font-normal text-muted-foreground">
                  Brave Search API Key
                  {braveKeySet && <span className="ml-2 text-xs text-emerald-500">Configured</span>}
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="brave-key"
                    type="password"
                    autoComplete="off"
                    placeholder={braveKeySet ? "Configured (leave empty to keep)" : "Enter Brave API Key"}
                    value={braveKeyInput}
                    disabled={!loaded || savingKey}
                    onChange={(e) => setBraveKeyInput(e.target.value)}
                  />
                  <Button
                    type="button"
                    onClick={saveBraveKey}
                    disabled={!loaded || savingKey || braveKeyInput.trim() === ""}
                  >
                    Save
                  </Button>
                </div>
                {braveNeedsKey && (
                  <p className="text-xs text-amber-500">
                    Brave is selected but no key is configured — the search tool stays disabled until you save one.
                  </p>
                )}
                <p className="text-muted-foreground text-xs">
                  The free tier allows about 2,000 queries/month. Get a key at https://brave.com/search/api/.
                </p>
              </div>
            )}

            {webSearch && backend === "tavily" && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="tavily-key" className="text-sm font-normal text-muted-foreground">
                  Tavily Search API Key
                  {tavilyKeySet && <span className="ml-2 text-xs text-emerald-500">Configured</span>}
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="tavily-key"
                    type="password"
                    autoComplete="off"
                    placeholder={tavilyKeySet ? "Configured (leave empty to keep)" : "Enter Tavily API Key (tvly-…)"}
                    value={tavilyKeyInput}
                    disabled={!loaded || savingTavilyKey}
                    onChange={(e) => setTavilyKeyInput(e.target.value)}
                  />
                  <Button
                    type="button"
                    onClick={saveTavilyKey}
                    disabled={!loaded || savingTavilyKey || tavilyKeyInput.trim() === ""}
                  >
                    Save
                  </Button>
                </div>
                {webSearch && backend === "tavily" && !tavilyKeySet && (
                  <p className="text-xs text-amber-500">
                    Tavily is selected but no key is configured — the search tool stays disabled until you save one.
                  </p>
                )}
                <p className="text-muted-foreground text-xs">Register and get an API key at https://tavily.com.</p>
              </div>
            )}

            {webSearch && (
              <div className="flex flex-col gap-2">
                <Label htmlFor="ws-proxy" className="text-sm font-normal text-muted-foreground">
                  Egress proxy (optional)
                </Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="ws-proxy"
                    autoComplete="off"
                    placeholder="http://host:port or socks5://host:port (empty = direct)"
                    value={proxyInput}
                    disabled={!loaded || savingProxy}
                    onChange={(e) => setProxyInput(e.target.value)}
                  />
                  <Button type="button" onClick={saveProxy} disabled={!loaded || savingProxy}>
                    Save
                  </Button>
                </div>
                <p className="text-muted-foreground text-xs">
                  A dedicated egress proxy used only to reach search endpoints (VPN/SOCKS etc.). Unrelated to the
                  traffic-recording MITM proxy; use it to reach endpoints when the network is blocked.
                </p>
              </div>
            )}

            {webSearch && (
              <div className="flex items-center justify-between gap-4 border-t pt-4">
                <p className="text-muted-foreground text-xs">
                  Run a real "test" search with the current config (source + proxy + key) to verify it works.
                </p>
                <Button
                  type="button"
                  variant="outline"
                  onClick={runTest}
                  disabled={!loaded || testing}
                  className="shrink-0"
                >
                  {testing ? "Testing…" : "Test search"}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RadioTowerIcon className="size-4" />
              Custom scripts · Python interpreter
            </CardTitle>
            <CardDescription>
              Custom <b>script</b> tools run Python with it. Auto-detected at startup (python3 first); you can enter an
              absolute path to a venv / specific version here; leave empty to auto-detect at runtime.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Input
                className="font-mono text-sm"
                placeholder="/usr/bin/python3 (empty = auto-detect)"
                value={pyInterp}
                disabled={!loaded || saving}
                onChange={(e) => setPyInterp(e.target.value)}
              />
              <Button variant="outline" onClick={detectPython} disabled={!loaded || saving}>
                Re-detect
              </Button>
              <Button onClick={savePython} disabled={!loaded || saving}>
                Save
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <CpuIcon className="size-4" />
              Work concurrency · worker agent count
            </CardTitle>
            <CardDescription>
              The number of worker agents running concurrently per task (default 3). Higher values mean more parallel
              probing and higher consumption. Changes
              <b>apply to tasks started afterwards</b>; running tasks are unaffected.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={1}
                className="w-32 font-mono text-sm"
                placeholder="3"
                value={workers}
                disabled={!loaded || savingWorkers}
                onChange={(e) => setWorkers(e.target.value)}
              />
              <Button onClick={saveWorkers} disabled={!loaded || savingWorkers}>
                Save
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="mb-4 break-inside-avoid md:mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyboardIcon className="size-4" />
              Chat input send key binding
            </CardTitle>
            <CardDescription>
              Shared by the main-agent chat inputs on the chat page and task details; takes effect immediately on
              selection, no saving needed.
              <br />
              This preference <b>lives only in this browser</b>, does not sync with the account, and must be set again
              after switching browsers or clearing site data.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-between gap-4">
            <Label htmlFor="chat-send-mode" className="text-sm font-normal text-muted-foreground">
              Send mode
            </Label>
            <Select value={sendMode} onValueChange={(v) => setChatSendMode(v as ChatSendMode)}>
              <SelectTrigger id="chat-send-mode" className="w-72">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CHAT_SEND_MODE_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
