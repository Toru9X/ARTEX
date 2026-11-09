"use client";

import * as React from "react";

import Link from "next/link";

import { CopyIcon, RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { CredentialContent, CredentialTrafficViewer, intelligencePreview } from "@/components/credential-content";
import { StatusBadge, ToneDot } from "@/components/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePoll } from "@/hooks/use-poll";
import { api } from "@/lib/api";
import { statusMeta } from "@/lib/status";
import type { IntelligenceKind, IntelligencePage, TaskIntelligence } from "@/lib/types";
import { copyText } from "@/lib/utils";

const KINDS: { value: IntelligenceKind; label: string }[] = [
  { value: "credential", label: "Credential" },
  { value: "lead", label: "Lead" },
  { value: "sensitive_data", label: "Sensitive data" },
];
const STATUS: Record<IntelligenceKind, Record<string, string>> = {
  credential: { unverified: "Unverified", verified: "Verified", invalid: "Invalid" },
  lead: { pending: "Pending", in_progress: "In progress", dismissed: "Dismissed", converted: "Converted to finding" },
  sensitive_data: { suspected: "Suspected", confirmed: "Confirmed", dismissed: "Dismissed" },
};
function time(value: string) {
  return new Date(value).toLocaleString("zh-CN");
}

function conversationHref(item: TaskIntelligence) {
  return `/function/tasks/detail?id=${item.task_id}&tab=sessions${item.source_session ? `&session=${encodeURIComponent(item.source_session)}` : ""}`;
}

function AssetLinks({ ids, onNavigate }: { ids: number[]; onNavigate?: () => void }) {
  return ids.length ? (
    <span className="inline-flex flex-wrap gap-x-2 gap-y-1">
      {ids.map((id) => (
        <Link
          key={id}
          href={`/function/assets?asset=${id}`}
          onClick={onNavigate}
          className="underline underline-offset-2"
          aria-label={`View asset #${id}`}
        >
          #{id}
        </Link>
      ))}
    </span>
  ) : (
    <>none</>
  );
}

export function IntelligencePanel({
  scope,
  scopeId,
  onNavigate,
}: {
  scope: "tasks" | "assets";
  scopeId: string;
  onNavigate?: () => void;
}) {
  const [kind, setKind] = React.useState("all");
  const [status, setStatus] = React.useState("all");
  const [search, setSearch] = React.useState("");
  const [query, setQuery] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [data, setData] = React.useState<IntelligencePage | null>(null);
  const [error, setError] = React.useState("");
  const [refresh, setRefresh] = React.useState(0);
  const [selected, setSelected] = React.useState<TaskIntelligence | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [retrying, setRetrying] = React.useState(false);
  const [trafficTarget, setTrafficTarget] = React.useState<{ item: TaskIntelligence; id: string } | null>(null);
  React.useEffect(() => {
    if (data)
      setSelected((current) => (current ? (data.items.find((item) => item.id === current.id) ?? current) : null));
  }, [data]);
  React.useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search.trim());
      setPage(0);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);
  // The hidden-tab check this panel already did by hand now comes from usePoll,
  // together with the overlap guard. resetKey carries what used to be the effect's
  // dependency list: changing a filter refetches at once instead of on the next tick.
  usePoll(
    async (signal) => {
      const params = new URLSearchParams({ limit: "25", offset: String(page * 25) });
      if (kind !== "all") params.set("kind", kind);
      if (status !== "all") params.set("status", status);
      if (query) params.set("q", query);
      try {
        const result = await api.intelligence(scope, scopeId, params);
        if (signal.aborted) return;
        setData(result);
        setError("");
      } catch (e) {
        if (!signal.aborted) setError((e as Error).message);
      }
    },
    8000,
    { resetKey: `${scope}|${scopeId}|${kind}|${status}|${query}|${page}|${refresh}` },
  );
  const open = (item: TaskIntelligence) => setSelected(item);
  const close = () => setSelected(null);
  const navigate = () => {
    close();
    onNavigate?.();
  };
  const update = async (value: string) => {
    if (!selected) return;
    setSaving(true);
    try {
      await api.updateIntelligence(selected.task_id, selected.id, value);
      setSelected((item) => (item ? { ...item, status: value } : null));
      setRefresh((n) => n + 1);
      toast.success("Intelligence status updated");
    } catch (e) {
      toast.error("Update failed: " + (e as Error).message);
    } finally {
      setSaving(false);
    }
  };
  const statusOptions = kind === "all" ? {} : STATUS[kind as IntelligenceKind];
  return (
    <div className="flex min-w-0 flex-col gap-4">
      {data && !data.enabled && scope === "tasks" ? (
        <Alert>
          <AlertTitle>Automatic recording is off</AlertTitle>
          <AlertDescription>
            Existing intelligence is still readable. Turn it on in{" "}
            <Link href="/system/settings" className="underline">
              system settings
            </Link>{" "}
            and agents will record new intelligence as they run, at the cost of extra tokens.
          </AlertDescription>
        </Alert>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>{scope === "tasks" ? "Task intelligence" : "Intelligence linked to this asset"}</CardTitle>
          <CardDescription>
            {scope === "tasks"
              ? "Everything collected in this run, plus what it inherited from directly linked tasks."
              : "Intelligence linked to this asset, grouped by the task that found it."}{" "}
            Credentials, sensitive data and the source evidence are shown as recorded; a credential found is not a
            credential verified.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex min-w-0 flex-col gap-4">
          <Tabs
            value={kind}
            onValueChange={(value) => {
              setKind(value);
              setStatus("all");
              setPage(0);
            }}
          >
            <TabsList className="max-w-full overflow-x-auto">
              <TabsTrigger value="all">
                All {data ? Object.values(data.counts).reduce((a, b) => a + b, 0) : ""}
              </TabsTrigger>
              {KINDS.map((item) => (
                <TabsTrigger key={item.value} value={item.value}>
                  <ToneDot tone={statusMeta("intelligence", item.value).tone} />
                  {item.label} {data?.counts[item.value] ?? 0}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
          <div className="flex flex-wrap items-center gap-2">
            <Input
              aria-label="Search intelligence by title, content or reporter"
              placeholder="Search title, content or reporter"
              value={search}
              maxLength={200}
              onChange={(e) => setSearch(e.target.value)}
              className="min-w-40 flex-1"
            />
            {kind !== "all" ? (
              <Select
                value={status}
                onValueChange={(value) => {
                  setStatus(value);
                  setPage(0);
                }}
              >
                <SelectTrigger aria-label="Filter by status">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="all">All statuses</SelectItem>
                    {Object.entries(statusOptions).map(([value, label]) => (
                      <SelectItem key={value} value={value}>
                        {label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            ) : null}
            <Button variant="outline" onClick={() => setRefresh((n) => n + 1)}>
              <RefreshCwIcon data-icon="inline-start" />
              Refresh
            </Button>
          </div>
          {error ? (
            <Alert variant="destructive">
              <AlertTitle>Could not load intelligence</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
          {!data && !error ? (
            <Skeleton className="h-40 w-full" />
          ) : data?.items.length ? (
            <Table className="min-w-[68rem] table-fixed">
              <colgroup>
                <col className="w-[20%]" />
                <col className="w-[35%]" />
                <col className="w-[8%]" />
                <col className="w-[12%]" />
                <col className="w-[6%]" />
                <col className="w-[12%]" />
                <col className="w-[7%]" />
              </colgroup>
              <TableHeader>
                <TableRow>
                  <TableHead>Kind / title</TableHead>
                  <TableHead>Content / source evidence</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Session</TableHead>
                  <TableHead>Assets</TableHead>
                  <TableHead>Found at</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className="align-top whitespace-normal">
                      <div className="flex min-w-0 flex-col items-start gap-1">
                        <StatusBadge domain="intelligence" value={item.kind} />
                        <span className="max-w-full [overflow-wrap:anywhere]">{item.title}</span>
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal">
                      <div className="flex min-w-0 flex-col gap-2">
                        <CredentialContent
                          item={item}
                          enabled={data.credential_agent_enabled}
                          onDetails={() => open(item)}
                          onTraffic={(id) => setTrafficTarget({ item, id })}
                        />
                        <div className="flex flex-col gap-1 text-xs text-muted-foreground">
                          <span>Source evidence</span>
                          <p className="whitespace-pre-wrap break-all">{intelligencePreview(item.evidence, 220)}</p>
                          {Array.from(item.evidence).length > 220 ? (
                            <button type="button" className="text-left underline" onClick={() => open(item)}>
                              Open details for the full evidence
                            </button>
                          ) : null}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal [overflow-wrap:anywhere]">
                      <div className="flex flex-col items-start gap-1">
                        <Badge variant="outline">{STATUS[item.kind][item.status] ?? item.status}</Badge>
                        <span className="text-xs text-muted-foreground">
                          {item.confidence === "observed" ? "Directly observed" : "Inferred"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal [overflow-wrap:anywhere]">
                      <div className="flex flex-col gap-1">
                        <Link href={conversationHref(item)} onClick={navigate} className="underline">
                          {item.source_session ? "Open session" : "Open task sessions"}
                        </Link>
                        <span className="text-xs text-muted-foreground">
                          Task #{item.task_id} · {item.worker || "Agent"}
                          {item.node_id ? ` · node #${item.node_id}` : ""}
                        </span>
                        {item.inherited ? <Badge variant="outline">Inherited · read-only</Badge> : null}
                      </div>
                    </TableCell>
                    <TableCell className="align-top whitespace-normal [overflow-wrap:anywhere]">
                      <AssetLinks ids={item.asset_ids} onNavigate={navigate} />
                    </TableCell>
                    <TableCell className="align-top whitespace-normal text-xs">{time(item.created_at)}</TableCell>
                    <TableCell className="align-top whitespace-normal [overflow-wrap:anywhere]">
                      <Button size="sm" variant="outline" onClick={() => open(item)}>
                        Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : data ? (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>No intelligence matches these filters</EmptyTitle>
                <EmptyDescription>
                  {query || kind !== "all" || status !== "all"
                    ? "Try a different kind or filter."
                    : data.enabled
                      ? "Anything valuable an agent finds from here on will show up here."
                      : "With automatic recording on, new intelligence appears here; past sessions are not re-scanned."}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : null}
        </CardContent>
        <CardFooter className="flex items-center justify-between gap-2">
          <span className="text-sm text-muted-foreground">{data?.total ?? 0} total · 25 per page</span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((n) => n - 1)}>
              Previous
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!data || (page + 1) * 25 >= data.total}
              onClick={() => setPage((n) => n + 1)}
            >
              Next
            </Button>
          </div>
        </CardFooter>
      </Card>
      <Dialog
        open={!!selected}
        onOpenChange={(value) => {
          if (!value) close();
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>{selected?.title ?? "Intelligence details"}</DialogTitle>
            <DialogDescription>The full recorded content and the evidence it came from.</DialogDescription>
          </DialogHeader>
          {selected ? (
            <div className="flex min-w-0 flex-col gap-4">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge domain="intelligence" value={selected.kind} />
                <Badge variant="outline">{selected.confidence === "observed" ? "Directly observed" : "Inferred"}</Badge>
                <span className="text-xs text-muted-foreground">
                  Task #{selected.task_id}
                  {selected.node_id ? ` · source node #${selected.node_id}` : ""} · {selected.worker || "Agent"}
                </span>
              </div>
              {scope === "tasks" && !selected.inherited ? (
                <Select value={selected.status} disabled={saving} onValueChange={(value) => void update(value)}>
                  <SelectTrigger aria-label="Update status">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {Object.entries(STATUS[selected.kind]).map(([value, label]) => (
                        <SelectItem key={value} value={value}>
                          {label}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              ) : (
                <p className="text-sm text-muted-foreground">
                  {STATUS[selected.kind][selected.status]} · change the status from the task that found it
                </p>
              )}
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm">Content</span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={async () => {
                    if (await copyText(selected.content)) toast.success("Copied");
                    else toast.error("Copy failed; select the text and copy it manually");
                  }}
                >
                  <CopyIcon data-icon="inline-start" />
                  Copy
                </Button>
              </div>
              <CredentialContent
                item={selected}
                detail
                enabled={data?.credential_agent_enabled}
                onTraffic={(id) => setTrafficTarget({ item: selected, id })}
              />
              {selected.kind === "credential" && !selected.inherited && data?.credential_agent_enabled ? (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={
                    retrying || selected.credentials?.state === "processing" || selected.credentials?.state === "queued"
                  }
                  onClick={async () => {
                    setRetrying(true);
                    try {
                      await api.retryCredentials(selected.task_id, selected.id);
                      setRefresh((n) => n + 1);
                      toast.success("Queued for credential extraction");
                    } catch (e) {
                      toast.error((e as Error).message);
                    } finally {
                      setRetrying(false);
                    }
                  }}
                >
                  Re-run credential extraction
                </Button>
              ) : null}
              <p className="text-sm">Source evidence</p>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-muted p-3 text-xs">
                {selected.evidence}
              </pre>
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span>
                  Linked assets: <AssetLinks ids={selected.asset_ids} onNavigate={navigate} />
                </span>
                <span>Found at {time(selected.created_at)}</span>
              </div>
              <Link href={conversationHref(selected)} onClick={navigate} className="text-sm underline">
                {selected.source_session ? "Open the source session" : "Open the source task"}
              </Link>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
      <CredentialTrafficViewer
        scope={scope}
        scopeId={scopeId}
        item={trafficTarget?.item ?? null}
        trafficId={trafficTarget?.id ?? null}
        onClose={() => setTrafficTarget(null)}
      />
    </div>
  );
}
