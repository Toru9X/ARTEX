"use client";

import * as React from "react";

import { Card, CardContent } from "@/components/ui/card";
import { ExplorationGraph } from "@/components/exploration-graph";
import { usePoll } from "@/hooks/use-poll";
import { api } from "@/lib/api";
import type { Edge, TaskNode } from "@/lib/types";

export function GraphTab({ taskId }: { taskId: string }) {
  const [nodes, setNodes] = React.useState<TaskNode[]>([]);
  const [edges, setEdges] = React.useState<Edge[]>([]);
  // Signature of the previous graph data: polling skips setState on identical data to avoid
  // rebuilding the whole graph (so dragging is not jarred by the 20s poll). Only render-affecting fields count.
  const sigRef = React.useRef("");

  // biome-ignore lint/correctness/useExhaustiveDependencies: taskId is the trigger, not a value read here
  React.useEffect(() => {
    sigRef.current = ""; // task switch: force the next refresh to rebuild
  }, [taskId]);

  usePoll(
    async (signal) => {
      const g = await api.explorationGraph(taskId);
      if (signal.aborted) return; // keep last good data
      const ns = g.nodes ?? [];
      const es = g.edges ?? [];
      const sig = JSON.stringify([
        ns.map((n) => [n.id, n.type, n.state, n.priority, n.payload]),
        es.map((e) => [e.src, e.dst, e.rel]),
      ]);
      if (sig === sigRef.current) return; // unchanged → do not rebuild
      sigRef.current = sig;
      setNodes(ns);
      setEdges(es);
    },
    20000,
    { resetKey: taskId },
  );

  return (
    <Card>
      <CardContent className="p-0">
        <ExplorationGraph nodes={nodes} edges={edges} className="h-[72vh]" />
      </CardContent>
    </Card>
  );
}
