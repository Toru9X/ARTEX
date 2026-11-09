"use client";

import * as React from "react";

import { usePoll } from "@/hooks/use-poll";
import { cn } from "@/lib/utils";

function formatClock(value: Date) {
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())} ${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`;
}

export function LiveClock({ className }: { className?: string }) {
  // Starts null and fills in on mount: rendering a time during SSR/static
  // export would bake the build time into the page and mismatch on hydration.
  const [now, setNow] = React.useState<Date | null>(null);

  // The second-by-second re-render stops while the tab is hidden; coming back reads
  // the clock again, so what shows is the time now, never the time it paused at.
  usePoll(() => setNow(new Date()), 1000);

  return (
    <time
      role="timer"
      className={cn(
        "hidden rounded-md border bg-muted/40 px-2 py-1 font-mono text-[11px] text-muted-foreground tabular-nums sm:inline-flex",
        className,
      )}
      dateTime={now?.toISOString()}
      aria-label="Current time"
      title="Current local time"
    >
      {now ? formatClock(now) : "---- -- -- --:--:--"}
    </time>
  );
}
