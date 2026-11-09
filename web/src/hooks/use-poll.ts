"use client";

import * as React from "react";

/**
 * Runs `load` now and then on an interval, but only while the tab is visible.
 *
 * Every page used to hand-roll this with `setInterval` inside a `useEffect`, at
 * eight different cadences and with no visibility check, so panels on one screen
 * refreshed at unrelated moments and a backgrounded tab kept calling the API
 * forever. Those three behaviours — the leading call, the pause, the catch-up
 * refresh when the tab comes back — belong in one place.
 *
 * `load` receives an AbortSignal that fires on unmount and whenever `enabled` or
 * `intervalMs` changes; check `signal.aborted` before writing state, the way the
 * old `let alive = true` flags did. Ticks never overlap: while one run is still
 * pending the next tick is skipped rather than queued, so a slow endpoint cannot
 * pile up requests.
 *
 * `load` is held in a ref, so an inline arrow function is fine — it does not need
 * `useCallback` and does not restart the timer on every render. The flip side is
 * that each run sees the latest render's closure, not the one from mount.
 *
 * `enabled` false stops the poll entirely. `resetKey` is for a poll whose subject
 * can change without the component unmounting — the task id on a detail page, say:
 * changing it restarts the poll, so the new subject is fetched at once instead of
 * at the end of the current interval, which is what a `[id]` dependency used to do.
 *
 * `leading` false drops the run at mount, for a caller that already fetches on its
 * own — a separate effect that loads whenever its filters change, or a banner that
 * deliberately does not probe twice. It suppresses only that first run: coming back
 * to a hidden tab still refreshes, and that refresh replaces the ticks the pause
 * skipped rather than adding one.
 */
export function usePoll(
  load: (signal: AbortSignal) => void | Promise<void>,
  intervalMs: number,
  options: { enabled?: boolean; resetKey?: unknown; leading?: boolean } = {},
): void {
  const { enabled = true, resetKey, leading = true } = options;
  const latest = React.useRef(load);
  // Updated during render rather than in an effect: a tick that fires between
  // render and effect flush would otherwise call the previous closure.
  latest.current = load;

  // biome-ignore lint/correctness/useExhaustiveDependencies: resetKey is a restart trigger, not a value read inside
  React.useEffect(() => {
    if (!enabled || intervalMs <= 0) return;
    const controller = new AbortController();
    let running = false;
    let timer: ReturnType<typeof setInterval> | undefined;

    const run = () => {
      if (running || controller.signal.aborted) return;
      running = true;
      void (async () => {
        try {
          await latest.current(controller.signal);
        } catch {
          // A poll is best-effort: keep whatever is on screen and try again on
          // the next tick, exactly as the hand-rolled loops did.
        } finally {
          running = false;
        }
      })();
    };

    const start = () => {
      if (timer !== undefined) return;
      timer = setInterval(run, intervalMs);
    };
    const stop = () => {
      if (timer === undefined) return;
      clearInterval(timer);
      timer = undefined;
    };

    // Effects never run during Next's server render, so `document` is always here;
    // what it can already be by now is hidden, before this ever mounted.
    const visible = () => document.visibilityState !== "hidden";

    const onVisibility = () => {
      if (visible()) {
        run(); // catch up on what was missed, then resume the cadence
        start();
      } else {
        stop();
      }
    };

    if (visible()) {
      if (leading) run();
      start();
    }
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      stop();
      controller.abort();
    };
  }, [intervalMs, enabled, leading, resetKey]);
}
