"use client";

import * as React from "react";

import { format, parseISO } from "date-fns";
import { zhCN } from "date-fns/locale/zh-CN";
import { CalendarDaysIcon, RotateCcwIcon } from "lucide-react";

import { TimeSelect } from "@/components/time-select";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

export interface FindingDateRange {
  from?: string;
  to?: string;
}

function localIso(date: string, time: string) {
  if (!date) return undefined;
  const value = new Date(`${date}T${time || "00:00"}:00`);
  return Number.isNaN(value.getTime()) ? undefined : value.toISOString();
}

function displayDate(iso?: string) {
  if (!iso) return "";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleDateString("zh-CN");
}

function DateField({ value, onChange, label }: { value: string; onChange: (value: string) => void; label: string }) {
  const selected = value ? parseISO(value) : undefined;
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-10 justify-between px-3 font-normal"
          aria-label={label}
        >
          <span className={selected ? "text-foreground" : "text-muted-foreground"}>
            {selected ? format(selected, "yyyy-MM-dd") : "yyyy / mm / dd"}
          </span>
          <CalendarDaysIcon className="size-4 text-muted-foreground" aria-hidden="true" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-auto p-0" align="start">
        <Calendar
          mode="single"
          locale={zhCN}
          selected={selected}
          defaultMonth={selected}
          onSelect={(date) => date && onChange(format(date, "yyyy-MM-dd"))}
        />
      </PopoverContent>
    </Popover>
  );
}

export function FindingDateFilter({
  value,
  onChange,
}: {
  value: FindingDateRange;
  onChange: (value: FindingDateRange) => void;
}) {
  const [open, setOpen] = React.useState(false);
  const [fromDate, setFromDate] = React.useState("");
  const [fromTime, setFromTime] = React.useState("00:00");
  const [toDate, setToDate] = React.useState("");
  const [toTime, setToTime] = React.useState("23:59");
  const active = Boolean(value.from ?? value.to);

  const apply = (next: { fromDate?: string; fromTime?: string; toDate?: string; toTime?: string }) => {
    const nextFromDate = next.fromDate ?? fromDate;
    const nextFromTime = next.fromTime ?? fromTime;
    const nextToDate = next.toDate ?? toDate;
    const nextToTime = next.toTime ?? toTime;
    if (next.fromDate !== undefined) setFromDate(next.fromDate);
    if (next.fromTime !== undefined) setFromTime(next.fromTime);
    if (next.toDate !== undefined) setToDate(next.toDate);
    if (next.toTime !== undefined) setToTime(next.toTime);
    onChange({ from: localIso(nextFromDate, nextFromTime), to: localIso(nextToDate, nextToTime) });
  };

  const clear = () => {
    setFromDate("");
    setToDate("");
    setFromTime("00:00");
    setToTime("23:59");
    onChange({});
  };

  const label = active
    ? `${displayDate(value.from) || "any start"} – ${displayDate(value.to) || "any end"}`
    : "Date filter";

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          size="sm"
          variant={active ? "secondary" : "outline"}
          className="max-w-64 justify-start gap-2 font-normal"
          aria-label="Filter by date"
        >
          <CalendarDaysIcon aria-hidden="true" />
          <span className="truncate">{label}</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[26rem] max-w-[calc(100vw-2rem)] p-4">
        <div className="mb-3">
          <p className="font-medium">Filter by when it was found</p>
          <p className="text-muted-foreground text-xs">Pick a date and time; both ends are inclusive.</p>
        </div>
        <div className="space-y-3">
          <div className="grid gap-1.5 text-xs font-medium">
            <span>From</span>
            <div className="grid grid-cols-[minmax(0,1fr)_9.25rem] items-center gap-2">
              <DateField value={fromDate} onChange={(value) => apply({ fromDate: value })} label="Start date" />
              <TimeSelect
                value={fromTime}
                onValueChange={(value) => apply({ fromTime: value })}
                aria-label="Start time"
              />
            </div>
          </div>
          <div className="grid gap-1.5 text-xs font-medium">
            <span>To</span>
            <div className="grid grid-cols-[minmax(0,1fr)_9.25rem] items-center gap-2">
              <DateField value={toDate} onChange={(value) => apply({ toDate: value })} label="End date" />
              <TimeSelect value={toTime} onValueChange={(value) => apply({ toTime: value })} aria-label="End time" />
            </div>
          </div>
        </div>
        {active && (
          <Button variant="ghost" size="sm" className="mt-3 w-full" onClick={clear}>
            <RotateCcwIcon />
            Clear the date filter
          </Button>
        )}
      </PopoverContent>
    </Popover>
  );
}
