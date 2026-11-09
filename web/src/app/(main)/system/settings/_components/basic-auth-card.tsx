"use client";

import { useCallback, useEffect, useState } from "react";

import { ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";

export function BasicAuthCard() {
  const [enabled, setEnabled] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordSet, setPasswordSet] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const settings = await api.basicAuthSettings();
      setEnabled(settings.enabled);
      setUsername(settings.username);
      setPasswordSet(settings.password_set);
      setLoaded(true);
    } catch (e) {
      setError(`Could not load: ${(e as Error).message}`);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const settings = await api.setBasicAuthSettings({ enabled, username: username.trim(), password });
      setEnabled(settings.enabled);
      setUsername(settings.username);
      setPasswordSet(settings.password_set);
      setPassword("");
      toast.success(
        settings.enabled ? "HTTP Basic Auth is on; this browser keeps its access" : "HTTP Basic Auth is off",
      );
    } catch (e) {
      setError(`Save failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheckIcon className="size-4" />
          HTTP Basic Auth
        </CardTitle>
        <CardDescription>
          When on, a visitor must pass the browser's own username and password prompt before reaching the ARTEX login
          page. Off by default; saving takes effect at once.
        </CardDescription>
      </CardHeader>
      <form onSubmit={save}>
        <CardContent>
          <FieldGroup>
            <Field orientation="horizontal">
              <FieldLabel htmlFor="basic-auth-enabled">Require Basic Auth</FieldLabel>
              <Switch
                id="basic-auth-enabled"
                checked={enabled}
                onCheckedChange={setEnabled}
                disabled={!loaded || saving}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="basic-auth-username">Username</FieldLabel>
              <Input
                id="basic-auth-username"
                autoComplete="off"
                value={username}
                required={enabled}
                disabled={!loaded || saving}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="separate from the ARTEX login account"
              />
              <FieldDescription>No colons, at most 128 bytes.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="basic-auth-password">Password</FieldLabel>
              <Input
                id="basic-auth-password"
                type="password"
                autoComplete="new-password"
                value={password}
                required={enabled && !passwordSet}
                disabled={!loaded || saving}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={passwordSet ? "set; leave empty to keep it" : "at least 8 characters, at most 72 bytes"}
              />
              <FieldDescription>
                Independent of the ARTEX login password. Use HTTPS when it is reachable from the internet.
              </FieldDescription>
            </Field>
            <FieldDescription>
              Saving does not cut off this browser. Check the prompt in a private window; browsers may cache
              credentials. Turning it off keeps the username and password for next time.
            </FieldDescription>
            {error ? (
              <p role="alert" className="text-destructive text-sm">
                {error}
              </p>
            ) : null}
          </FieldGroup>
        </CardContent>
        <CardFooter className="mt-4 gap-2">
          <Button type="submit" disabled={!loaded || saving}>
            {saving ? "Saving…" : "Save"}
          </Button>
          {!loaded && error ? (
            <Button type="button" variant="outline" onClick={load}>
              Reload
            </Button>
          ) : null}
        </CardFooter>
      </form>
    </Card>
  );
}
