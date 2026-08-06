"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useTranslation } from "react-i18next";
import { adminLogin, fetchAuthStatus } from "@/lib/auth";

/** Local break-glass login for the DeepTutor administrator. */
export default function AdminLoginPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = searchParams.get("next") ?? "/";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchAuthStatus().then((status) => {
      if (status?.authenticated && status.is_admin) router.replace(next);
    });
  }, [next, router]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError("");
    const result = await adminLogin(username, password);
    if (result.ok) router.replace(next);
    else {
      setError(result.error ?? "Login failed");
      setLoading(false);
    }
  }

  return (
    <div className="w-full max-w-sm">
      <div className="text-center mb-8">
        <h1 className="font-serif text-2xl font-semibold text-[var(--foreground)] tracking-tight">{t("DeepTutor")}</h1>
        <p className="mt-1 text-sm text-[var(--muted-foreground)]">{t("Administrator sign in")}</p>
      </div>
      <form onSubmit={submit} className="space-y-5 bg-[var(--card)] border border-[var(--border)] rounded-2xl shadow-sm px-8 py-8">
        <input aria-label={t("Username")} autoComplete="username" required value={username} onChange={(event) => setUsername(event.target.value)} placeholder={t("Username")} className="w-full px-3.5 py-2.5 rounded-lg border border-[var(--border)] bg-[var(--background)] text-sm" />
        <input aria-label={t("Password")} type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} placeholder={t("Password")} className="w-full px-3.5 py-2.5 rounded-lg border border-[var(--border)] bg-[var(--background)] text-sm" />
        {error && <p className="text-sm text-red-500 bg-red-500/10 rounded-lg px-3 py-2">{error}</p>}
        <button type="submit" disabled={loading} className="w-full py-2.5 px-4 rounded-lg font-medium text-sm bg-[var(--primary)] text-[var(--primary-foreground)] disabled:opacity-50">{loading ? t("Signing in…") : t("Sign in as administrator")}</button>
      </form>
    </div>
  );
}
