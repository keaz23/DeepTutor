"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useTranslation } from "react-i18next";
import { fetchAuthStatus } from "@/lib/auth";

function LoginPageContent() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = searchParams.get("next") ?? "/";
  const [error, setError] = useState("");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    fetchAuthStatus().then((status) => {
      if (status?.authenticated) router.replace(next);
      else if (status?.provider !== "microsoft") setError("Microsoft SSO is not enabled.");
      setReady(true);
    });
  }, [next, router]);

  const reason = searchParams.get("error");
  const rawFailureReason = searchParams.get("reason") ?? "";
  const failureReason = /^[a-z_]{1,64}$/.test(rawFailureReason)
    ? rawFailureReason
    : "";
  const callbackError =
    reason === "microsoft_cancelled"
      ? t("Microsoft sign-in was cancelled.")
      : reason === "microsoft_failed" || reason === "microsoft_state"
        ? `${t("Microsoft sign-in could not be completed. Please try again.")}${
            failureReason ? ` (${failureReason})` : ""
          }`
        : "";
  const message = callbackError || error;

  function signIn() {
    window.location.assign(`/api/v1/auth/microsoft/login?next=${encodeURIComponent(next)}`);
  }

  return (
    <div className="w-full max-w-sm">
      <div className="text-center mb-8">
        <h1 className="font-serif text-2xl font-semibold text-[var(--foreground)] tracking-tight">DeepTutor</h1>
        <p className="mt-1 text-sm text-[var(--muted-foreground)]">{t("Sign in to your account")}</p>
      </div>
      <div className="bg-[var(--card)] border border-[var(--border)] rounded-2xl shadow-sm px-8 py-8">
        <p className="mb-5 text-center text-sm text-[var(--muted-foreground)]">
          {t("Use your organization’s Microsoft account to continue.")}
        </p>
        {message && <p className="mb-4 text-sm text-red-500 bg-red-500/10 rounded-lg px-3 py-2">{message}</p>}
        <button
          type="button"
          disabled={!ready || Boolean(error)}
          onClick={signIn}
          className="w-full py-2.5 px-4 rounded-lg font-medium text-sm bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
        >
          {t("Sign in with Microsoft")}
        </button>
      </div>
      <p className="mt-3 text-center text-xs text-[var(--muted-foreground)]">DeepTutor · Agent-Native Learning</p>
    </div>
  );
}

export default function LoginPage() {
  return <Suspense fallback={<div>Loading sign in...</div>}><LoginPageContent /></Suspense>;
}
