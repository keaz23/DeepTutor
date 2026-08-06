"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/** Microsoft Entra ID owns account provisioning; keep old bookmarks usable. */
export default function RegisterPage() {
  const router = useRouter();
  useEffect(() => router.replace("/login"), [router]);
  return null;
}
