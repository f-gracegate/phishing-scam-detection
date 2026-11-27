"use client";

import { CheckCard, LinkCheckForm } from "@/components/check-forms";
import { PageHeader } from "@/components/ui";

export default function CheckLinkPage() {
  return (
    <>
      <PageHeader title="Check a link" description="Find out whether a website or link shows signs of phishing before you open it." />
      <CheckCard
        title="Paste the link"
        description="We check our verified threat list, the address itself (look-alike names, tricks, new domains) and safely visit the website from an isolated system to inspect forms, redirects and its certificate."
      >
        <LinkCheckForm autoFocus />
      </CheckCard>
    </>
  );
}
