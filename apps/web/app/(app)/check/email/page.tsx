"use client";

import { CheckCard, EmailCheckForm } from "@/components/check-forms";
import { PageHeader } from "@/components/ui";

export default function CheckEmailPage() {
  return (
    <>
      <PageHeader title="Check an email" description="Inspect the sender, reply-to address, authentication results, links and attachments." />
      <CheckCard
        title="Paste or upload the email"
        description="We compare the sender with the organisation it claims to be, check SPF, DKIM and DMARC results when headers are included, and look for disguised links and dangerous attachments."
      >
        <EmailCheckForm />
      </CheckCard>
    </>
  );
}
