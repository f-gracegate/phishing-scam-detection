"use client";

import { CheckCard, MessageCheckForm } from "@/components/check-forms";
import { PageHeader } from "@/components/ui";

export default function CheckMessagePage() {
  return (
    <>
      <PageHeader title="Check a message" description="SMS, WhatsApp and social media messages: spot fake MoMo reversals, OTP requests and other scams." />
      <CheckCard
        title="Paste the message"
        description="We look for requests for PINs or codes, pressure and threats, fake prizes and fees, look-alike links and numbers others have reported."
      >
        <MessageCheckForm />
      </CheckCard>
    </>
  );
}
