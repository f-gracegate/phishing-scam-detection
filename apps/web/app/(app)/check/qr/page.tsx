"use client";

import { CheckCard, QrCheckForm } from "@/components/check-forms";
import { PageHeader } from "@/components/ui";

export default function CheckQrPage() {
  return (
    <>
      <PageHeader title="Scan a QR code" description="QR codes on posters, payment stickers and messages can lead to fake payment pages." />
      <CheckCard title="Check where it leads" description="Decode the QR code here, then check the link or text it contains — without opening it.">
        <QrCheckForm />
      </CheckCard>
    </>
  );
}
