"use client";

import { AlertTriangle, CheckCircle2, Phone, XCircle } from "lucide-react";
import { ButtonLink, Card, CardHeader, PageHeader } from "@/components/ui";

const GUIDES: { title: string; signs: string[]; doThis: string[] }[] = [
  {
    title: "Fake MoMo reversals and “sent by mistake”",
    signs: [
      "A message says money was sent to you by mistake, then someone calls asking you to send it back.",
      "You're asked to dial a code or approve a prompt to “reverse” a payment.",
      "The “confirmation” SMS comes from an ordinary phone number.",
    ],
    doThis: [
      "Check your real balance in your MoMo menu or app — not in the message.",
      "Never approve a prompt you didn't start. You never need a PIN to receive money.",
      "If money really arrived by mistake, let your provider reverse it, not the caller.",
    ],
  },
  {
    title: "Fake bank and account alerts",
    signs: [
      "Your account will be “blocked” or “suspended” unless you click a link today.",
      "The link looks close to your bank's name but isn't its real website.",
      "You're asked for your PIN, OTP, card number or online banking password.",
    ],
    doThis: [
      "Call your bank on the number on your card.",
      "Type your bank's address yourself instead of using links.",
      "Never share one-time codes, even with someone who says they're from the bank.",
    ],
  },
  {
    title: "Government, delivery and fee scams",
    signs: [
      "GRA, SSNIT, DVLA or NIA “penalties” or refunds paid through an SMS link.",
      "A parcel is “held at customs” until you pay a small fee.",
      "A job, loan, scholarship or prize needs a registration or processing fee first.",
    ],
    doThis: [
      "Use the agency's official .gov.gh website or visit an office.",
      "Track parcels in the courier's official app with your own tracking number.",
      "Don't pay to receive a job, loan, parcel or prize.",
    ],
  },
  {
    title: "Investment, crypto and romance scams",
    signs: [
      "Guaranteed returns, “double your money”, or daily profits.",
      "Requests for your wallet's recovery phrase or to send crypto to “unlock” funds.",
      "Someone you met online has an emergency and needs money urgently.",
    ],
    doThis: [
      "Check investment companies are licensed by the Securities and Exchange Commission, Ghana.",
      "Never share a recovery phrase with anyone, for any reason.",
      "Call the person on a number you already know before sending money.",
    ],
  },
];

export default function SafetyPage() {
  return (
    <>
      <PageHeader title="Safety centre" description="How common scams in Ghana work, and what to do if you're targeted." />
      <div className="grid gap-6 xl:grid-cols-2">
        {GUIDES.map((g) => (
          <Card key={g.title}>
            <CardHeader title={g.title} />
            <p className="mb-2 text-sm font-medium text-critical-text">Warning signs</p>
            <ul className="mb-4 space-y-2 text-sm">
              {g.signs.map((s) => (
                <li key={s} className="flex gap-2">
                  <XCircle className="mt-0.5 size-4 shrink-0 text-critical" aria-hidden />
                  {s}
                </li>
              ))}
            </ul>
            <p className="mb-2 text-sm font-medium text-success-text">What to do</p>
            <ul className="space-y-2 text-sm">
              {g.doThis.map((s) => (
                <li key={s} className="flex gap-2">
                  <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-success" aria-hidden />
                  {s}
                </li>
              ))}
            </ul>
          </Card>
        ))}
      </div>
      <Card className="mt-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
          <AlertTriangle className="size-8 shrink-0 text-high" aria-hidden />
          <div className="flex-1">
            <h2 className="font-heading text-lg font-semibold">Already sent money or shared details?</h2>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-muted">
              <li>Call your bank or mobile money provider immediately to block the account or transaction.</li>
              <li>Change any password or PIN you shared, and sign out of other devices.</li>
              <li>Report it to the Cyber Security Authority — call or text 292 — or to the police.</li>
              <li>Keep screenshots, numbers and transaction IDs as evidence, then report it here.</li>
            </ol>
          </div>
          <div className="flex flex-col gap-2">
            <ButtonLink href="/report">Report a scam</ButtonLink>
            <a href="tel:292" className="inline-flex items-center justify-center gap-1.5 text-sm font-medium text-primary-text">
              <Phone className="size-4" /> Call 292
            </a>
          </div>
        </div>
      </Card>
      <p className="mt-4 text-xs text-subtle">Contact details should be confirmed on the official websites of the organisations named.</p>
    </>
  );
}
