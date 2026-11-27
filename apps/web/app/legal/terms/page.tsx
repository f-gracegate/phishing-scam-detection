import type { Metadata } from "next";
import Link from "next/link";
import { PoweredBy, ProductMark } from "@/components/powered-by";

export const metadata: Metadata = { title: "Terms of Service" };

export default function Page() {
  return (
    <div className="mx-auto max-w-2xl px-5 py-10">
      <Link href="/login">
        <ProductMark />
      </Link>
      <h1 className="mt-10 text-2xl font-semibold tracking-tight">Terms of Service</h1>
      <p className="mt-1 text-sm text-muted">The rules for using the platform.</p>
      <div className="mt-6 rounded-[var(--radius-control)] border border-warning/30 bg-warning-soft p-4 text-sm text-warning-text">
        Pilot version. The full terms and data-processing agreement will be published after legal
        review and before commercial launch.
      </div>
      <ul className="mt-6 list-disc space-y-3 pl-5 text-sm leading-relaxed">
          <li>Results are assessments of the evidence available at the time, not guarantees. A link or message with no warning signs may still be a scam, and a flagged one may be genuine — always verify through official channels before acting.</li>
          <li>Only submit content you received or are entitled to share. Remove other people&apos;s personal details where you can.</li>
          <li>Scam reports must be honest. Don&apos;t report a person, number or business you know to be legitimate; false or malicious reports may lead to your account being closed.</li>
          <li>Reports are reviewed before anything is confirmed, and we never publish them as accusations.</li>
          <li>Keep your login details and API keys private, and use multi-factor authentication for administrator accounts.</li>
          <li>Don&apos;t use the service, its API or the website scanner to attack, probe or overload systems, or to scan internal networks.</li>
          <li>Business plans are prepaid monthly or yearly in Ghana cedis, with no automatic charges. If a plan lapses your data is kept and your team can still check content, but you can&apos;t add people, API keys or webhooks until you renew.</li>
          <li>Investigation or managed security services, where offered, are subject to applicable Cyber Security Authority licensing.</li>
          <li>You can export your data and delete your account or workspace at any time from Settings → Data and privacy.</li>
      </ul>
      <div className="mt-12">
        <PoweredBy />
      </div>
    </div>
  );
}
