import type { Metadata } from "next";
import Link from "next/link";
import { PoweredBy, ProductMark } from "@/components/powered-by";

export const metadata: Metadata = { title: "Privacy Notice" };

export default function Page() {
  return (
    <div className="mx-auto max-w-2xl px-5 py-10">
      <Link href="/login">
        <ProductMark />
      </Link>
      <h1 className="mt-10 text-2xl font-semibold tracking-tight">Privacy Notice</h1>
      <p className="mt-1 text-sm text-muted">How we handle personal data under Ghana’s Data Protection Act, 2012 (Act 843).</p>
      <div className="mt-6 rounded-[var(--radius-control)] border border-warning/30 bg-warning-soft p-4 text-sm text-warning-text">
        Pilot version. This notice will be reviewed by a lawyer, and our registration with the Data
        Protection Commission and guidance from the Cyber Security Authority confirmed, before commercial launch.
      </div>
      <Section title="Who we are and our role">
        <p>
          Phishing and Scam Detection is provided by GraceGate Technologies. For your personal account, your private
          checks and the scam reports you send, we are the <strong>data controller</strong>. For content a business
          workspace&apos;s staff submit, that organisation is the controller and we act as its{" "}
          <strong>data processor</strong> under a data-processing agreement.
        </p>
      </Section>
      <Section title="What we process">
        <ul className="list-disc space-y-1.5 pl-5">
          <li>Account details: name, email, sign-in history and whether two-step sign-in is on.</li>
          <li>
            What you ask us to check: links, messages, emails and QR codes. Before anything is saved we remove one-time
            codes, PINs, passwords, card numbers and private tokens in links we can recognise.
          </li>
          <li>
            Scam reports: the category, the suspicious link, number or sender, your description, screenshots and, if you
            give it, a contact email. Phone numbers are stored encrypted and shown masked.
          </li>
          <li>Feedback on results, notifications, and (mobile) a push token per phone. Billing: plan and amounts only.</li>
        </ul>
      </Section>
      <Section title="Why, and who else is involved">
        <p>
          To check suspicious content for you, keep the service secure, improve detection, warn others about verified
          scams, bill and support you. We don&apos;t sell data, use it for advertising, or train AI models on your
          submissions by default. When you allow it, links (with private tokens removed) may be checked with licensed
          threat-intelligence providers such as Google Web Risk. Other providers: our hosting provider, Paystack
          (payments), Google Firebase (phone notifications) and our email provider, each bound by contract.
        </p>
        <p className="mt-2">
          Your personal scan history is private to you. An employer never sees it, even if you sign up with a work
          email; only checks you run inside a business workspace are visible to that workspace&apos;s security staff.
        </p>
      </Section>
      <Section title="Scam reports and other people's data">
        <p>
          Reports often name phone numbers, websites or businesses. Every report starts <strong>unverified</strong> and
          is reviewed by an analyst before anything it names is treated as a confirmed threat. We never publish a
          report, a private message or a personal phone number as an accusation. Public warnings describe scam patterns
          only.
        </p>
      </Section>
      <Section title="How long we keep it">
        <ul className="list-disc space-y-1.5 pl-5">
          <li>Submitted message and email text: encrypted, 30 days by default (a workspace can choose 1 to 365 days within its plan), then erased.</li>
          <li>Verdicts and the indicators extracted from them: while your account or workspace exists, or until you delete them.</li>
          <li>Verified threat indicators: until they expire or are revoked; they are rechecked regularly.</li>
          <li>Notifications: 180 days. Data exports: 7 days. Deleted workspaces: erased after a 30-day cooling-off period.</li>
        </ul>
      </Section>
      <Section title="Security">
        <p>
          Private data is isolated at the database level. Content is encrypted at rest and in transit. Websites are
          visited only by an isolated system with no access to our databases. Passwords are hashed with Argon2id.
          Analyst access to reports is limited, and revealing a full phone number is recorded.
        </p>
      </Section>
      <Section title="Your rights">
        <p>
          You can access, correct or delete your personal data and object to processing. Download your data, clear your
          scan history or delete your account under <em>Settings → Data and privacy</em>. If someone reported your
          number or website and you believe it&apos;s wrong, contact us and an analyst will review it. You may complain
          to the Data Protection Commission of Ghana.
        </p>
      </Section>
      <p className="mt-8 text-[13px] text-muted">Contact: privacy@gracegate.example. Last updated 27 November 2026.</p>
      <div className="mt-12">
        <PoweredBy />
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-7 text-sm leading-relaxed">
      <h2 className="mb-2 text-base font-semibold text-fg">{title}</h2>
      {children}
    </section>
  );
}

