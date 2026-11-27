// Product identity is configuration, not code. Change these through environment variables
// (NEXT_PUBLIC_*) at build time to rebrand without touching components.
export const brand = {
  productName: process.env.NEXT_PUBLIC_PRODUCT_NAME ?? "Phishing and Scam Detection",
  shortName: process.env.NEXT_PUBLIC_PRODUCT_SHORT_NAME ?? "Scam Check",
  tagline:
    process.env.NEXT_PUBLIC_PRODUCT_TAGLINE ??
    "Check suspicious links, messages and emails before they cost you.",
  poweredByName: process.env.NEXT_PUBLIC_POWERED_BY_NAME ?? "GraceGate Technologies",
  poweredByLogo: process.env.NEXT_PUBLIC_POWERED_BY_LOGO ?? "/brand/gracegate-technologies-logo.jpg",
};
