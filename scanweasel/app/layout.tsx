import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ScanWeasel — Passive website security check",
  description:
    "Fast passive checks for security headers, CSP, cookies, HTTPS, and selected public paths — explained in plain language.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
