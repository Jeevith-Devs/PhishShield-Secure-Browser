import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'PhishShield SOC Dashboard',
  description: 'Enterprise Security Operations Center — Cyber Threat Detection, Risk Analytics & Investigation Platform',
  keywords: ['phishing', 'cybersecurity', 'threat intelligence', 'SOC', 'browser security'],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="scanline-bg">{children}</body>
    </html>
  );
}
