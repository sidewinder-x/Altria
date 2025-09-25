import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Altria Dashboard",
  description: "Internal control panel for the Altria platform"
};

interface RootLayoutProps {
  children: React.ReactNode;
}

export default function RootLayout({ children }: RootLayoutProps) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased">
        <main className="mx-auto flex w-full max-w-4xl flex-col gap-8 p-6">
          <header className="flex flex-col gap-2">
            <h1 className="text-3xl font-semibold tracking-tight">Altria</h1>
            <p className="text-sm text-slate-400">
              Simple starter layout powered by Next.js 14 and Tailwind CSS.
            </p>
          </header>
          {children}
        </main>
      </body>
    </html>
  );
}
