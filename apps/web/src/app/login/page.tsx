import Link from "next/link";

export default function LoginPage() {
  return (
    <section className="space-y-6">
      <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-6 shadow">
        <h2 className="text-2xl font-medium">Sign in</h2>
        <p className="mt-2 text-sm text-slate-300">
          This placeholder page documents the future login experience. Replace it
          with your authentication flow when ready.
        </p>
      </div>
      <p className="text-sm text-slate-400">
        Return to the <Link className="underline" href="/">home page</Link> or
        preview the <Link className="underline" href="/dashboard">dashboard</Link>.
      </p>
    </section>
  );
}
