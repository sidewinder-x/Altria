import Link from "next/link";

const widgets = [
  {
    title: "Revenue",
    description: "Track upcoming revenue streams and active subscriptions."
  },
  {
    title: "Operations",
    description: "Monitor service uptime, queue depths, and background jobs."
  },
  {
    title: "Team",
    description: "Assign owners, review requests, and share important updates."
  }
];

export default function DashboardPage() {
  return (
    <section className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-medium">Dashboard overview</h2>
          <p className="mt-2 text-sm text-slate-300">
            Stub content for the future operations dashboard.
          </p>
        </div>
        <Link
          className="rounded-md border border-slate-700 bg-slate-800 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-slate-500 hover:bg-slate-700"
          href="/"
        >
          Back home
        </Link>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        {widgets.map((widget) => (
          <div
            key={widget.title}
            className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 shadow"
          >
            <h3 className="text-lg font-semibold">{widget.title}</h3>
            <p className="mt-1 text-sm text-slate-300">{widget.description}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
