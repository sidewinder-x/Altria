import Link from "next/link";

const navigation = [
  { href: "/login", label: "Login" },
  { href: "/dashboard", label: "Dashboard" }
];

export default function HomePage() {
  return (
    <section className="space-y-6">
      <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-6 shadow">
        <h2 className="text-2xl font-medium">Welcome to Altria Web</h2>
        <p className="mt-2 text-sm text-slate-300">
          This is a minimal Next.js 14 starter wired into the monorepo. Use the
          navigation below to explore prepared pages or start building new
          experiences.
        </p>
      </div>
      <nav>
        <ul className="flex flex-wrap gap-4">
          {navigation.map((item) => (
            <li key={item.href}>
              <Link
                className="inline-flex items-center rounded-md border border-slate-700 bg-slate-800 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-slate-500 hover:bg-slate-700"
                href={item.href}
              >
                {item.label}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
    </section>
  );
}
