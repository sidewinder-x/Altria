# Altria Web

This is the Next.js 14 frontend for the Altria monorepo. It ships with a minimal
App Router layout, Tailwind CSS, and TypeScript configuration so new features can
be added quickly.

## Available pages

- `/` — landing page with quick navigation
- `/login` — placeholder for the authentication flow
- `/dashboard` — placeholder for future internal dashboards

Update or replace these stub pages as product requirements evolve.

## Getting started

```bash
pnpm install
pnpm --filter @altria/web dev
```

The dev script runs `next dev`, enabling hot reloading and TypeScript type
checking. Run `pnpm --filter @altria/web build` before deploying.
