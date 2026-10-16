# scripts/

Repository-level scripts. Server-specific tooling lives in `server/scripts/`,
where it can resolve the server's dependencies.

| Script | What it does |
|---|---|
| [`server/scripts/demo-journey.ts`](../server/scripts/demo-journey.ts) | Runs the full Phase 1 user journey against a real server and prints what the database holds. Development only — it truncates the database it points at. |

```bash
cd server && ./node_modules/.bin/tsx --env-file=.env scripts/demo-journey.ts
```
