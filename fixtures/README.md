# DevGuard fixtures

Two small Node.js apps with the same layout. `vulnerable-app` contains intentional flaws; `fixed-app` contains the corresponding fixes.

**Every credential in `vulnerable-app` is fake**: randomly generated, tied to no real service, and listed in `tests/fixture_secrets.txt` so leak tests can prove DevGuard never stores or shows them.

| Category | `vulnerable-app` (intentional flaw) | `fixed-app` (fix) |
|----------|-------------------------------------|-------------------|
| Dependencies | `express@4.16.0`, `lodash@4.17.15`, `minimist@1.2.0` (known CVEs) | Current patched releases |
| Secret: `src/config.js` | Hard-coded generic API key and signed session token (JWT) | Read from `process.env` |
| Secret: `.env.example` | Database password and GitHub personal access token | Empty placeholders |
| Dockerfile | `node:latest`, `ADD`, no `USER` (runs as root), no `HEALTHCHECK` | Pinned tag, `COPY`, `USER node`, `HEALTHCHECK` |
| Kubernetes | `privileged: true`, `allowPrivilegeEscalation: true`, `hostNetwork: true`, no resource limits, no `runAsNonRoot`, `:latest` image | Hardened `securityContext`, dropped capabilities, limits, `readOnlyRootFilesystem: true`, pinned image |

Lockfiles were generated with `npm install --package-lock-only`; `node_modules` is never created or committed.

`expected.json` holds version-independent minimum expectations used by the evaluation run. Exact counts are not asserted because vulnerability databases change over time.
