# forge — a GitHub-compatible core in one file

`forge` is a small, dependency-free GitHub-compatible service written in
TypeScript for Node.js 22+. A single in-memory store backs four surfaces
that all observe exactly the same state:

- **Git smart HTTP** — protocol v2 (`ls-refs`, `fetch` with shallow and
  deepen support) with a full v0 fallback, plus `receive-pack` with
  report-status, fast-forward enforcement and per-ref results.
- **REST API v3** — repositories, labels, issues, comments, pull requests
  (including squash merges with real three-way conflict detection),
  branches, refs, commits and the contents API. Contents writes are real
  git commits, so anything written over REST is immediately visible to
  git clones, GraphQL and MCP.
- **GraphQL** — viewer/repository/node queries, issue and pull-request
  connections with cursor pagination, `__type` introspection, batched
  operations, and the create-issue / close-issue / create-pull-request /
  merge-pull-request / add-comment mutations.
- **MCP** — a JSON-RPC endpoint that answers both the modern
  `server/discover` handshake and legacy `initialize`, exposing
  `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request` and `merge_pull_request` tools.

Git objects are plain SHA-1 addressed commits, trees, blobs and annotated
tags held in memory; packfiles are produced and consumed with `node:zlib`
alone. There is no database, no subprocess and no npm dependency — the
Node.js standard library does everything.

## Running

```sh
npm start
# equivalently:
node --experimental-strip-types main.ts
```

The process expects `MAKEFUN_ENV_URL` to point at the embedding harness:
it binds an ephemeral port, registers that port with the harness, serves
until the harness reports the run is done, and then exits.

Authentication is a bearer token: when `MAKEFUN_SHOP_TOKEN` is set the
token must match it exactly, otherwise any non-empty bearer token is
accepted. The authenticated user is `adaiversen`.

## Layout

- `main.ts` — process lifecycle (bind, register, wait, shut down).
- `app.ts` — the whole forge: object store, packfile codec, git smart
  HTTP, REST, GraphQL and MCP, exported as `createApp()`.
