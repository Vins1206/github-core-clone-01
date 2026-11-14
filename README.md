# github-core-clone-01 — a standalone GitHub-compatible forge

One Node process, one in-memory store, no dependencies, no UI, no external
services, and no `git` binary at runtime. The forge serves four surfaces that
all read and write the same store, so an object created through one surface is
the same object through every other:

- **Git smart HTTP** at `/{owner}/{repo}.git` — `info/refs`, `git-upload-pack`
  and `git-receive-pack`. Upload-pack speaks protocol v2 (`ls-refs` and the
  sectioned `fetch`, with shallow/deepen support) and protocol v0 (with
  side-band-64k). Receive-pack speaks v0 with `report-status`, per-ref
  fast-forward enforcement and delta pack reading (OFS_DELTA and REF_DELTA).
  Objects are stored by their real sha1 ids; packs are written plain and
  verified by clients through their sha1 trailer.
- **REST v3** under `/api/v3` — the API root and `/meta`, repository CRUD,
  the contents API (create/update/delete with sha checks), branches, git
  refs, commit lists, labels, issues and comments, and pull requests
  (list/read/files/merge, squash or merge commit, with real three-way
  conflict detection against the merge base). Lists paginate with `Link`
  headers; every answer is JSON carrying an `X-GitHub-Request-Id`.
- **GraphQL v4** at `/api/graphql` — `viewer`, `repository` (fields, issues
  with states/orderBy/cursor pagination, pull requests and their files),
  `node(id:)` global-id round-trips, `__type` introspection for the field
  probes `gh` runs, and the create/close/merge mutations plus `addComment`.
  Batched operation arrays are answered in order; an unknown field is a 200
  with an `errors` array naming it, as GitHub answers.
- **MCP** at `/mcp` — streamable-HTTP JSON-RPC with `server/discover`
  (2026-07-28), the legacy `initialize` handshake, and six tools
  (`create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request`) acting on the same store.

## Layout

- `main.ts` — the harness lifecycle: bind an ephemeral port, register it with
  `$MAKEFUN_ENV_URL`, poll `/done`, exit 0.
- `app.ts` — the whole forge: object store, pack codec, protocol handlers,
  REST router, GraphQL parser/executor and MCP endpoint.

Determinism: every timestamp the forge writes comes from a logical clock, so
replaying the same request sequence reproduces the same export byte for byte.

## Run

```
node --experimental-strip-types main.ts   # needs MAKEFUN_ENV_URL
```

Requires Node ≥ 22.18 (native type stripping; only erasable TypeScript syntax
is used).
