// forge — a small, self-contained GitHub-compatible forge.
//
// One in-memory store backs four surfaces that all observe the same state:
//   * git smart HTTP (protocol v2 with a v0 fallback)
//   * the REST v3 API
//   * a GraphQL endpoint covering the query/mutation shapes clients use
//   * an MCP endpoint (JSON-RPC, modern discover + legacy initialize)
//
// Everything runs on the Node.js standard library alone: git objects are
// plain SHA-1 addressed blobs/commits/trees/tags kept in Maps, packfiles
// are produced and consumed with node:zlib, and the HTTP layer is
// node:http. There is no database and no subprocess: state lives for the
// lifetime of the process, which is exactly what the embedding harness
// expects from createApp().

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';

// ---------------------------------------------------------------------------
// Identity of the single authenticated user (the "viewer").
// ---------------------------------------------------------------------------

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';

const ZERO_OID = '0000000000000000000000000000000000000000';
const EPOCH_SECONDS = 1735689600; // 2025-01-01T00:00:00Z, base for fake clocks
const AGENT_STRING = 'forge/1.0';
const FORGE_VERSION = '1.0.0';

// ---------------------------------------------------------------------------
// Small byte helpers.
// ---------------------------------------------------------------------------

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

function utf8(text: string): Buffer {
  return Buffer.from(text, 'utf8');
}

function countLines(data: Buffer): number {
  if (data.length === 0) return 0;
  const text = data.toString('utf8');
  const parts = text.split('\n').length;
  return text.endsWith('\n') ? parts - 1 : parts;
}

// ---------------------------------------------------------------------------
// pkt-line framing (git smart HTTP).
// ---------------------------------------------------------------------------

function pktLine(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? utf8(payload) : payload;
  const head = utf8((body.length + 4).toString(16).padStart(4, '0'));
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = utf8('0000');
const PKT_DELIM = utf8('0001');

type PktItem = Buffer | 'flush' | 'delim';

// Parse a whole pkt-line stream. Throws on malformed input so HTTP handlers
// can answer 400 instead of dying.
function parsePktStream(buf: Buffer): { items: PktItem[]; rest: Buffer } {
  const items: PktItem[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const hex = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('invalid pkt-line header');
    const length = parseInt(hex, 16);
    if (length === 0 || length === 2) {
      items.push('flush');
      offset += 4;
    } else if (length === 1) {
      items.push('delim');
      offset += 4;
    } else {
      if (length < 4 || offset + length > buf.length) throw new Error('truncated pkt-line');
      items.push(Buffer.from(buf.subarray(offset + 4, offset + length)));
      offset += length;
    }
  }
  if (offset !== buf.length) throw new Error('trailing bytes after pkt-line stream');
  return { items, rest: buf.subarray(offset) };
}

// Split pkt-items into flush/delim separated sections.
function pktSections(items: PktItem[]): Buffer[][] {
  const sections: Buffer[][] = [];
  let current: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush' || item === 'delim') {
      sections.push(current);
      current = [];
    } else {
      current.push(item);
    }
  }
  if (current.length > 0) sections.push(current);
  return sections;
}

// Wrap payload bytes in side-band-64k band-1 packets.
function sidebandPackets(data: Buffer, band = 1): Buffer[] {
  const packets: Buffer[] = [];
  const maxPayload = 65520 - 5;
  for (let offset = 0; offset < data.length; offset += maxPayload) {
    const chunk = data.subarray(offset, Math.min(data.length, offset + maxPayload));
    packets.push(pktLine(Buffer.concat([Buffer.from([band]), chunk])));
  }
  return packets;
}

// ---------------------------------------------------------------------------
// Git object model.
// ---------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: ObjType;
  data: Buffer;
}

const TYPE_TO_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TO_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function objectId(type: ObjType, data: Buffer): string {
  const header = utf8(`${type} ${data.length}\0`);
  return sha1Hex(Buffer.concat([header, data]));
}

// --- packfiles --------------------------------------------------------------

function encodePackObjectHeader(type: ObjType, size: number): Buffer {
  const bytes: number[] = [];
  let first = (TYPE_TO_CODE[type] << 4) | (size & 0x0f);
  size = Math.floor(size / 16);
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let byte = size & 0x7f;
    size = Math.floor(size / 128);
    if (size > 0) byte |= 0x80;
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

function buildPack(objects: GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(encodePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// Apply a git delta buffer to a base payload.
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (offset >= delta.length) throw new Error('delta varint overruns buffer');
      const byte = delta[offset++];
      value |= (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const targetSize = readVarint();
  const chunks: Buffer[] = [];
  let produced = 0;
  while (offset < delta.length) {
    const command = delta[offset++];
    if (command & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      for (let bit = 0; bit < 4; bit++) {
        if (command & (1 << bit)) copyOffset |= delta[offset++] * 2 ** (8 * bit);
      }
      for (let bit = 0; bit < 3; bit++) {
        if (command & (0x10 << bit)) copySize |= delta[offset++] * 2 ** (8 * bit);
      }
      if (copySize === 0) copySize = 0x10000;
      chunks.push(base.subarray(copyOffset, copyOffset + copySize));
      produced += copySize;
    } else if (command > 0) {
      chunks.push(delta.subarray(offset, offset + command));
      offset += command;
      produced += command;
    } else {
      throw new Error('delta opcode 0 is reserved');
    }
  }
  const result = Buffer.concat(chunks);
  if (produced !== targetSize || result.length !== targetSize) {
    throw new Error('delta result size mismatch');
  }
  return result;
}

interface PackEntry {
  type: ObjType;
  data: Buffer;
}

// Parse a packfile. Delta bases may live inside the pack (ofs/ref) or, for
// thin packs, in the receiving repository — `externalBase` resolves those.
function readPack(
  buf: Buffer,
  externalBase?: (oid: string) => GitObject | undefined,
): PackEntry[] {
  if (buf.length < 12 + 20) throw new Error('pack too short');
  if (buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack magic');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const trailerStart = buf.length - 20;
  const trailer = buf.subarray(trailerStart);
  const digest = createHash('sha1').update(buf.subarray(0, trailerStart)).digest();
  if (!digest.equals(trailer)) throw new Error('pack checksum mismatch');

  interface RawEntry {
    type: ObjType;
    data: Buffer;
    packOffset: number;
    baseOffset?: number;
    baseOid?: string;
  }
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, number>();
  let offset = 12;
  for (let index = 0; index < count; index++) {
    const entryOffset = offset;
    let byte = buf[offset++];
    const type = CODE_TO_TYPE[(byte >> 4) & 0x07];
    if (!type) throw new Error('unknown pack object type');
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = buf[offset++];
      size |= (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    let baseOffset: number | undefined;
    let baseOid: string | undefined;
    let kind: ObjType | 'ofs-delta' | 'ref-delta' = type;
    const code = (buf[entryOffset] >> 4) & 0x07;
    if (code === 6) {
      kind = 'ofs-delta';
      let back = buf[offset++];
      let value = back & 0x7f;
      while (back & 0x80) {
        back = buf[offset++];
        value = (value + 1) * 128 + (back & 0x7f);
      }
      baseOffset = entryOffset - value;
    } else if (code === 7) {
      kind = 'ref-delta';
      baseOid = buf.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    const inflated = inflateSync(buf.subarray(offset, trailerStart), { info: true });
    const data = inflated.buffer as Buffer;
    if (data.length !== size) throw new Error('pack object size mismatch');
    offset += (inflated.engine as unknown as { bytesWritten: number }).bytesWritten;
    byOffset.set(entryOffset, raw.length);
    raw.push({
      type: kind === 'ofs-delta' || kind === 'ref-delta' ? 'blob' : type,
      data,
      packOffset: entryOffset,
      baseOffset,
      baseOid,
    });
    // Remember the delta flavour on the entry for the resolution pass.
    (raw[raw.length - 1] as RawEntry & { kind: string }).kind = kind;
  }
  if (offset !== trailerStart) throw new Error('pack entries do not end at the trailer');

  const resolved: (PackEntry | undefined)[] = raw.map(() => undefined);
  const resolve = (index: number, depth: number): PackEntry => {
    const cached = resolved[index];
    if (cached) return cached;
    if (depth > 64) throw new Error('delta chain too deep');
    const entry = raw[index] as RawEntry & { kind: string };
    let out: PackEntry;
    if (entry.kind === 'ofs-delta') {
      const baseIndex = byOffset.get(entry.baseOffset as number);
      if (baseIndex === undefined) throw new Error('ofs-delta base not in pack');
      const base = resolve(baseIndex, depth + 1);
      out = { type: base.type, data: applyDelta(base.data, entry.data) };
    } else if (entry.kind === 'ref-delta') {
      let base: PackEntry | undefined;
      const baseOid = entry.baseOid as string;
      for (let i = 0; i < raw.length; i++) {
        const candidate = raw[i] as RawEntry & { kind: string };
        if (candidate.kind !== 'ofs-delta' && candidate.kind !== 'ref-delta') {
          if (objectId(candidate.type, candidate.data) === baseOid) {
            base = resolve(i, depth + 1);
            break;
          }
        }
      }
      if (!base && externalBase) {
        const external = externalBase(baseOid);
        if (external) base = { type: external.type, data: external.data };
      }
      if (!base) throw new Error('ref-delta base not found');
      out = { type: base.type, data: applyDelta(base.data, entry.data) };
    } else {
      out = { type: entry.type, data: entry.data };
    }
    resolved[index] = out;
    return out;
  };
  return raw.map((_, index) => resolve(index, 0));
}

// ---------------------------------------------------------------------------
// Repository store.
// ---------------------------------------------------------------------------

interface CommentRec {
  id: number;
  body: string;
  author: string;
  createdSeq: number;
}

interface IssueRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: CommentRec[];
  createdSeq: number;
}

interface PullRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headShaAtCreate: string;
  baseShaAtCreate: string;
  createdSeq: number;
}

interface LabelRec {
  name: string;
  color: string;
}

interface RepoRec {
  id: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  headRef: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, LabelRec>;
  issues: Map<number, IssueRec>;
  pulls: Map<number, PullRec>;
  nextNumber: number;
  createdSeq: number;
}

interface Store {
  repos: Map<string, RepoRec>;
  nextRepoId: number;
  nextIssueId: number;
  nextPullId: number;
  nextCommentId: number;
  clockSeq: number;
  requestSeq: number;
}

function createStore(): Store {
  return {
    repos: new Map(),
    nextRepoId: 1,
    nextIssueId: 1,
    nextPullId: 1,
    nextCommentId: 1,
    clockSeq: 0,
    requestSeq: 0,
  };
}

// Deterministic pseudo-clock: each call advances one second past the epoch.
function tickIso(store: Store): string {
  store.clockSeq += 1;
  return new Date((EPOCH_SECONDS + store.clockSeq) * 1000).toISOString();
}

function tickSeconds(store: Store): number {
  store.clockSeq += 1;
  return EPOCH_SECONDS + store.clockSeq;
}

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function findRepo(store: Store, owner: string, name: string): RepoRec | undefined {
  return store.repos.get(repoKey(owner, name));
}

function createRepoRec(
  store: Store,
  owner: string,
  name: string,
  description: string,
  isPrivate: boolean,
): RepoRec {
  const repo: RepoRec = {
    id: store.nextRepoId++,
    owner,
    name,
    description,
    isPrivate,
    defaultBranch: 'main',
    headRef: 'refs/heads/main',
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    createdSeq: store.clockSeq + 1,
  };
  tickIso(store);
  store.repos.set(repoKey(owner, name), repo);
  return repo;
}

// --- object access ----------------------------------------------------------

function putObject(repo: RepoRec, type: ObjType, data: Buffer): string {
  const oid = objectId(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function getObject(repo: RepoRec, oid: string): GitObject | undefined {
  return repo.objects.get(oid);
}

// --- trees ------------------------------------------------------------------

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const mode = data.subarray(offset, space).toString('ascii');
    const nul = data.indexOf(0x00, space + 1);
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

function serializeTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const keyA = a.name + (a.mode === '40000' ? '/' : '');
    const keyB = b.name + (b.mode === '40000' ? '/' : '');
    return Buffer.compare(utf8(keyA), utf8(keyB));
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(utf8(`${entry.mode} ${entry.name}\0`));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

// Flatten a tree into path -> blob info, recursing into subtrees.
function flattenTree(repo: RepoRec, treeOid: string): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, prefix: string): void => {
    const object = getObject(repo, oid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(treeOid, '');
  return out;
}

// Rebuild nested trees from a flattened path map. Returns the root tree oid.
function buildTreeFromFlat(repo: RepoRec, flat: Map<string, { oid: string; mode: string }>): string {
  interface DirNode {
    files: { name: string; oid: string; mode: string }[];
    dirs: Map<string, DirNode>;
  }
  const root: DirNode = { files: [], dirs: new Map() };
  for (const [path, info] of flat) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i++) {
      let next = node.dirs.get(segments[i]);
      if (!next) {
        next = { files: [], dirs: new Map() };
        node.dirs.set(segments[i], next);
      }
      node = next;
    }
    node.files.push({ name: segments[segments.length - 1], oid: info.oid, mode: info.mode });
  }
  const emit = (node: DirNode): string => {
    const entries: TreeEntry[] = [];
    for (const [name, child] of node.dirs) {
      entries.push({ mode: '40000', name, oid: emit(child) });
    }
    for (const file of node.files) {
      entries.push({ mode: file.mode, name: file.name, oid: file.oid });
    }
    return putObject(repo, 'tree', serializeTree(entries));
  };
  return emit(root);
}

// --- commits & tags ---------------------------------------------------------

interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitInfo {
  const splitAt = data.indexOf('\n\n');
  const headerText = data.subarray(0, splitAt === -1 ? data.length : splitAt).toString('utf8');
  const message = splitAt === -1 ? '' : data.subarray(splitAt + 2).toString('utf8');
  const info: CommitInfo = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of headerText.split('\n')) {
    if (line.startsWith('tree ')) info.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) info.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) info.author = line.slice(7);
    else if (line.startsWith('committer ')) info.committer = line.slice(10);
  }
  return info;
}

function makeCommit(
  store: Store,
  repo: RepoRec,
  treeOid: string,
  parents: string[],
  message: string,
): string {
  const stamp = tickSeconds(store);
  const ident = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${stamp} +0000`;
  const lines = [`tree ${treeOid}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${ident}`, `committer ${ident}`, '', message);
  return putObject(repo, 'commit', utf8(lines.join('\n')));
}

function parseTagTarget(data: Buffer): string {
  for (const line of data.toString('utf8').split('\n')) {
    if (line.startsWith('object ')) return line.slice(7).trim();
    if (line === '') break;
  }
  return '';
}

// Follow tag objects until a non-tag object; returns that oid.
function peelTag(repo: RepoRec, oid: string): string {
  let current = oid;
  for (let guard = 0; guard < 32; guard++) {
    const object = getObject(repo, current);
    if (!object || object.type !== 'tag') return current;
    current = parseTagTarget(object.data);
  }
  return current;
}

// Resolve an oid to the commit it points at (through tags), or undefined.
function resolveCommit(repo: RepoRec, oid: string): string | undefined {
  const target = peelTag(repo, oid);
  const object = getObject(repo, target);
  return object && object.type === 'commit' ? target : undefined;
}

function commitTreeOid(repo: RepoRec, commitOid: string): string {
  const object = getObject(repo, commitOid);
  if (!object || object.type !== 'commit') return '';
  return parseCommit(object.data).tree;
}

function branchTip(repo: RepoRec, branch: string): string | undefined {
  return repo.refs.get(`refs/heads/${branch}`);
}

// Read a path inside a commit: file contents or a directory listing.
type PathRead =
  | { kind: 'file'; oid: string; data: Buffer }
  | { kind: 'dir'; entries: { name: string; path: string; oid: string; type: 'file' | 'dir' }[] }
  | null;

function readPath(repo: RepoRec, commitOid: string, path: string): PathRead {
  let treeOid = commitTreeOid(repo, commitOid);
  if (!treeOid) return null;
  const segments = path === '' ? [] : path.split('/');
  for (let i = 0; i < segments.length; i++) {
    const tree = getObject(repo, treeOid);
    if (!tree || tree.type !== 'tree') return null;
    const entries = parseTree(tree.data);
    if (i === segments.length - 1) {
      const entry = entries.find((candidate) => candidate.name === segments[i]);
      if (!entry) return null;
      if (entry.mode === '40000') {
        const sub = getObject(repo, entry.oid);
        if (!sub || sub.type !== 'tree') return null;
        return {
          kind: 'dir',
          entries: parseTree(sub.data).map((child) => ({
            name: child.name,
            path: `${path}/${child.name}`,
            oid: child.oid,
            type: child.mode === '40000' ? ('dir' as const) : ('file' as const),
          })),
        };
      }
      const blob = getObject(repo, entry.oid);
      if (!blob) return null;
      return { kind: 'file', oid: entry.oid, data: blob.data };
    }
    const next = entries.find((candidate) => candidate.name === segments[i] && candidate.mode === '40000');
    if (!next) return null;
    treeOid = next.oid;
  }
  // path === '' → the root directory listing.
  const tree = getObject(repo, treeOid);
  if (!tree || tree.type !== 'tree') return null;
  return {
    kind: 'dir',
    entries: parseTree(tree.data).map((child) => ({
      name: child.name,
      path: child.name,
      oid: child.oid,
      type: child.mode === '40000' ? ('dir' as const) : ('file' as const),
    })),
  };
}

// --- ancestry & reachability --------------------------------------------------

function isAncestor(repo: RepoRec, ancestor: string, descendant: string): boolean {
  const seen = new Set<string>();
  const queue = [descendant];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    if (current === ancestor) return true;
    if (seen.has(current)) continue;
    seen.add(current);
    const object = getObject(repo, current);
    if (!object || object.type !== 'commit') continue;
    queue.push(...parseCommit(object.data).parents);
  }
  return false;
}

function findMergeBase(repo: RepoRec, a: string, b: string): string | undefined {
  const ancestorsOfA = new Set<string>();
  const stack = [a];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    if (ancestorsOfA.has(current)) continue;
    ancestorsOfA.add(current);
    const object = getObject(repo, current);
    if (object && object.type === 'commit') stack.push(...parseCommit(object.data).parents);
  }
  const seen = new Set<string>();
  const queue = [b];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    if (ancestorsOfA.has(current)) return current;
    if (seen.has(current)) continue;
    seen.add(current);
    const object = getObject(repo, current);
    if (object && object.type === 'commit') queue.push(...parseCommit(object.data).parents);
  }
  return undefined;
}

// Every object reachable from the given roots (full closure).
function closureFull(repo: RepoRec, roots: string[]): Set<string> {
  const out = new Set<string>();
  const visit = (oid: string): void => {
    if (out.has(oid)) return;
    const object = getObject(repo, oid);
    if (!object) return;
    out.add(oid);
    if (object.type === 'commit') {
      const info = parseCommit(object.data);
      visit(info.tree);
      for (const parent of info.parents) visit(parent);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) visit(entry.oid);
    } else if (object.type === 'tag') {
      visit(parseTagTarget(object.data));
    }
  };
  for (const root of roots) visit(root);
  return out;
}

// Depth-limited closure used by shallow fetches. Commits at generation
// depth-1 form the boundary; commits in `cut` are included but their
// parents are not traversed (used to model what a shallow client holds).
function closureDepth(
  repo: RepoRec,
  roots: string[],
  depth: number | null,
  cut: Set<string>,
): { objects: Set<string>; boundary: Set<string> } {
  const objects = new Set<string>();
  const boundary = new Set<string>();
  const addTreeClosure = (treeOid: string): void => {
    const visit = (oid: string): void => {
      if (objects.has(oid)) return;
      const object = getObject(repo, oid);
      if (!object) return;
      objects.add(oid);
      if (object.type === 'tree') {
        for (const entry of parseTree(object.data)) visit(entry.oid);
      }
    };
    visit(treeOid);
  };
  const queue: { oid: string; generation: number }[] = [];
  for (const root of roots) {
    const commit = resolveCommit(repo, root);
    if (commit) queue.push({ oid: commit, generation: 0 });
    else if (getObject(repo, root)) objects.add(root);
    // Tag objects themselves are part of the closure.
    let cursor = root;
    while (getObject(repo, cursor)?.type === 'tag') {
      objects.add(cursor);
      cursor = parseTagTarget((getObject(repo, cursor) as GitObject).data);
    }
  }
  const seenCommits = new Set<string>();
  while (queue.length > 0) {
    const { oid, generation } = queue.shift() as { oid: string; generation: number };
    if (seenCommits.has(oid)) continue;
    seenCommits.add(oid);
    const object = getObject(repo, oid);
    if (!object || object.type !== 'commit') continue;
    objects.add(oid);
    const info = parseCommit(object.data);
    addTreeClosure(info.tree);
    const atBoundary = depth !== null && generation >= depth - 1;
    if (atBoundary || cut.has(oid)) {
      if (info.parents.length > 0) boundary.add(oid);
      continue;
    }
    for (const parent of info.parents) queue.push({ oid: parent, generation: generation + 1 });
  }
  return { objects, boundary };
}

// --- three-way tree merge (squash merges & conflict detection) --------------

function tryMergeTrees(
  repo: RepoRec,
  baseTip: string,
  headTip: string,
): { conflict: boolean; treeOid?: string } {
  const mergeBase = findMergeBase(repo, headTip, baseTip);
  const baseMap = mergeBase
    ? flattenTree(repo, commitTreeOid(repo, mergeBase))
    : new Map<string, { oid: string; mode: string }>();
  const oursMap = flattenTree(repo, commitTreeOid(repo, baseTip));
  const theirsMap = flattenTree(repo, commitTreeOid(repo, headTip));
  const merged = new Map(oursMap);
  const paths = new Set([...baseMap.keys(), ...oursMap.keys(), ...theirsMap.keys()]);
  for (const path of paths) {
    const base = baseMap.get(path)?.oid;
    const ours = oursMap.get(path)?.oid;
    const theirs = theirsMap.get(path)?.oid;
    if (ours === theirs) {
      if (ours === undefined) merged.delete(path);
      continue;
    }
    if (base === ours) {
      if (theirs === undefined) merged.delete(path);
      else merged.set(path, theirsMap.get(path) as { oid: string; mode: string });
      continue;
    }
    if (base === theirs) continue;
    return { conflict: true };
  }
  return { conflict: false, treeOid: buildTreeFromFlat(repo, merged) };
}

// Diff two trees path-by-path (used for pull request file lists).
interface FileChange {
  filename: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
  changes: number;
  sha: string;
}

function diffTrees(repo: RepoRec, fromTree: string, toTree: string): FileChange[] {
  const fromMap = fromTree
    ? flattenTree(repo, fromTree)
    : new Map<string, { oid: string; mode: string }>();
  const toMap = toTree
    ? flattenTree(repo, toTree)
    : new Map<string, { oid: string; mode: string }>();
  const changes: FileChange[] = [];
  const paths = new Set([...fromMap.keys(), ...toMap.keys()]);
  for (const path of [...paths].sort()) {
    const from = fromMap.get(path);
    const to = toMap.get(path);
    if (from && !to) {
      changes.push({
        filename: path,
        status: 'removed',
        additions: 0,
        deletions: countLines((getObject(repo, from.oid) as GitObject).data),
        changes: countLines((getObject(repo, from.oid) as GitObject).data),
        sha: from.oid,
      });
    } else if (!from && to) {
      const lines = countLines((getObject(repo, to.oid) as GitObject).data);
      changes.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines, sha: to.oid });
    } else if (from && to && from.oid !== to.oid) {
      const additions = countLines((getObject(repo, to.oid) as GitObject).data);
      const deletions = countLines((getObject(repo, from.oid) as GitObject).data);
      changes.push({
        filename: path,
        status: 'modified',
        additions,
        deletions,
        changes: additions + deletions,
        sha: to.oid,
      });
    }
  }
  return changes;
}

// ---------------------------------------------------------------------------
// HTTP plumbing.
// ---------------------------------------------------------------------------

interface RequestContext {
  store: Store;
  req: IncomingMessage;
  url: URL;
  body: Buffer;
  jsonCache: { parsed: boolean; value: unknown };
}

function sendBuffer(
  res: ServerResponse,
  status: number,
  body: Buffer,
  contentType: string,
  extraHeaders: Record<string, string> = {},
): void {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': body.length,
    ...extraHeaders,
  });
  res.end(body);
}

function sendJson(
  store: Store,
  res: ServerResponse,
  status: number,
  value: unknown,
  extraHeaders: Record<string, string> = {},
): void {
  store.requestSeq += 1;
  sendBuffer(res, status, utf8(JSON.stringify(value)), 'application/json; charset=utf-8', {
    'X-GitHub-Request-Id': `forge-${store.requestSeq}`,
    ...extraHeaders,
  });
}

function sendError(store: Store, res: ServerResponse, status: number, message: string): void {
  sendJson(store, res, status, { message });
}

function requestJson(ctx: RequestContext): { ok: boolean; value: Record<string, unknown> } {
  if (ctx.jsonCache.parsed) {
    return { ok: true, value: ctx.jsonCache.value as Record<string, unknown> };
  }
  const text = ctx.body.toString('utf8').trim();
  if (text === '') {
    ctx.jsonCache = { parsed: true, value: {} };
    return { ok: true, value: {} };
  }
  try {
    const value = JSON.parse(text) as unknown;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return { ok: false, value: {} };
    }
    ctx.jsonCache = { parsed: true, value };
    return { ok: true, value: value as Record<string, unknown> };
  } catch {
    return { ok: false, value: {} };
  }
}

function isAuthed(req: IncomingMessage): boolean {
  const header = req.headers['authorization'];
  if (typeof header !== 'string') return false;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (!match) return false;
  const presented = match[1].trim();
  if (presented === '') return false;
  const expected = process.env.MAKEFUN_SHOP_TOKEN;
  if (expected !== undefined && expected !== '') return presented === expected;
  return true;
}

function originOf(req: IncomingMessage): string {
  const host = req.headers['host'];
  return `http://${typeof host === 'string' && host !== '' ? host : '127.0.0.1'}`;
}

// ---------------------------------------------------------------------------
// REST serializers.
// ---------------------------------------------------------------------------

function userJson(login: string): Record<string, unknown> {
  return {
    login,
    id: login === VIEWER_LOGIN ? VIEWER_ID : 0,
    type: 'User',
    name: login === VIEWER_LOGIN ? VIEWER_NAME : login,
    email: login === VIEWER_LOGIN ? VIEWER_EMAIL : `${login}@example.invalid`,
  };
}

function repoJson(repo: RepoRec): Record<string, unknown> {
  const openIssues = [...repo.issues.values()].filter((issue) => issue.state === 'open').length;
  const openPulls = [...repo.pulls.values()].filter((pull) => pull.state === 'open').length;
  return {
    id: repo.id,
    node_id: `repo-${repo.id}`,
    name: repo.name,
    full_name: repoKey(repo.owner, repo.name),
    owner: userJson(repo.owner),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://forge.invalid/${repo.owner}/${repo.name}`,
    url: `https://forge.invalid/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: new Date((EPOCH_SECONDS + repo.createdSeq) * 1000).toISOString(),
    updated_at: new Date((EPOCH_SECONDS + repo.createdSeq) * 1000).toISOString(),
    has_issues: true,
    has_pull_requests: true,
    open_issues_count: openIssues + openPulls,
    visibility: repo.isPrivate ? 'private' : 'public',
    size: 0,
    stargazers_count: 0,
    forks_count: 0,
  };
}

function labelJson(label: LabelRec): Record<string, unknown> {
  return { name: label.name, color: label.color, default: false };
}

function issueJson(repo: RepoRec, issue: IssueRec): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: `issue-${repo.id}-${issue.number}`,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels
      .map((name) => repo.labels.get(name))
      .filter((label): label is LabelRec => label !== undefined)
      .map(labelJson),
    user: userJson(VIEWER_LOGIN),
    author: userJson(VIEWER_LOGIN),
    comments: issue.comments.length,
    created_at: new Date((EPOCH_SECONDS + issue.createdSeq) * 1000).toISOString(),
    updated_at: new Date((EPOCH_SECONDS + issue.createdSeq) * 1000).toISOString(),
    html_url: `https://forge.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function commentJson(comment: CommentRec): Record<string, unknown> {
  return {
    id: comment.id,
    body: comment.body,
    user: userJson(comment.author),
    author: userJson(comment.author),
    created_at: new Date((EPOCH_SECONDS + comment.createdSeq) * 1000).toISOString(),
    updated_at: new Date((EPOCH_SECONDS + comment.createdSeq) * 1000).toISOString(),
  };
}

function pullJson(repo: RepoRec, pull: PullRec): Record<string, unknown> {
  const headSha = branchTip(repo, pull.headRef) ?? pull.headShaAtCreate;
  const baseSha = branchTip(repo, pull.baseRef) ?? pull.baseShaAtCreate;
  let mergeable: boolean | null = null;
  if (pull.state === 'open' && !pull.merged) {
    const baseTipNow = branchTip(repo, pull.baseRef);
    const headTipNow = branchTip(repo, pull.headRef);
    if (baseTipNow && headTipNow) {
      mergeable = !tryMergeTrees(repo, baseTipNow, headTipNow).conflict;
    }
  }
  return {
    id: pull.id,
    node_id: `pull-${repo.id}-${pull.number}`,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable,
    mergeable_state: mergeable === null ? 'unknown' : mergeable ? 'clean' : 'dirty',
    head: { label: `${repo.owner}:${pull.headRef}`, ref: pull.headRef, sha: headSha },
    base: { label: `${repo.owner}:${pull.baseRef}`, ref: pull.baseRef, sha: baseSha },
    user: userJson(VIEWER_LOGIN),
    author: userJson(VIEWER_LOGIN),
    created_at: new Date((EPOCH_SECONDS + pull.createdSeq) * 1000).toISOString(),
    updated_at: new Date((EPOCH_SECONDS + pull.createdSeq) * 1000).toISOString(),
    html_url: `https://forge.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
  };
}

function parseIdent(ident: string): { name: string; email: string; date: string } {
  const match = /^(.*) <(.*)> (\d+) [+-]\d{4}$/.exec(ident);
  if (!match) return { name: ident, email: '', date: new Date(EPOCH_SECONDS * 1000).toISOString() };
  return {
    name: match[1],
    email: match[2],
    date: new Date(Number(match[3]) * 1000).toISOString(),
  };
}

function commitJson(repo: RepoRec, oid: string): Record<string, unknown> {
  const object = getObject(repo, oid) as GitObject;
  const info = parseCommit(object.data);
  return {
    sha: oid,
    node_id: `commit-${oid}`,
    commit: {
      message: info.message.replace(/\n+$/, ''),
      author: parseIdent(info.author),
      committer: parseIdent(info.committer),
      tree: { sha: info.tree },
    },
    parents: info.parents.map((parent) => ({ sha: parent })),
    html_url: `https://forge.invalid/commit/${oid}`,
  };
}

// Shared pull-request merge execution (REST + GraphQL + MCP all land here).
function executeSquashMerge(
  store: Store,
  repo: RepoRec,
  pull: PullRec,
): { ok: true; sha: string } | { ok: false; conflict: boolean } {
  const baseTip = branchTip(repo, pull.baseRef);
  const headTip = branchTip(repo, pull.headRef);
  if (!baseTip || !headTip) return { ok: false, conflict: false };
  const attempt = tryMergeTrees(repo, baseTip, headTip);
  if (attempt.conflict || attempt.treeOid === undefined) return { ok: false, conflict: true };
  const sha = makeCommit(store, repo, attempt.treeOid, [baseTip], pull.title);
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = tickIso(store);
  pull.mergeCommitSha = sha;
  return { ok: true, sha };
}

function createPullRec(
  store: Store,
  repo: RepoRec,
  title: string,
  body: string,
  headRef: string,
  baseRef: string,
): PullRec {
  const pull: PullRec = {
    id: store.nextPullId++,
    number: repo.nextNumber++,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef,
    baseRef,
    headShaAtCreate: branchTip(repo, headRef) ?? ZERO_OID,
    baseShaAtCreate: branchTip(repo, baseRef) ?? ZERO_OID,
    createdSeq: store.clockSeq + 1,
  };
  tickIso(store);
  repo.pulls.set(pull.number, pull);
  return pull;
}

function createIssueRec(
  store: Store,
  repo: RepoRec,
  title: string,
  body: string,
  labels: string[],
): IssueRec {
  const issue: IssueRec = {
    id: store.nextIssueId++,
    number: repo.nextNumber++,
    title,
    body,
    state: 'open',
    labels: [...labels],
    comments: [],
    createdSeq: store.clockSeq + 1,
  };
  tickIso(store);
  repo.issues.set(issue.number, issue);
  return issue;
}

// ---------------------------------------------------------------------------
// REST v3 handlers. `segments` is the path after /api/v3, already decoded.
// ---------------------------------------------------------------------------

function paginationParams(url: URL): { perPage: number; page: number } {
  const perPageRaw = Number(url.searchParams.get('per_page') ?? '30');
  const pageRaw = Number(url.searchParams.get('page') ?? '1');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.floor(perPageRaw)) : 30;
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1;
  return { perPage, page };
}

function routeRest(ctx: RequestContext, res: ServerResponse, segments: string[]): void {
  const { store, req } = ctx;
  const method = (req.method ?? 'GET').toUpperCase();

  // Body-bearing verbs must carry valid JSON when a body is present.
  let body: Record<string, unknown> = {};
  if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
    const parsed = requestJson(ctx);
    if (!parsed.ok) {
      sendError(store, res, 400, 'Malformed JSON in request body');
      return;
    }
    body = parsed.value;
  }

  if (segments.length === 0) {
    if (method === 'GET') {
      sendJson(store, res, 200, {
        current_user_url: `${originOf(req)}/api/v3/user`,
        repository_url: `${originOf(req)}/api/v3/repos/{owner}/{repo}`,
        emojis_url: `${originOf(req)}/api/v3/emojis`,
      }, { 'X-OAuth-Scopes': 'repo, user, read:org, write:org' });
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (segments[0] === 'meta' && segments.length === 1) {
    if (method === 'GET') {
      sendJson(store, res, 200, {
        installed_version: `forge-${FORGE_VERSION}`,
        git_version: 'forge',
        verifiable_password_authentication: false,
      });
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (segments[0] === 'user' && segments.length === 1) {
    if (method === 'GET') {
      sendJson(store, res, 200, {
        ...userJson(VIEWER_LOGIN),
        name: VIEWER_NAME,
        email: VIEWER_EMAIL,
        bio: '',
        company: '',
        location: '',
        followers: 0,
        following: 0,
        public_repos: [...store.repos.values()].filter((repo) => repo.owner === VIEWER_LOGIN).length,
      });
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (segments[0] === 'user' && segments[1] === 'repos' && segments.length === 2) {
    if (method === 'POST') {
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') {
        sendError(store, res, 422, 'name is required');
        return;
      }
      if (findRepo(store, VIEWER_LOGIN, name)) {
        sendError(store, res, 422, 'Repository already exists');
        return;
      }
      const repo = createRepoRec(
        store,
        VIEWER_LOGIN,
        name,
        typeof body.description === 'string' ? body.description : '',
        body.private === true,
      );
      sendJson(store, res, 201, repoJson(repo));
      return;
    }
    if (method === 'GET') {
      const { perPage, page } = paginationParams(ctx.url);
      const mine = [...store.repos.values()]
        .filter((repo) => repo.owner === VIEWER_LOGIN)
        .sort((a, b) => a.createdSeq - b.createdSeq);
      const totalPages = Math.max(1, Math.ceil(mine.length / perPage));
      const slice = mine.slice((page - 1) * perPage, page * perPage);
      const headers: Record<string, string> = {};
      if (page < totalPages) {
        const base = `${originOf(req)}/api/v3/user/repos`;
        headers['Link'] =
          `<${base}?per_page=${perPage}&page=${page + 1}>; rel="next", ` +
          `<${base}?per_page=${perPage}&page=${totalPages}>; rel="last"`;
      }
      sendJson(store, res, 200, slice.map(repoJson), headers);
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = segments[1];
    const name = segments[2];
    const repo = findRepo(store, owner, name);
    if (!repo) {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    routeRepoScoped(ctx, res, repo, segments.slice(3), body);
    return;
  }

  sendError(store, res, 404, 'Not Found');
}

function routeRepoScoped(
  ctx: RequestContext,
  res: ServerResponse,
  repo: RepoRec,
  rest: string[],
  body: Record<string, unknown>,
): void {
  const { store, req } = ctx;
  const method = (req.method ?? 'GET').toUpperCase();

  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(store, res, 200, repoJson(repo));
      return;
    }
    if (method === 'PATCH') {
      if (typeof body.description === 'string') repo.description = body.description;
      if (typeof body.private === 'boolean') repo.isPrivate = body.private;
      sendJson(store, res, 200, repoJson(repo));
      return;
    }
    if (method === 'DELETE') {
      store.repos.delete(repoKey(repo.owner, repo.name));
      store.requestSeq += 1;
      res.writeHead(204, { 'X-GitHub-Request-Id': `forge-${store.requestSeq}` });
      res.end();
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (rest[0] === 'labels') {
    if (method === 'POST' && rest.length === 1) {
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') {
        sendError(store, res, 422, 'name is required');
        return;
      }
      const existing = repo.labels.get(name);
      if (existing) {
        sendJson(store, res, 201, labelJson(existing));
        return;
      }
      const label: LabelRec = {
        name,
        color: typeof body.color === 'string' ? body.color : 'ededed',
      };
      repo.labels.set(name, label);
      sendJson(store, res, 201, labelJson(label));
      return;
    }
    if (method === 'GET' && rest.length === 1) {
      sendJson(store, res, 200, [...repo.labels.values()].map(labelJson));
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (rest[0] === 'issues') {
    routeIssues(ctx, res, repo, rest.slice(1), body);
    return;
  }

  if (rest[0] === 'pulls') {
    routePulls(ctx, res, repo, rest.slice(1), body);
    return;
  }

  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      const ref = typeof body.ref === 'string' ? body.ref : '';
      const sha = typeof body.sha === 'string' ? body.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha) || !getObject(repo, sha)) {
        sendError(store, res, 422, 'Invalid ref or object');
        return;
      }
      repo.refs.set(ref, sha);
      const object = getObject(repo, sha) as GitObject;
      sendJson(store, res, 201, { ref, node_id: `ref-${ref}`, object: { sha, type: object.type } });
      return;
    }
    if (method === 'GET' && rest.length >= 4 && rest[2] === 'heads') {
      const branch = rest.slice(3).join('/');
      const tip = branchTip(repo, branch);
      if (!tip) {
        sendError(store, res, 404, 'Not Found');
        return;
      }
      sendJson(store, res, 200, {
        ref: `refs/heads/${branch}`,
        node_id: `ref-heads-${branch}`,
        object: { sha: tip, type: 'commit' },
      });
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (rest[0] === 'branches') {
    if (method === 'GET' && rest.length === 1) {
      const branches = [...repo.refs.entries()]
        .filter(([ref]) => ref.startsWith('refs/heads/'))
        .map(([ref, sha]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha }, protected: false }))
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      sendJson(store, res, 200, branches);
      return;
    }
    if (method === 'GET' && rest.length >= 2) {
      const branch = rest.slice(1).join('/');
      const tip = branchTip(repo, branch);
      if (!tip) {
        sendError(store, res, 404, 'Not Found');
        return;
      }
      sendJson(store, res, 200, { name: branch, commit: { sha: tip }, protected: false });
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (rest[0] === 'commits') {
    if (method === 'GET' && rest.length === 1) {
      const shaParam = ctx.url.searchParams.get('sha') ?? repo.defaultBranch;
      const start = branchTip(repo, shaParam) ?? (isOid(shaParam) ? resolveCommit(repo, shaParam) : undefined);
      if (!start) {
        sendError(store, res, 404, 'Not Found');
        return;
      }
      const { perPage } = paginationParams(ctx.url);
      const ordered: string[] = [];
      const seen = new Set<string>();
      const stack = [start];
      while (stack.length > 0 && ordered.length < perPage) {
        const current = stack.pop() as string;
        if (seen.has(current)) continue;
        seen.add(current);
        ordered.push(current);
        const object = getObject(repo, current);
        if (object && object.type === 'commit') {
          const parents = parseCommit(object.data).parents;
          for (let i = parents.length - 1; i >= 0; i--) stack.push(parents[i]);
        }
      }
      sendJson(store, res, 200, ordered.map((oid) => commitJson(repo, oid)));
      return;
    }
    if (method === 'GET' && rest.length === 2 && isOid(rest[1]) && getObject(repo, rest[1])?.type === 'commit') {
      sendJson(store, res, 200, commitJson(repo, rest[1]));
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (rest[0] === 'contents') {
    routeContents(ctx, res, repo, rest.slice(1).join('/'), body);
    return;
  }

  sendError(store, res, 404, 'Not Found');
}

function routeIssues(
  ctx: RequestContext,
  res: ServerResponse,
  repo: RepoRec,
  rest: string[],
  body: Record<string, unknown>,
): void {
  const { store, req } = ctx;
  const method = (req.method ?? 'GET').toUpperCase();

  if (rest.length === 0) {
    if (method === 'POST') {
      const title = typeof body.title === 'string' ? body.title : '';
      if (title === '') {
        sendError(store, res, 422, 'title is required');
        return;
      }
      const rawLabels = Array.isArray(body.labels) ? body.labels : [];
      const labels: string[] = [];
      for (const raw of rawLabels) {
        const labelName = typeof raw === 'string' ? raw : (raw as { name?: unknown })?.name;
        if (typeof labelName !== 'string' || !repo.labels.has(labelName)) {
          sendError(store, res, 422, `Unknown label: ${String(labelName)}`);
          return;
        }
        labels.push(labelName);
      }
      const issue = createIssueRec(
        store,
        repo,
        title,
        typeof body.body === 'string' ? body.body : '',
        labels,
      );
      sendJson(store, res, 201, issueJson(repo, issue));
      return;
    }
    if (method === 'GET') {
      const stateParam = ctx.url.searchParams.get('state') ?? 'open';
      const direction = ctx.url.searchParams.get('direction') ?? 'desc';
      const { perPage, page } = paginationParams(ctx.url);
      let list = [...repo.issues.values()];
      if (stateParam === 'open' || stateParam === 'closed') {
        list = list.filter((issue) => issue.state === stateParam);
      }
      list.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      const slice = list.slice((page - 1) * perPage, page * perPage);
      sendJson(store, res, 200, slice.map((issue) => issueJson(repo, issue)));
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  const number = Number(rest[0]);
  const issue = Number.isInteger(number) ? repo.issues.get(number) : undefined;

  if (rest.length === 1) {
    if (!issue) {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    if (method === 'GET') {
      sendJson(store, res, 200, issueJson(repo, issue));
      return;
    }
    if (method === 'PATCH') {
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (Array.isArray(body.labels)) {
        const labels: string[] = [];
        for (const raw of body.labels) {
          const labelName = typeof raw === 'string' ? raw : (raw as { name?: unknown })?.name;
          if (typeof labelName !== 'string' || !repo.labels.has(labelName)) {
            sendError(store, res, 422, `Unknown label: ${String(labelName)}`);
            return;
          }
          labels.push(labelName);
        }
        issue.labels = labels;
      }
      sendJson(store, res, 200, issueJson(repo, issue));
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (rest.length === 2 && rest[1] === 'comments') {
    if (!issue) {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    if (method === 'POST') {
      const comment: CommentRec = {
        id: store.nextCommentId++,
        body: typeof body.body === 'string' ? body.body : '',
        author: VIEWER_LOGIN,
        createdSeq: store.clockSeq + 1,
      };
      tickIso(store);
      issue.comments.push(comment);
      sendJson(store, res, 201, commentJson(comment));
      return;
    }
    if (method === 'GET') {
      sendJson(store, res, 200, issue.comments.map(commentJson));
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  sendError(store, res, 404, 'Not Found');
}

function stripOwnerPrefix(ref: string): string {
  const colon = ref.indexOf(':');
  return colon === -1 ? ref : ref.slice(colon + 1);
}

function routePulls(
  ctx: RequestContext,
  res: ServerResponse,
  repo: RepoRec,
  rest: string[],
  body: Record<string, unknown>,
): void {
  const { store, req } = ctx;
  const method = (req.method ?? 'GET').toUpperCase();

  if (rest.length === 0) {
    if (method === 'POST') {
      const title = typeof body.title === 'string' ? body.title : '';
      const head = stripOwnerPrefix(typeof body.head === 'string' ? body.head : '');
      const base = stripOwnerPrefix(typeof body.base === 'string' ? body.base : '');
      if (!branchTip(repo, head)) {
        sendError(store, res, 422, `head branch not found: ${head}`);
        return;
      }
      if (!branchTip(repo, base)) {
        sendError(store, res, 422, `base branch not found: ${base}`);
        return;
      }
      const duplicate = [...repo.pulls.values()].find(
        (pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base,
      );
      if (duplicate) {
        sendError(store, res, 422, `A pull request already exists for ${head} into ${base}`);
        return;
      }
      const pull = createPullRec(store, repo, title, typeof body.body === 'string' ? body.body : '', head, base);
      sendJson(store, res, 201, pullJson(repo, pull));
      return;
    }
    if (method === 'GET') {
      const stateParam = ctx.url.searchParams.get('state') ?? 'open';
      let list = [...repo.pulls.values()];
      if (stateParam === 'open' || stateParam === 'closed') {
        list = list.filter((pull) => pull.state === stateParam);
      }
      list.sort((a, b) => a.number - b.number);
      sendJson(store, res, 200, list.map((pull) => pullJson(repo, pull)));
      return;
    }
    sendError(store, res, 404, 'Not Found');
    return;
  }

  const number = Number(rest[0]);
  const pull = Number.isInteger(number) ? repo.pulls.get(number) : undefined;
  if (!pull) {
    sendError(store, res, 404, 'Not Found');
    return;
  }

  if (rest.length === 1 && method === 'GET') {
    sendJson(store, res, 200, pullJson(repo, pull));
    return;
  }

  if (rest.length === 2 && rest[1] === 'files' && method === 'GET') {
    const baseTip = branchTip(repo, pull.baseRef);
    const headTip = branchTip(repo, pull.headRef);
    if (!baseTip || !headTip) {
      sendJson(store, res, 200, []);
      return;
    }
    const mergeBase = findMergeBase(repo, headTip, baseTip);
    const fromTree = mergeBase ? commitTreeOid(repo, mergeBase) : '';
    const changes = diffTrees(repo, fromTree, commitTreeOid(repo, headTip));
    sendJson(store, res, 200, changes.map((change) => ({
      filename: change.filename,
      status: change.status,
      additions: change.additions,
      deletions: change.deletions,
      changes: change.changes,
      sha: change.sha,
    })));
    return;
  }

  if (rest.length === 2 && rest[1] === 'merge' && method === 'PUT') {
    if (pull.merged || pull.state === 'closed') {
      sendError(store, res, 405, 'Pull Request is not mergeable');
      return;
    }
    const result = executeSquashMerge(store, repo, pull);
    if (!result.ok) {
      sendError(store, res, 405, 'Pull Request is not mergeable');
      return;
    }
    sendJson(store, res, 200, {
      sha: result.sha,
      merged: true,
      message: 'Pull Request successfully merged',
    });
    return;
  }

  sendError(store, res, 404, 'Not Found');
}

function routeContents(
  ctx: RequestContext,
  res: ServerResponse,
  repo: RepoRec,
  path: string,
  body: Record<string, unknown>,
): void {
  const { store, req } = ctx;
  const method = (req.method ?? 'GET').toUpperCase();

  if (method === 'GET') {
    const refParam = ctx.url.searchParams.get('ref') ?? repo.defaultBranch;
    const commitOid = branchTip(repo, refParam) ?? (isOid(refParam) ? resolveCommit(repo, refParam) : undefined);
    if (!commitOid) {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    const read = readPath(repo, commitOid, path);
    if (!read) {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    if (read.kind === 'file') {
      const name = path.split('/').pop() ?? path;
      sendJson(store, res, 200, {
        type: 'file',
        encoding: 'base64',
        content: read.data.toString('base64'),
        sha: read.oid,
        size: read.data.length,
        name,
        path,
        html_url: `https://forge.invalid/${repo.owner}/${repo.name}/blob/${refParam}/${path}`,
        download_url: `https://forge.invalid/${repo.owner}/${repo.name}/raw/${refParam}/${path}`,
      });
      return;
    }
    sendJson(store, res, 200, read.entries.map((entry) => ({
      type: entry.type,
      name: entry.name,
      path: entry.path,
      sha: entry.oid,
      size: 0,
    })));
    return;
  }

  if (method === 'PUT') {
    if (path === '') {
      sendError(store, res, 422, 'path is required');
      return;
    }
    const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    const content = Buffer.from(typeof body.content === 'string' ? body.content : '', 'base64');
    const message = typeof body.message === 'string' ? body.message : `Update ${path}`;
    const tip = branchTip(repo, branch);
    let flat = new Map<string, { oid: string; mode: string }>();
    if (tip) flat = flattenTree(repo, commitTreeOid(repo, tip));
    const existing = flat.get(path);
    const shaParam = typeof body.sha === 'string' && body.sha !== '' ? body.sha : undefined;
    if (shaParam !== undefined) {
      if (!existing) {
        sendError(store, res, 422, 'sha supplied but the file does not exist');
        return;
      }
      if (existing.oid !== shaParam) {
        sendError(store, res, 409, 'The supplied sha does not match the current file');
        return;
      }
    }
    const blobOid = putObject(repo, 'blob', content);
    flat.set(path, { oid: blobOid, mode: existing?.mode ?? '100644' });
    const treeOid = buildTreeFromFlat(repo, flat);
    const commitOid = makeCommit(store, repo, treeOid, tip ? [tip] : [], message);
    repo.refs.set(`refs/heads/${branch}`, commitOid);
    const name = path.split('/').pop() ?? path;
    sendJson(store, res, existing ? 200 : 201, {
      content: {
        type: 'file',
        encoding: 'base64',
        sha: blobOid,
        size: content.length,
        name,
        path,
      },
      commit: {
        sha: commitOid,
        message,
        author: { name: VIEWER_NAME, email: VIEWER_EMAIL },
        committer: { name: VIEWER_NAME, email: VIEWER_EMAIL },
      },
    });
    return;
  }

  if (method === 'DELETE') {
    const branch = typeof body.branch === 'string' && body.branch !== '' ? body.branch : repo.defaultBranch;
    const tip = branchTip(repo, branch);
    if (!tip) {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    const flat = flattenTree(repo, commitTreeOid(repo, tip));
    const existing = flat.get(path);
    if (!existing) {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    const shaParam = typeof body.sha === 'string' && body.sha !== '' ? body.sha : undefined;
    if (shaParam !== undefined && shaParam !== existing.oid) {
      sendError(store, res, 409, 'The supplied sha does not match the current file');
      return;
    }
    flat.delete(path);
    const treeOid = buildTreeFromFlat(repo, flat);
    const message = typeof body.message === 'string' ? body.message : `Delete ${path}`;
    const commitOid = makeCommit(store, repo, treeOid, [tip], message);
    repo.refs.set(`refs/heads/${branch}`, commitOid);
    sendJson(store, res, 200, {
      content: null,
      commit: {
        sha: commitOid,
        message,
        author: { name: VIEWER_NAME, email: VIEWER_EMAIL },
        committer: { name: VIEWER_NAME, email: VIEWER_EMAIL },
      },
    });
    return;
  }

  sendError(store, res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// Git smart HTTP.
// ---------------------------------------------------------------------------

const UPLOAD_CAPS = 'side-band-64k ofs-delta thin-pack symref=HEAD:refs/heads/main agent=forge/1.0';
const RECEIVE_CAPS = 'report-status delete-refs side-band-64k ofs-delta agent=forge/1.0';

function sortedRefs(repo: RepoRec): [string, string][] {
  return [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function refAdvertisement(repo: RepoRec, capabilities: string): Buffer {
  const lines: Buffer[] = [];
  const refs = sortedRefs(repo);
  const headTip = repo.refs.get(repo.headRef);
  if (refs.length === 0) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${capabilities}\n`));
  } else {
    let first = true;
    const suffix = () => {
      if (!first) return '';
      first = false;
      return `\0${capabilities}`;
    };
    if (headTip) lines.push(pktLine(`${headTip} HEAD${suffix()}\n`));
    for (const [ref, oid] of refs) {
      lines.push(pktLine(`${oid} ${ref}${suffix()}\n`));
      const object = getObject(repo, oid);
      if (object && object.type === 'tag') {
        const target = peelTag(repo, oid);
        if (target !== oid) lines.push(pktLine(`${target} ${ref}^{}\n`));
      }
    }
  }
  lines.push(PKT_FLUSH);
  return Buffer.concat(lines);
}

function wantsV2(req: IncomingMessage): boolean {
  const header = req.headers['git-protocol'];
  return typeof header === 'string' && header.includes('version=2');
}

function handleInfoRefs(
  store: Store,
  req: IncomingMessage,
  res: ServerResponse,
  repo: RepoRec,
  service: string,
): void {
  if (service === 'git-upload-pack') {
    if (wantsV2(req)) {
      const body = Buffer.concat([
        pktLine('version 2\n'),
        pktLine(`agent=${AGENT_STRING}\n`),
        pktLine('ls-refs=unborn\n'),
        pktLine('fetch=shallow\n'),
        pktLine('object-format=sha1\n'),
        PKT_FLUSH,
      ]);
      sendBuffer(res, 200, body, 'application/x-git-upload-pack-advertisement');
      return;
    }
    const body = Buffer.concat([
      pktLine('# service=git-upload-pack\n'),
      PKT_FLUSH,
      refAdvertisement(repo, UPLOAD_CAPS),
    ]);
    sendBuffer(res, 200, body, 'application/x-git-upload-pack-advertisement');
    return;
  }
  if (service === 'git-receive-pack') {
    const body = Buffer.concat([
      pktLine('# service=git-receive-pack\n'),
      PKT_FLUSH,
      refAdvertisement(repo, RECEIVE_CAPS),
    ]);
    sendBuffer(res, 200, body, 'application/x-git-receive-pack-advertisement');
    return;
  }
  sendError(store, res, 400, 'Unknown service');
}

interface LsRefsArgs {
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  refPrefixes: string[];
}

function lsRefsResponse(repo: RepoRec, args: LsRefsArgs): Buffer {
  const lines: Buffer[] = [];
  const headTip = repo.refs.get(repo.headRef);
  const includeHead =
    args.refPrefixes.length === 0 || args.refPrefixes.some((prefix) => 'HEAD'.startsWith(prefix));
  if (includeHead) {
    if (headTip) {
      const attrs = args.symrefs ? ` symref-target:${repo.headRef}` : '';
      lines.push(pktLine(`${headTip} HEAD${attrs}\n`));
    } else if (args.unborn) {
      const attrs = args.symrefs ? ` symref-target:${repo.headRef}` : '';
      lines.push(pktLine(`unborn HEAD${attrs}\n`));
    }
  }
  for (const [ref, oid] of sortedRefs(repo)) {
    if (args.refPrefixes.length > 0 && !args.refPrefixes.some((prefix) => ref.startsWith(prefix))) {
      continue;
    }
    let attrs = '';
    const object = getObject(repo, oid);
    if (args.peel && object && object.type === 'tag') {
      attrs += ` peeled:${peelTag(repo, oid)}`;
    }
    lines.push(pktLine(`${oid} ${ref}${attrs}\n`));
  }
  lines.push(PKT_FLUSH);
  return Buffer.concat(lines);
}

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
  deepen: number | null;
}

function planFetch(repo: RepoRec, request: FetchRequest): { pack: Buffer; shallowLines: string[] } {
  const wants = request.wants.filter((oid) => getObject(repo, oid) !== undefined);
  const effectiveDepth = request.deepen ?? request.depth;
  let packOids: string[] = [];
  const shallowLines: string[] = [];
  if (effectiveDepth !== null) {
    const send = closureDepth(repo, wants, effectiveDepth, new Set());
    let held = new Set<string>();
    if (request.haves.length > 0) {
      held = closureDepth(repo, request.haves, null, new Set(request.shallow)).objects;
    }
    packOids = [...send.objects].filter((oid) => !held.has(oid));
    for (const boundary of send.boundary) shallowLines.push(`shallow ${boundary}`);
    for (const previous of request.shallow) {
      if (send.objects.has(previous) && !send.boundary.has(previous)) {
        shallowLines.push(`unshallow ${previous}`);
      }
    }
  } else {
    const send = closureFull(repo, wants);
    const held = closureFull(repo, request.haves);
    packOids = [...send].filter((oid) => !held.has(oid));
  }
  const objects = packOids
    .map((oid) => getObject(repo, oid))
    .filter((object): object is GitObject => object !== undefined);
  return { pack: buildPack(objects), shallowLines };
}

function handleUploadPack(
  store: Store,
  req: IncomingMessage,
  res: ServerResponse,
  repo: RepoRec,
  body: Buffer,
): void {
  let parsed: { items: PktItem[]; rest: Buffer };
  try {
    parsed = parsePktStream(body);
  } catch {
    sendBuffer(res, 400, utf8('invalid pkt-line stream\n'), 'text/plain; charset=utf-8');
    return;
  }
  const sections = pktSections(parsed.items);

  if (wantsV2(req)) {
    const headerLines = (sections[0] ?? []).map((line) => line.toString('utf8').replace(/\n$/, ''));
    const command = headerLines.find((line) => line.startsWith('command='));
    if (command === 'command=ls-refs') {
      const args: LsRefsArgs = { peel: false, symrefs: false, unborn: false, refPrefixes: [] };
      for (const raw of sections[1] ?? []) {
        const line = raw.toString('utf8').replace(/\n$/, '');
        if (line === 'peel') args.peel = true;
        else if (line === 'symrefs') args.symrefs = true;
        else if (line === 'unborn') args.unborn = true;
        else if (line.startsWith('ref-prefix ')) args.refPrefixes.push(line.slice('ref-prefix '.length));
      }
      sendBuffer(res, 200, lsRefsResponse(repo, args), 'application/x-git-upload-pack-result');
      return;
    }
    if (command === 'command=fetch') {
      const request: FetchRequest = { wants: [], haves: [], shallow: [], depth: null, deepen: null };
      for (const raw of sections[1] ?? []) {
        const line = raw.toString('utf8').replace(/\n$/, '');
        if (line.startsWith('want ')) request.wants.push(line.slice(5).trim());
        else if (line.startsWith('have ')) request.haves.push(line.slice(5).trim());
        else if (line.startsWith('shallow ')) request.shallow.push(line.slice(8).trim());
        else if (line.startsWith('deepen ')) request.deepen = Number(line.slice(7).trim());
        else if (line.startsWith('deepen-since ')) request.deepen = null;
      }
      const { pack, shallowLines } = planFetch(repo, request);
      const parts: Buffer[] = [];
      if (request.haves.length > 0 || request.depth !== null || request.deepen !== null) {
        parts.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_DELIM);
      }
      if (shallowLines.length > 0) {
        parts.push(pktLine('shallow-info\n'));
        for (const line of shallowLines) parts.push(pktLine(`${line}\n`));
        parts.push(PKT_DELIM);
      }
      parts.push(pktLine('packfile\n'));
      parts.push(...sidebandPackets(pack, 1));
      parts.push(PKT_FLUSH);
      sendBuffer(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
      return;
    }
    sendBuffer(res, 400, utf8('unknown command\n'), 'text/plain; charset=utf-8');
    return;
  }

  // Protocol v0 fetch: wants in section 0, haves + done in section 1.
  const request: FetchRequest = { wants: [], haves: [], shallow: [], depth: null, deepen: null };
  for (const raw of sections[0] ?? []) {
    const line = raw.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) request.wants.push(line.slice(5).trim().split(' ')[0]);
    else if (line.startsWith('deepen ')) request.depth = Number(line.slice(7).trim());
    else if (line.startsWith('shallow ')) request.shallow.push(line.slice(8).trim());
  }
  for (const raw of sections[1] ?? []) {
    const line = raw.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('have ')) request.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) request.shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) request.depth = Number(line.slice(7).trim());
  }
  const { pack, shallowLines } = planFetch(repo, request);
  const parts: Buffer[] = [];
  for (const line of shallowLines) parts.push(pktLine(`${line}\n`));
  parts.push(pktLine('NAK\n'));
  parts.push(...sidebandPackets(pack, 1));
  parts.push(PKT_FLUSH);
  sendBuffer(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}

// Split a receive-pack body into pkt-line commands and the raw pack tail.
function splitPktPrefix(buf: Buffer): { lines: Buffer[]; rest: Buffer } {
  const lines: Buffer[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const hex = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('invalid pkt-line header');
    const length = parseInt(hex, 16);
    if (length === 0) return { lines, rest: buf.subarray(offset + 4) };
    if (length < 4 || offset + length > buf.length) throw new Error('truncated pkt-line');
    lines.push(Buffer.from(buf.subarray(offset + 4, offset + length)));
    offset += length;
  }
  return { lines, rest: buf.subarray(offset) };
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(
  store: Store,
  req: IncomingMessage,
  res: ServerResponse,
  repo: RepoRec,
  body: Buffer,
): void {
  let lines: Buffer[];
  let packBytes: Buffer;
  try {
    const split = splitPktPrefix(body);
    lines = split.lines;
    packBytes = split.rest;
  } catch {
    sendBuffer(res, 400, utf8('invalid pkt-line stream\n'), 'text/plain; charset=utf-8');
    return;
  }
  const commands: PushCommand[] = [];
  const capabilities = new Set<string>();
  lines.forEach((raw, index) => {
    let text = raw.toString('utf8').replace(/\n$/, '');
    if (index === 0) {
      const nul = text.indexOf('\0');
      if (nul !== -1) {
        for (const cap of text.slice(nul + 1).split(' ')) if (cap) capabilities.add(cap);
        text = text.slice(0, nul);
      }
    }
    const fields = text.split(' ');
    if (fields.length >= 3) {
      commands.push({ oldOid: fields[0], newOid: fields[1], ref: fields[2] });
    }
  });

  let unpackError: string | null = null;
  if (packBytes.length > 0) {
    try {
      const entries = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const entry of entries) putObject(repo, entry.type, entry.data);
    } catch (error) {
      unpackError = error instanceof Error ? error.message : 'unpack failed';
    }
  }

  const results: { ref: string; ok: boolean; reason?: string }[] = [];
  for (const command of commands) {
    const fail = (reason: string): void => {
      results.push({ ref: command.ref, ok: false, reason });
    };
    if (unpackError !== null) {
      fail('unpack failed');
      continue;
    }
    const current = repo.refs.get(command.ref) ?? ZERO_OID;
    if (command.oldOid !== current) {
      fail('stale info');
      continue;
    }
    if (command.newOid === ZERO_OID) {
      if (command.ref === repo.headRef) {
        fail('cannot delete the current branch');
        continue;
      }
      repo.refs.delete(command.ref);
      results.push({ ref: command.ref, ok: true });
      continue;
    }
    const newObject = getObject(repo, command.newOid);
    if (!newObject) {
      fail('invalid object');
      continue;
    }
    if (command.ref.startsWith('refs/heads/') && command.oldOid !== ZERO_OID) {
      const oldCommit = resolveCommit(repo, command.oldOid);
      const newCommit = resolveCommit(repo, command.newOid);
      if (oldCommit && newCommit && !isAncestor(repo, oldCommit, newCommit)) {
        fail('non-fast-forward');
        continue;
      }
    }
    repo.refs.set(command.ref, command.newOid);
    results.push({ ref: command.ref, ok: true });
  }

  const reportLines: string[] = [unpackError === null ? 'unpack ok' : `unpack ${unpackError}`];
  for (const result of results) {
    reportLines.push(result.ok ? `ok ${result.ref}` : `ng ${result.ref} ${result.reason ?? 'failed'}`);
  }
  const reportStream = Buffer.concat([
    ...reportLines.map((line) => pktLine(`${line}\n`)),
    PKT_FLUSH,
  ]);
  let responseBody: Buffer;
  if (capabilities.has('side-band-64k')) {
    responseBody = Buffer.concat([...sidebandPackets(reportStream, 1), PKT_FLUSH]);
  } else {
    responseBody = reportStream;
  }
  sendBuffer(res, 200, responseBody, 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------------------
// GraphQL: a small parser + executor covering the document shapes the API
// promises (viewer/repository/node/__type, issue & pull connections, and
// the create/close/merge/comment mutations).
// ---------------------------------------------------------------------------

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'string'; value: string }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: { name: string; value: GqlValue }[] };

interface GqlFieldNode {
  kind: 'field';
  alias?: string;
  name: string;
  args: { name: string; value: GqlValue }[];
  selection?: GqlSelection[];
}

type GqlSelection =
  | GqlFieldNode
  | { kind: 'fragment'; typeCondition?: string; selection: GqlSelection[] }
  | { kind: 'spread'; name: string };

interface GqlOperation {
  operation: 'query' | 'mutation';
  name?: string;
  variableDefaults: Map<string, GqlValue>;
  selection: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { typeCondition?: string; selection: GqlSelection[] }>;
}

interface GqlToken {
  kind: 'name' | 'int' | 'float' | 'string' | 'punct' | 'spread' | 'eof';
  value: string;
}

function gqlTokenize(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',' || ch === '﻿') {
      i++;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i++;
      continue;
    }
    if (source.startsWith('...', i)) {
      tokens.push({ kind: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:=@$!|&'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i++;
      continue;
    }
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        if (end === -1) throw new Error('unterminated block string');
        tokens.push({ kind: 'string', value: source.slice(i + 3, end) });
        i = end + 3;
        continue;
      }
      let j = i + 1;
      let raw = '"';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\') {
          raw += source.slice(j, j + 2);
          j += 2;
        } else {
          raw += source[j];
          j++;
        }
      }
      if (j >= source.length) throw new Error('unterminated string');
      raw += '"';
      tokens.push({ kind: 'string', value: JSON.parse(raw) as string });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      const match = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(source.slice(i));
      if (!match) throw new Error('invalid number');
      const text = match[0];
      const isFloat = text.includes('.') || text.includes('e') || text.includes('E');
      tokens.push({ kind: isFloat ? 'float' : 'int', value: text });
      i += text.length;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      const match = /^[_0-9A-Za-z]+/.exec(source.slice(i));
      const text = (match as RegExpExecArray)[0];
      tokens.push({ kind: 'name', value: text });
      i += text.length;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)}`);
  }
  tokens.push({ kind: 'eof', value: '' });
  return tokens;
}

class GqlParser {
  private tokens: GqlToken[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = gqlTokenize(source);
  }

  private peek(): GqlToken {
    return this.tokens[this.pos];
  }

  private next(): GqlToken {
    return this.tokens[this.pos++];
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) {
      throw new Error(`expected '${value}' but found '${token.value}'`);
    }
  }

  private skipPunct(value: string): boolean {
    const token = this.peek();
    if (token.kind === 'punct' && token.value === value) {
      this.pos++;
      return true;
    }
    return false;
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, { typeCondition?: string; selection: GqlSelection[] }>();
    while (this.peek().kind !== 'eof') {
      const token = this.peek();
      if (token.kind === 'punct' && token.value === '{') {
        operations.push({
          operation: 'query',
          variableDefaults: new Map(),
          selection: this.parseSelectionSet(),
        });
        continue;
      }
      if (token.kind === 'name' && (token.value === 'query' || token.value === 'mutation')) {
        this.next();
        const operation = token.value as 'query' | 'mutation';
        let name: string | undefined;
        if (this.peek().kind === 'name') name = this.next().value;
        const variableDefaults = new Map<string, GqlValue>();
        if (this.peek().kind === 'punct' && this.peek().value === '(') {
          this.parseVariableDefinitions(variableDefaults);
        }
        this.skipDirectives();
        operations.push({ operation, name, variableDefaults, selection: this.parseSelectionSet() });
        continue;
      }
      if (token.kind === 'name' && token.value === 'fragment') {
        this.next();
        const fragName = this.next().value;
        const onToken = this.next();
        if (onToken.value !== 'on') throw new Error('expected on in fragment definition');
        const typeCondition = this.next().value;
        this.skipDirectives();
        fragments.set(fragName, { typeCondition, selection: this.parseSelectionSet() });
        continue;
      }
      throw new Error(`unexpected token '${token.value}' in document`);
    }
    return { operations, fragments };
  }

  private parseVariableDefinitions(defaults: Map<string, GqlValue>): void {
    this.expectPunct('(');
    while (!this.skipPunct(')')) {
      this.expectPunct('$');
      const nameToken = this.next();
      if (nameToken.kind !== 'name') throw new Error('expected variable name');
      this.expectPunct(':');
      this.parseType();
      if (this.skipPunct('=')) {
        defaults.set(nameToken.value, this.parseValue());
      }
      this.skipDirectives();
    }
  }

  private parseType(): void {
    if (this.skipPunct('[')) {
      this.parseType();
      this.expectPunct(']');
    } else {
      const token = this.next();
      if (token.kind !== 'name') throw new Error('expected type name');
    }
    this.skipPunct('!');
  }

  private skipDirectives(): void {
    while (this.peek().kind === 'punct' && this.peek().value === '@') {
      this.next();
      this.next(); // directive name
      if (this.peek().kind === 'punct' && this.peek().value === '(') {
        this.parseArguments();
      }
    }
  }

  private parseArguments(): { name: string; value: GqlValue }[] {
    const args: { name: string; value: GqlValue }[] = [];
    this.expectPunct('(');
    while (!this.skipPunct(')')) {
      const nameToken = this.next();
      if (nameToken.kind !== 'name') throw new Error('expected argument name');
      this.expectPunct(':');
      args.push({ name: nameToken.value, value: this.parseValue() });
    }
    return args;
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token.kind === 'punct' && token.value === '$') {
      const nameToken = this.next();
      return { kind: 'variable', name: nameToken.value };
    }
    if (token.kind === 'int') return { kind: 'int', value: parseInt(token.value, 10) };
    if (token.kind === 'float') return { kind: 'float', value: parseFloat(token.value) };
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'punct' && token.value === '[') {
      const items: GqlValue[] = [];
      while (!this.skipPunct(']')) items.push(this.parseValue());
      return { kind: 'list', items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields: { name: string; value: GqlValue }[] = [];
      while (!this.skipPunct('}')) {
        const nameToken = this.next();
        if (nameToken.kind !== 'name') throw new Error('expected object field name');
        this.expectPunct(':');
        fields.push({ name: nameToken.value, value: this.parseValue() });
      }
      return { kind: 'object', fields };
    }
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    throw new Error(`unexpected value token '${token.value}'`);
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!this.skipPunct('}')) {
      const token = this.peek();
      if (token.kind === 'spread') {
        this.next();
        const after = this.peek();
        if (after.kind === 'name' && after.value === 'on') {
          this.next();
          const typeCondition = this.next().value;
          this.skipDirectives();
          selections.push({ kind: 'fragment', typeCondition, selection: this.parseSelectionSet() });
        } else if (after.kind === 'name') {
          this.next();
          this.skipDirectives();
          selections.push({ kind: 'spread', name: after.value });
        } else {
          this.skipDirectives();
          selections.push({ kind: 'fragment', selection: this.parseSelectionSet() });
        }
        continue;
      }
      if (token.kind === 'name') {
        this.next();
        let alias: string | undefined;
        let name = token.value;
        if (this.skipPunct(':')) {
          alias = name;
          name = this.next().value;
        }
        let args: { name: string; value: GqlValue }[] = [];
        if (this.peek().kind === 'punct' && this.peek().value === '(') {
          args = this.parseArguments();
        }
        this.skipDirectives();
        let selection: GqlSelection[] | undefined;
        if (this.peek().kind === 'punct' && this.peek().value === '{') {
          selection = this.parseSelectionSet();
        }
        selections.push({ kind: 'field', alias, name, args, selection });
        continue;
      }
      throw new Error(`unexpected token '${token.value}' in selection set`);
    }
    return selections;
  }
}

// --- global ids ---------------------------------------------------------------

function encodeGid(kind: string, key: string): string {
  return utf8(`fg1:${kind}:${key}`).toString('base64');
}

function decodeGid(id: string): { kind: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    if (!text.startsWith('fg1:')) return null;
    const rest = text.slice(4);
    const colon = rest.indexOf(':');
    if (colon === -1) return null;
    return { kind: rest.slice(0, colon), key: rest.slice(colon + 1) };
  } catch {
    return null;
  }
}

// --- typed source objects -----------------------------------------------------

type GqlObj = { __typename: string } & Record<string, unknown>;

function userObj(login: string): GqlObj {
  return { __typename: 'User', login };
}

function repoObj(repo: RepoRec): GqlObj {
  return { __typename: 'Repository', repo };
}

function issueObj(repo: RepoRec, issue: IssueRec): GqlObj {
  return { __typename: 'Issue', repo, issue };
}

function pullObj(repo: RepoRec, pull: PullRec): GqlObj {
  return { __typename: 'PullRequest', repo, pull };
}

function encodeCursor(offset: number): string {
  return utf8(`idx:${offset}`).toString('base64');
}

function decodeCursor(cursor: unknown): number {
  if (typeof cursor !== 'string') return 0;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^idx:(\d+)$/.exec(text);
    return match ? Number(match[1]) : 0;
  } catch {
    return 0;
  }
}

function connectionObj(
  typeName: string,
  allNodes: GqlObj[],
  args: Record<string, unknown>,
): GqlObj {
  const first = typeof args.first === 'number' ? Math.max(0, Math.floor(args.first)) : allNodes.length;
  const start = decodeCursor(args.after);
  const nodes = allNodes.slice(start, start + first);
  const hasNextPage = start + nodes.length < allNodes.length;
  return {
    __typename: typeName,
    nodes,
    pageInfo: {
      __typename: 'PageInfo',
      hasNextPage,
      hasPreviousPage: start > 0,
      startCursor: encodeCursor(start),
      endCursor: encodeCursor(start + nodes.length),
    },
    totalCount: allNodes.length,
  };
}

// --- __type support -----------------------------------------------------------

const TYPE_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', 'search', 'rateLimit'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  User: ['login', 'id', 'name', 'email', 'avatarUrl', 'url', 'isViewer'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'description', 'isPrivate', 'private',
    'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'hasPullRequestsEnabled',
    'issue', 'issues', 'pullRequests', 'pullRequest', 'createdAt', 'updatedAt', 'url',
  ],
  Issue: [
    'id', 'number', 'title', 'state', 'body', 'author', 'labels', 'comments', 'repository',
    'createdAt', 'updatedAt', 'closed', 'url',
  ],
  PullRequest: [
    'id', 'number', 'title', 'body', 'state', 'merged', 'mergedAt', 'mergeCommitSha', 'mergeable',
    'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'author', 'createdAt', 'updatedAt',
    'closed', 'url', 'changedFiles', 'additions', 'deletions',
  ],
  Ref: ['name', 'prefix', 'target'],
  Commit: ['oid', 'message', 'committedDate'],
  Label: ['id', 'name', 'color'],
  Comment: ['id', 'body', 'author', 'createdAt', 'updatedAt'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  IssueConnection: ['nodes', 'pageInfo', 'totalCount', 'edges'],
  PullRequestConnection: ['nodes', 'pageInfo', 'totalCount', 'edges'],
  CommentConnection: ['nodes', 'pageInfo', 'totalCount', 'edges'],
  LabelConnection: ['nodes', 'pageInfo', 'totalCount', 'edges'],
  PullRequestFileConnection: ['nodes', 'pageInfo', 'totalCount', 'edges'],
  PullRequestFile: ['path', 'additions', 'deletions'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId'],
  CommentEdge: ['node', 'cursor'],
};

const ENUM_TYPES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
};

function typeDescriptor(name: string): GqlObj | null {
  if (ENUM_TYPES[name]) {
    return {
      __typename: '__Type',
      name,
      kind: 'ENUM',
      fields: null,
      enumValues: ENUM_TYPES[name].map((value) => ({ __typename: '__EnumValue', name: value })),
    };
  }
  if (TYPE_FIELDS[name]) {
    return {
      __typename: '__Type',
      name,
      kind: 'OBJECT',
      fields: TYPE_FIELDS[name].map((field) => ({ __typename: '__Field', name: field })),
      enumValues: null,
    };
  }
  if (name === '__Type' || name === '__Field' || name === '__EnumValue' || name === '__Schema') {
    return { __typename: '__Type', name, kind: 'OBJECT', fields: [], enumValues: null };
  }
  return null;
}

// --- field resolution -----------------------------------------------------------

const UNKNOWN_FIELD = Symbol('unknown-field');

interface GqlExecContext {
  store: Store;
  variables: Record<string, unknown>;
  fragments: Map<string, { typeCondition?: string; selection: GqlSelection[] }>;
  errors: { message: string }[];
}

function evalGqlValue(value: GqlValue, ctx: GqlExecContext): unknown {
  switch (value.kind) {
    case 'variable':
      return ctx.variables[value.name];
    case 'int':
    case 'float':
    case 'string':
    case 'boolean':
    case 'enum':
      return value.value;
    case 'null':
      return null;
    case 'list':
      return value.items.map((item) => evalGqlValue(item, ctx));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = evalGqlValue(field.value, ctx);
      return out;
    }
  }
}

function evalArgs(
  args: { name: string; value: GqlValue }[],
  ctx: GqlExecContext,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const arg of args) out[arg.name] = evalGqlValue(arg.value, ctx);
  return out;
}

function repoByGid(store: Store, gid: string): RepoRec | null {
  const decoded = decodeGid(gid);
  if (!decoded || decoded.kind !== 'Repository') return null;
  const id = Number(decoded.key);
  for (const repo of store.repos.values()) if (repo.id === id) return repo;
  return null;
}

function issueByGid(store: Store, gid: string): { repo: RepoRec; issue: IssueRec } | null {
  const decoded = decodeGid(gid);
  if (!decoded || decoded.kind !== 'Issue') return null;
  const [repoIdRaw, numberRaw] = decoded.key.split(':');
  for (const repo of store.repos.values()) {
    if (repo.id === Number(repoIdRaw)) {
      const issue = repo.issues.get(Number(numberRaw));
      return issue ? { repo, issue } : null;
    }
  }
  return null;
}

function pullByGid(store: Store, gid: string): { repo: RepoRec; pull: PullRec } | null {
  const decoded = decodeGid(gid);
  if (!decoded || decoded.kind !== 'PullRequest') return null;
  const [repoIdRaw, numberRaw] = decoded.key.split(':');
  for (const repo of store.repos.values()) {
    if (repo.id === Number(repoIdRaw)) {
      const pull = repo.pulls.get(Number(numberRaw));
      return pull ? { repo, pull } : null;
    }
  }
  return null;
}

function nodeByGid(store: Store, gid: string): GqlObj | null {
  const decoded = decodeGid(gid);
  if (!decoded) return null;
  if (decoded.kind === 'Repository') {
    const repo = repoByGid(store, gid);
    return repo ? repoObj(repo) : null;
  }
  if (decoded.kind === 'Issue') {
    const found = issueByGid(store, gid);
    return found ? issueObj(found.repo, found.issue) : null;
  }
  if (decoded.kind === 'PullRequest') {
    const found = pullByGid(store, gid);
    return found ? pullObj(found.repo, found.pull) : null;
  }
  if (decoded.kind === 'User') return userObj(decoded.key);
  return null;
}

function resolveField(
  ctx: GqlExecContext,
  typeName: string,
  source: GqlObj,
  field: string,
  args: Record<string, unknown>,
): unknown {
  const store = ctx.store;

  if (typeName === 'Query') {
    if (field === 'viewer') return userObj(VIEWER_LOGIN);
    if (field === 'repository') {
      const repo = findRepo(store, String(args.owner ?? ''), String(args.name ?? ''));
      return repo ? repoObj(repo) : null;
    }
    if (field === 'node') return typeof args.id === 'string' ? nodeByGid(store, args.id) : null;
    if (field === '__type') return typeDescriptor(String(args.name ?? ''));
    if (field === '__schema') {
      return {
        __typename: '__Schema',
        queryType: typeDescriptor('Query'),
        mutationType: typeDescriptor('Mutation'),
      };
    }
    if (field === 'rateLimit') {
      return { __typename: 'RateLimit', limit: 5000, cost: 1, remaining: 4999, used: 1, resetAt: tickIso(store) };
    }
    return UNKNOWN_FIELD;
  }

  if (typeName === 'Mutation') {
    const input = (args.input ?? {}) as Record<string, unknown>;
    if (field === 'createIssue') {
      const repo = typeof input.repositoryId === 'string' ? repoByGid(store, input.repositoryId) : null;
      if (!repo) throw new Error('repository not found');
      const issue = createIssueRec(
        store,
        repo,
        String(input.title ?? ''),
        String(input.body ?? ''),
        [],
      );
      return { __typename: 'CreateIssuePayload', issue: issueObj(repo, issue) };
    }
    if (field === 'closeIssue') {
      const found = typeof input.issueId === 'string' ? issueByGid(store, input.issueId) : null;
      if (!found) throw new Error('issue not found');
      found.issue.state = 'closed';
      return { __typename: 'CloseIssuePayload', issue: issueObj(found.repo, found.issue) };
    }
    if (field === 'createPullRequest') {
      const repo = typeof input.repositoryId === 'string' ? repoByGid(store, input.repositoryId) : null;
      if (!repo) throw new Error('repository not found');
      const head = String(input.headRefName ?? '');
      const base = String(input.baseRefName ?? '');
      if (!branchTip(repo, head)) throw new Error(`head branch not found: ${head}`);
      if (!branchTip(repo, base)) throw new Error(`base branch not found: ${base}`);
      const pull = createPullRec(store, repo, String(input.title ?? ''), String(input.body ?? ''), head, base);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pullObj(repo, pull) };
    }
    if (field === 'mergePullRequest') {
      const found = typeof input.pullRequestId === 'string' ? pullByGid(store, input.pullRequestId) : null;
      if (!found) throw new Error('pull request not found');
      if (found.pull.merged) throw new Error('pull request already merged');
      const result = executeSquashMerge(store, found.repo, found.pull);
      if (!result.ok) throw new Error('Pull Request is not mergeable');
      return { __typename: 'MergePullRequestPayload', pullRequest: pullObj(found.repo, found.pull) };
    }
    if (field === 'addComment') {
      const found = typeof input.subjectId === 'string' ? issueByGid(store, input.subjectId) : null;
      if (!found) throw new Error('subject not found');
      const comment: CommentRec = {
        id: store.nextCommentId++,
        body: String(input.body ?? ''),
        author: VIEWER_LOGIN,
        createdSeq: store.clockSeq + 1,
      };
      tickIso(store);
      found.issue.comments.push(comment);
      const node: GqlObj = {
        __typename: 'Comment',
        repo: found.repo,
        issue: found.issue,
        comment,
      };
      return {
        __typename: 'AddCommentPayload',
        commentEdge: { __typename: 'CommentEdge', node, cursor: encodeCursor(found.issue.comments.length) },
        subject: node,
      };
    }
    return UNKNOWN_FIELD;
  }

  if (typeName === 'User') {
    const login = String(source.login ?? '');
    if (field === 'login') return login;
    if (field === 'id') return encodeGid('User', login);
    if (field === 'name') return login === VIEWER_LOGIN ? VIEWER_NAME : login;
    if (field === 'email') return login === VIEWER_LOGIN ? VIEWER_EMAIL : `${login}@example.invalid`;
    if (field === 'isViewer') return login === VIEWER_LOGIN;
    if (field === 'url' || field === 'avatarUrl') return `https://forge.invalid/${login}`;
    return UNKNOWN_FIELD;
  }

  if (typeName === 'Repository') {
    const repo = source.repo as RepoRec;
    switch (field) {
      case 'id': return encodeGid('Repository', String(repo.id));
      case 'databaseId': return repo.id;
      case 'name': return repo.name;
      case 'nameWithOwner': return repoKey(repo.owner, repo.name);
      case 'owner': return userObj(repo.owner);
      case 'description': return repo.description;
      case 'isPrivate': return repo.isPrivate;
      case 'private': return repo.isPrivate;
      case 'defaultBranchRef': return { __typename: 'Ref', repo, name: repo.defaultBranch };
      case 'viewerPermission': return 'ADMIN';
      case 'hasIssuesEnabled': return true;
      case 'hasPullRequestsEnabled': return true;
      case 'createdAt': return new Date((EPOCH_SECONDS + repo.createdSeq) * 1000).toISOString();
      case 'updatedAt': return new Date((EPOCH_SECONDS + repo.createdSeq) * 1000).toISOString();
      case 'url': return `https://forge.invalid/${repo.owner}/${repo.name}`;
      case 'issue': {
        const issue = repo.issues.get(Number(args.number));
        return issue ? issueObj(repo, issue) : null;
      }
      case 'issues': {
        let list = [...repo.issues.values()];
        const states = Array.isArray(args.states) ? (args.states as string[]) : null;
        if (states && states.length > 0) {
          list = list.filter((issue) => states.includes(issue.state.toUpperCase()));
        }
        const orderBy = (args.orderBy ?? null) as { field?: string; direction?: string } | null;
        if (orderBy && orderBy.field === 'CREATED_AT') {
          const dir = orderBy.direction === 'DESC' ? -1 : 1;
          list.sort((a, b) => dir * (a.createdSeq - b.createdSeq) || dir * (a.number - b.number));
        } else {
          list.sort((a, b) => a.number - b.number);
        }
        return connectionObj('IssueConnection', list.map((issue) => issueObj(repo, issue)), args);
      }
      case 'pullRequest': {
        const pull = repo.pulls.get(Number(args.number));
        return pull ? pullObj(repo, pull) : null;
      }
      case 'pullRequests': {
        let list = [...repo.pulls.values()];
        const states = Array.isArray(args.states) ? (args.states as string[]) : null;
        if (states && states.length > 0) {
          list = list.filter((pull) => {
            const gqlState = pull.merged ? 'MERGED' : pull.state.toUpperCase();
            return states.includes(gqlState);
          });
        }
        list.sort((a, b) => a.number - b.number);
        return connectionObj('PullRequestConnection', list.map((pull) => pullObj(repo, pull)), args);
      }
    }
    return UNKNOWN_FIELD;
  }

  if (typeName === 'Issue') {
    const repo = source.repo as RepoRec;
    const issue = source.issue as IssueRec;
    switch (field) {
      case 'id': return encodeGid('Issue', `${repo.id}:${issue.number}`);
      case 'number': return issue.number;
      case 'title': return issue.title;
      case 'body': return issue.body;
      case 'state': return issue.state.toUpperCase();
      case 'closed': return issue.state === 'closed';
      case 'author': return userObj(VIEWER_LOGIN);
      case 'repository': return repoObj(repo);
      case 'createdAt': return new Date((EPOCH_SECONDS + issue.createdSeq) * 1000).toISOString();
      case 'updatedAt': return new Date((EPOCH_SECONDS + issue.createdSeq) * 1000).toISOString();
      case 'url': return `https://forge.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`;
      case 'labels': {
        const nodes = issue.labels
          .map((name) => repo.labels.get(name))
          .filter((label): label is LabelRec => label !== undefined)
          .map((label): GqlObj => ({ __typename: 'Label', repo, label }));
        return connectionObj('LabelConnection', nodes, args);
      }
      case 'comments': {
        const nodes = issue.comments.map(
          (comment): GqlObj => ({ __typename: 'Comment', repo, issue, comment }),
        );
        return connectionObj('CommentConnection', nodes, args);
      }
    }
    return UNKNOWN_FIELD;
  }

  if (typeName === 'PullRequest') {
    const repo = source.repo as RepoRec;
    const pull = source.pull as PullRec;
    switch (field) {
      case 'id': return encodeGid('PullRequest', `${repo.id}:${pull.number}`);
      case 'number': return pull.number;
      case 'title': return pull.title;
      case 'body': return pull.body;
      case 'state': return pull.merged ? 'MERGED' : pull.state.toUpperCase();
      case 'merged': return pull.merged;
      case 'mergedAt': return pull.mergedAt;
      case 'mergeCommitSha': return pull.mergeCommitSha;
      case 'closed': return pull.state === 'closed';
      case 'headRefName': return pull.headRef;
      case 'baseRefName': return pull.baseRef;
      case 'author': return userObj(VIEWER_LOGIN);
      case 'createdAt': return new Date((EPOCH_SECONDS + pull.createdSeq) * 1000).toISOString();
      case 'updatedAt': return new Date((EPOCH_SECONDS + pull.createdSeq) * 1000).toISOString();
      case 'url': return `https://forge.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`;
      case 'mergeable': {
        if (pull.state !== 'open' || pull.merged) return 'UNKNOWN';
        const baseTip = branchTip(repo, pull.baseRef);
        const headTip = branchTip(repo, pull.headRef);
        if (!baseTip || !headTip) return 'UNKNOWN';
        return tryMergeTrees(repo, baseTip, headTip).conflict ? 'CONFLICTING' : 'MERGEABLE';
      }
      case 'files': {
        const baseTip = branchTip(repo, pull.baseRef);
        const headTip = branchTip(repo, pull.headRef);
        if (!baseTip || !headTip) return connectionObj('PullRequestFileConnection', [], args);
        const mergeBase = findMergeBase(repo, headTip, baseTip);
        const fromTree = mergeBase ? commitTreeOid(repo, mergeBase) : '';
        const changes = diffTrees(repo, fromTree, commitTreeOid(repo, headTip));
        const nodes = changes.map(
          (change): GqlObj => ({
            __typename: 'PullRequestFile',
            path: change.filename,
            additions: change.additions,
            deletions: change.deletions,
          }),
        );
        return connectionObj('PullRequestFileConnection', nodes, args);
      }
      case 'changedFiles': {
        const baseTip = branchTip(repo, pull.baseRef);
        const headTip = branchTip(repo, pull.headRef);
        if (!baseTip || !headTip) return 0;
        const mergeBase = findMergeBase(repo, headTip, baseTip);
        const fromTree = mergeBase ? commitTreeOid(repo, mergeBase) : '';
        return diffTrees(repo, fromTree, commitTreeOid(repo, headTip)).length;
      }
      case 'headRef': return { __typename: 'Ref', repo, name: pull.headRef };
      case 'baseRef': return { __typename: 'Ref', repo, name: pull.baseRef };
    }
    return UNKNOWN_FIELD;
  }

  if (typeName === 'Ref') {
    const repo = source.repo as RepoRec;
    if (field === 'name') return String(source.name ?? '');
    if (field === 'prefix') return 'refs/heads/';
    if (field === 'target') {
      const tip = branchTip(repo, String(source.name ?? ''));
      return tip ? { __typename: 'Commit', repo, oid: tip } : null;
    }
    return UNKNOWN_FIELD;
  }

  if (typeName === 'Commit') {
    const repo = source.repo as RepoRec;
    const oid = String(source.oid ?? '');
    if (field === 'oid') return oid;
    const object = getObject(repo, oid);
    if (field === 'message') return object && object.type === 'commit' ? parseCommit(object.data).message : '';
    if (field === 'committedDate') {
      if (object && object.type === 'commit') return parseIdent(parseCommit(object.data).committer).date;
      return new Date(EPOCH_SECONDS * 1000).toISOString();
    }
    return UNKNOWN_FIELD;
  }

  if (typeName === 'Label') {
    const repo = source.repo as RepoRec;
    const label = source.label as LabelRec;
    if (field === 'id') return encodeGid('Label', `${repo.id}:${label.name}`);
    if (field === 'name') return label.name;
    if (field === 'color') return label.color;
    return UNKNOWN_FIELD;
  }

  if (typeName === 'Comment') {
    const repo = source.repo as RepoRec;
    const issue = source.issue as IssueRec;
    const comment = source.comment as CommentRec;
    if (field === 'id') return encodeGid('Comment', `${repo.id}:${issue.number}:${comment.id}`);
    if (field === 'body') return comment.body;
    if (field === 'author') return userObj(comment.author);
    if (field === 'createdAt' || field === 'updatedAt') {
      return new Date((EPOCH_SECONDS + comment.createdSeq) * 1000).toISOString();
    }
    return UNKNOWN_FIELD;
  }

  // Generic fallback: plain properties on the source object.
  if (Object.prototype.hasOwnProperty.call(source, field)) {
    return source[field];
  }
  return UNKNOWN_FIELD;
}

function completeValue(
  ctx: GqlExecContext,
  value: unknown,
  selection: GqlSelection[] | undefined,
): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((item) => completeValue(ctx, item, selection));
  if (typeof value === 'object') {
    const obj = value as GqlObj;
    if (typeof obj.__typename === 'string' && selection) {
      const out: Record<string, unknown> = {};
      executeSelectionSet(ctx, obj.__typename, obj, selection, out);
      return out;
    }
    return value;
  }
  return value;
}

function executeSelectionSet(
  ctx: GqlExecContext,
  typeName: string,
  source: GqlObj,
  selections: GqlSelection[],
  out: Record<string, unknown>,
): void {
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      if (!selection.typeCondition || selection.typeCondition === typeName) {
        executeSelectionSet(ctx, typeName, source, selection.selection, out);
      }
      continue;
    }
    if (selection.kind === 'spread') {
      const fragment = ctx.fragments.get(selection.name);
      if (fragment && (!fragment.typeCondition || fragment.typeCondition === typeName)) {
        executeSelectionSet(ctx, typeName, source, fragment.selection, out);
      }
      continue;
    }
    const key = selection.alias ?? selection.name;
    if (selection.name === '__typename') {
      out[key] = typeName;
      continue;
    }
    if (selection.name === 'clientMutationId') {
      out[key] = null;
      continue;
    }
    const args = evalArgs(selection.args, ctx);
    let value: unknown;
    try {
      value = resolveField(ctx, typeName, source, selection.name, args);
    } catch (error) {
      ctx.errors.push({ message: error instanceof Error ? error.message : String(error) });
      out[key] = null;
      continue;
    }
    if (value === UNKNOWN_FIELD) {
      ctx.errors.push({
        message: `Field '${selection.name}' doesn't exist on type '${typeName}'`,
      });
      out[key] = null;
      continue;
    }
    out[key] = completeValue(ctx, value, selection.selection);
  }
}

function executeGraphqlOperation(
  store: Store,
  item: { query?: unknown; variables?: unknown; operationName?: unknown },
): Record<string, unknown> {
  if (typeof item.query !== 'string') {
    return { errors: [{ message: 'query must be a string' }] };
  }
  let document: GqlDocument;
  try {
    document = new GqlParser(item.query).parseDocument();
  } catch (error) {
    return { errors: [{ message: error instanceof Error ? error.message : 'parse error' }] };
  }
  let operation: GqlOperation | undefined;
  if (typeof item.operationName === 'string') {
    operation = document.operations.find((candidate) => candidate.name === item.operationName);
  }
  if (!operation) operation = document.operations[0];
  if (!operation) return { errors: [{ message: 'no operation in document' }] };

  const variables: Record<string, unknown> = {};
  for (const [name, defaultValue] of operation.variableDefaults) {
    const probe: GqlExecContext = { store, variables: {}, fragments: document.fragments, errors: [] };
    variables[name] = evalGqlValue(defaultValue, probe);
  }
  if (item.variables && typeof item.variables === 'object' && !Array.isArray(item.variables)) {
    Object.assign(variables, item.variables as Record<string, unknown>);
  }
  const ctx: GqlExecContext = { store, variables, fragments: document.fragments, errors: [] };
  const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
  const data: Record<string, unknown> = {};
  executeSelectionSet(ctx, rootType, { __typename: rootType }, operation.selection, data);
  const result: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) result.errors = ctx.errors;
  return result;
}

function handleGraphQL(store: Store, req: IncomingMessage, res: ServerResponse, body: Buffer): void {
  if (!isAuthed(req)) {
    sendJson(store, res, 401, { message: 'Bad credentials' });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    sendJson(store, res, 400, { errors: [{ message: 'Malformed JSON' }] });
    return;
  }
  if (Array.isArray(parsed)) {
    const results = parsed.map((item) =>
      executeGraphqlOperation(store, (item ?? {}) as { query?: unknown }),
    );
    sendJson(store, res, 200, results);
    return;
  }
  if (parsed && typeof parsed === 'object') {
    sendJson(store, res, 200, executeGraphqlOperation(store, parsed as { query?: unknown }));
    return;
  }
  sendJson(store, res, 400, { errors: [{ message: 'Malformed request' }] });
}

// ---------------------------------------------------------------------------
// MCP endpoint: JSON-RPC 2.0 over POST /mcp. Speaks the modern
// server/discover handshake and the legacy initialize handshake, and exposes
// six repository tools backed by the same store as REST.
// ---------------------------------------------------------------------------

const MCP_SERVER_INFO = { name: 'forge-mcp', version: FORGE_VERSION };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_LEGACY_VERSIONS = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'];

const MCP_TOOLS = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name.' },
        description: { type: 'string', description: 'Repository description.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Fetch a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Open a new issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Issue title.' },
        body: { type: 'string', description: 'Issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        state: { type: 'string', description: 'Issue state filter: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Pull request title.' },
        body: { type: 'string', description: 'Pull request body.' },
        head: { type: 'string', description: 'Head branch name.' },
        base: { type: 'string', description: 'Base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request into its base branch (squash).',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        pull_number: { type: 'number', description: 'Pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

class RpcError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

function mcpToolOk(value: unknown, textOverride?: string): Record<string, unknown> {
  const text = textOverride ?? JSON.stringify(value);
  const result: Record<string, unknown> = {
    content: [{ type: 'text', text }],
    isError: false,
  };
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    result.structuredContent = value;
  }
  return result;
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpCallTool(store: Store, params: Record<string, unknown>): Record<string, unknown> {
  const name = typeof params.name === 'string' ? params.name : '';
  const args = (params.arguments ?? {}) as Record<string, unknown>;
  const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (!tool) throw new RpcError(-32602, `Unknown tool: ${name}`);
  for (const required of tool.inputSchema.required) {
    if (args[required] === undefined || args[required] === '') {
      throw new RpcError(-32602, `Missing required argument: ${required}`);
    }
  }
  const repoFor = (): RepoRec | undefined =>
    findRepo(store, String(args.owner ?? ''), String(args.repo ?? ''));

  switch (name) {
    case 'create_repo': {
      const repoName = String(args.name);
      const existing = findRepo(store, VIEWER_LOGIN, repoName);
      if (existing) return mcpToolOk(repoJson(existing));
      const repo = createRepoRec(
        store,
        VIEWER_LOGIN,
        repoName,
        typeof args.description === 'string' ? args.description : '',
        args.private === true,
      );
      return mcpToolOk(repoJson(repo));
    }
    case 'get_repo': {
      const repo = repoFor();
      if (!repo) return mcpToolError(`Repository not found: ${String(args.owner)}/${String(args.repo)}`);
      return mcpToolOk(repoJson(repo));
    }
    case 'create_issue': {
      const repo = repoFor();
      if (!repo) return mcpToolError('Repository not found');
      const issue = createIssueRec(
        store,
        repo,
        String(args.title),
        typeof args.body === 'string' ? args.body : '',
        [],
      );
      return mcpToolOk(issueJson(repo, issue));
    }
    case 'list_issues': {
      const repo = repoFor();
      if (!repo) return mcpToolError('Repository not found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      let list = [...repo.issues.values()];
      if (state === 'open' || state === 'closed') {
        list = list.filter((issue) => issue.state === state);
      }
      list.sort((a, b) => a.number - b.number);
      const issues = list.map((issue) => issueJson(repo, issue));
      return mcpToolOk({ issues }, JSON.stringify(issues));
    }
    case 'create_pull_request': {
      const repo = repoFor();
      if (!repo) return mcpToolError('Repository not found');
      const head = stripOwnerPrefix(String(args.head));
      const base = stripOwnerPrefix(String(args.base));
      if (!branchTip(repo, head)) return mcpToolError(`head branch not found: ${head}`);
      if (!branchTip(repo, base)) return mcpToolError(`base branch not found: ${base}`);
      const duplicate = [...repo.pulls.values()].find(
        (pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base,
      );
      if (duplicate) return mcpToolOk(pullJson(repo, duplicate));
      const pull = createPullRec(
        store,
        repo,
        String(args.title),
        typeof args.body === 'string' ? args.body : '',
        head,
        base,
      );
      return mcpToolOk(pullJson(repo, pull));
    }
    case 'merge_pull_request': {
      const repo = repoFor();
      if (!repo) return mcpToolError('Repository not found');
      const pull = repo.pulls.get(Number(args.pull_number));
      if (!pull) return mcpToolError(`Pull request not found: ${String(args.pull_number)}`);
      if (pull.merged) return mcpToolOk(pullJson(repo, pull));
      if (pull.state === 'closed') return mcpToolError('Pull Request is not mergeable');
      const result = executeSquashMerge(store, repo, pull);
      if (!result.ok) return mcpToolError('Pull Request is not mergeable');
      return mcpToolOk(pullJson(repo, pull));
    }
  }
  throw new RpcError(-32602, `Unknown tool: ${name}`);
}

function mcpHandleOne(store: Store, message: unknown): Record<string, unknown> | null {
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } };
  }
  const msg = message as Record<string, unknown>;
  const hasId = Object.prototype.hasOwnProperty.call(msg, 'id');
  const id = hasId ? msg.id : null;
  const method = typeof msg.method === 'string' ? msg.method : '';
  if (!hasId) return null; // notification: nothing to answer
  const params = (msg.params ?? {}) as Record<string, unknown>;
  try {
    switch (method) {
      case 'server/discover':
        return {
          jsonrpc: '2.0',
          id,
          result: {
            supportedVersions: MCP_SUPPORTED_VERSIONS,
            capabilities: { tools: {} },
            serverInfo: MCP_SERVER_INFO,
            _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
          },
        };
      case 'initialize': {
        const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
        const protocolVersion = MCP_LEGACY_VERSIONS.includes(requested) ? requested : '2025-11-25';
        return {
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion,
            capabilities: { tools: {} },
            serverInfo: MCP_SERVER_INFO,
          },
        };
      }
      case 'ping':
        return { jsonrpc: '2.0', id, result: {} };
      case 'tools/list':
        return { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } };
      case 'tools/call':
        return { jsonrpc: '2.0', id, result: mcpCallTool(store, params) };
      default:
        return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
    }
  } catch (error) {
    if (error instanceof RpcError) {
      return { jsonrpc: '2.0', id, error: { code: error.code, message: error.message } };
    }
    return {
      jsonrpc: '2.0',
      id,
      error: { code: -32603, message: error instanceof Error ? error.message : 'Internal error' },
    };
  }
}

function handleMcp(store: Store, req: IncomingMessage, res: ServerResponse, text: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    sendBuffer(
      res,
      400,
      utf8(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })),
      'application/json; charset=utf-8',
    );
    return;
  }
  if (!isAuthed(req)) {
    sendBuffer(
      res,
      401,
      utf8(JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32001, message: 'Unauthorized' },
      })),
      'application/json; charset=utf-8',
    );
    return;
  }
  if (Array.isArray(parsed)) {
    const responses = parsed
      .map((item) => mcpHandleOne(store, item))
      .filter((item): item is Record<string, unknown> => item !== null);
    sendBuffer(res, 200, utf8(JSON.stringify(responses)), 'application/json; charset=utf-8');
    return;
  }
  const response = mcpHandleOne(store, parsed);
  if (response === null) {
    res.writeHead(202);
    res.end();
    return;
  }
  sendBuffer(res, 200, utf8(JSON.stringify(response)), 'application/json; charset=utf-8');
}

// ---------------------------------------------------------------------------
// Top-level dispatch + createApp.
// ---------------------------------------------------------------------------

const MAX_BODY_BYTES = 128 * 1024 * 1024;

async function handleRequest(store: Store, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = (req.method ?? 'GET').toUpperCase();
  let url: URL;
  try {
    url = new URL(req.url ?? '/', 'http://localhost');
  } catch {
    sendError(store, res, 400, 'Bad request target');
    return;
  }
  const path = url.pathname;

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > MAX_BODY_BYTES) {
      sendError(store, res, 413, 'Request body too large');
      return;
    }
    chunks.push(buffer);
  }
  const body = Buffer.concat(chunks);
  const ctx: RequestContext = { store, req, url, body, jsonCache: { parsed: false, value: undefined } };

  if (path === '/healthz') {
    sendJson(store, res, 200, { ok: true });
    return;
  }

  if (path === '/mcp') {
    if (method !== 'POST') {
      sendError(store, res, 405, 'Method Not Allowed');
      return;
    }
    handleMcp(store, req, res, body.toString('utf8'));
    return;
  }

  if (path === '/api/graphql') {
    if (method !== 'POST') {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    handleGraphQL(store, req, res, body);
    return;
  }

  if (path === '/api/v3' || path.startsWith('/api/v3/')) {
    if (!isAuthed(req)) {
      sendError(store, res, 401, 'Bad credentials');
      return;
    }
    const rawSegments = path
      .slice('/api/v3'.length)
      .split('/')
      .filter((segment) => segment !== '');
    let segments: string[];
    try {
      segments = rawSegments.map((segment) => decodeURIComponent(segment));
    } catch {
      segments = rawSegments;
    }
    routeRest(ctx, res, segments);
    return;
  }

  const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
  if (gitMatch) {
    if (!isAuthed(req)) {
      sendError(store, res, 401, 'Bad credentials');
      return;
    }
    let owner = gitMatch[1];
    let name = gitMatch[2];
    try {
      owner = decodeURIComponent(owner);
      name = decodeURIComponent(name);
    } catch {
      // keep raw values
    }
    const repo = findRepo(store, owner, name);
    if (!repo) {
      sendError(store, res, 404, 'Not Found');
      return;
    }
    const tail = gitMatch[3];
    if (tail === 'info/refs') {
      if (method !== 'GET') {
        sendError(store, res, 405, 'Method Not Allowed');
        return;
      }
      handleInfoRefs(store, req, res, repo, url.searchParams.get('service') ?? '');
      return;
    }
    if (method !== 'POST') {
      sendError(store, res, 405, 'Method Not Allowed');
      return;
    }
    if (tail === 'git-upload-pack') handleUploadPack(store, req, res, repo, body);
    else handleReceivePack(store, req, res, repo, body);
    return;
  }

  sendError(store, res, 404, 'Not Found');
}

export function createApp(): Server {
  const store = createStore();
  const server = createServer((req, res) => {
    handleRequest(store, req, res).catch(() => {
      try {
        if (!res.headersSent) sendError(store, res, 500, 'Internal Server Error');
        else res.end();
      } catch {
        // socket already gone
      }
    });
  });
  return server;
}
