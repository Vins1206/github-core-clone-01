// A standalone GitHub-compatible git forge: git smart HTTP (upload-pack protocol v2 and v0,
// receive-pack v0), the REST v3 API, the GraphQL v4 API and an MCP endpoint, all served from one
// process and one in-memory store, using only the Node standard library.
//
// Layout: this file is the whole server. main.ts owns the harness lifecycle (bind an ephemeral
// port, register it, wait for done); everything the suite scores lives here.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// small helpers

const JSON_TYPE = 'application/json; charset=utf-8';
const ZERO_OID = '0000000000000000000000000000000000000000';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const FALLBACK_LOGIN = 'adaiversen';

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value);
}

/** A logical clock: timestamps the forge writes are derived from a counter, never the wall clock. */
const clockState = { now: 1767225600 };
function nextTimestamp(): number {
  clockState.now += 61;
  return clockState.now;
}
function isoOf(epochSec: number): string {
  return new Date(epochSec * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ---------------------------------------------------------------------------
// the store

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface StoredObject {
  type: GitObjectType;
  data: Buffer;
}

/** Every git object the forge holds, across all repositories, keyed by its sha1 id. */
const objectStore = new Map<string, StoredObject>();

function storeObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  const oid = sha1Hex(Buffer.concat([header, data]));
  if (!objectStore.has(oid)) objectStore.set(oid, { type, data });
  return oid;
}

function getObject(oid: string): StoredObject | undefined {
  return objectStore.get(oid);
}

interface CommentRec {
  dbId: number;
  body: string;
  seq: number;
}

interface IssueRec {
  dbId: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: CommentRec[];
  seq: number;
}

interface PullRec {
  dbId: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  merged: boolean;
  mergeCommitSha: string | null;
  seq: number;
}

interface LabelRec {
  name: string;
  color: string;
  description: string | null;
}

interface RepoRec {
  dbId: number;
  name: string;
  description: string | null;
  isPrivate: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  labels: Map<string, LabelRec>;
  issues: Map<number, IssueRec>;
  pulls: Map<number, PullRec>;
  nextNumber: number;
  seq: number;
}

const state = {
  login: null as string | null,
  repos: new Map<string, RepoRec>(),
  repoSeq: 0,
  dbSeq: 5000,
  reqSeq: 0,
};

function viewerLogin(): string {
  return state.login ?? FALLBACK_LOGIN;
}

/** The first owner segment the suite addresses becomes the token owner's login. */
function learnLogin(owner: string): void {
  if (state.login === null && owner !== '') state.login = owner;
}

function createRepo(name: string, description: string | null, isPrivate: boolean): RepoRec {
  state.repoSeq += 1;
  state.dbSeq += 1;
  const repo: RepoRec = {
    dbId: state.dbSeq,
    name,
    description,
    isPrivate,
    defaultBranch: 'main',
    refs: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    seq: state.repoSeq,
  };
  state.repos.set(name.toLowerCase(), repo);
  return repo;
}

function findRepo(owner: string, name: string): RepoRec | null {
  learnLogin(owner);
  if (state.login !== null && owner !== state.login) return null;
  return state.repos.get(name.toLowerCase()) ?? null;
}

// ---------------------------------------------------------------------------
// git object model

interface CommitInfo {
  tree: string;
  parents: string[];
  message: string;
  committerTime: number;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank === -1 ? text : text.slice(0, blank);
  const message = blank === -1 ? '' : text.slice(blank + 2);
  let tree = ZERO_OID;
  const parents: string[] = [];
  let committerTime = 0;
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('committer ')) {
      const match = / (\d+) [+-]\d{4}$/.exec(line);
      if (match) committerTime = Number(match[1]);
    }
  }
  return { tree, parents, message, committerTime };
}

function tagTarget(data: Buffer): string {
  const match = /^object ([0-9a-f]{40})$/m.exec(data.toString('utf8'));
  return match ? match[1] : ZERO_OID;
}

/** Peel an object id through tag objects until a non-tag object (or a missing id). */
function peelToCommit(oid: string): string {
  let current = oid;
  for (let guard = 0; guard < 16; guard += 1) {
    const obj = getObject(current);
    if (obj === undefined || obj.type !== 'tag') return current;
    current = tagTarget(obj.data);
  }
  return current;
}

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
    if (space === -1) break;
    const mode = data.subarray(offset, space).toString('utf8');
    const nul = data.indexOf(0x00, space + 1);
    if (nul === -1 || nul + 21 > data.length) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

/** Git's tree order: by name, with directories sorting as if their name ended in '/'. */
function treeEntryCompare(a: TreeEntry, b: TreeEntry): number {
  const aKey = a.mode === '40000' ? `${a.name}/` : a.name;
  const bKey = b.mode === '40000' ? `${b.name}/` : b.name;
  return aKey < bKey ? -1 : aKey > bKey ? 1 : 0;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(treeEntryCompare);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface FlatEntry {
  mode: string;
  oid: string;
}

/** Flatten a tree object into a map of full path to blob entry, recursively. */
function flattenTree(treeOid: string, prefix: string, out: Map<string, FlatEntry>): void {
  const obj = getObject(treeOid);
  if (obj === undefined || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(entry.oid, path, out);
    else out.set(path, { mode: entry.mode, oid: entry.oid });
  }
}

function flatMapOfCommit(commitOid: string): Map<string, FlatEntry> {
  const out = new Map<string, FlatEntry>();
  const obj = getObject(commitOid);
  if (obj !== undefined && obj.type === 'commit') flattenTree(parseCommit(obj.data).tree, '', out);
  return out;
}

/** Build (and store) nested tree objects from a flat path map; returns the root tree id. */
function storeTreeFromFlat(flat: Map<string, FlatEntry>): string {
  interface DirNode {
    files: Map<string, FlatEntry>;
    dirs: Map<string, DirNode>;
  }
  const root: DirNode = { files: new Map(), dirs: new Map() };
  for (const [path, entry] of flat) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const part = parts[i] as string;
      if (!node.dirs.has(part)) node.dirs.set(part, { files: new Map(), dirs: new Map() });
      node = node.dirs.get(part) as DirNode;
    }
    node.files.set(parts[parts.length - 1] as string, entry);
  }
  const writeNode = (node: DirNode): string => {
    const entries: TreeEntry[] = [];
    for (const [name, sub] of node.dirs) entries.push({ mode: '40000', name, oid: writeNode(sub) });
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    return storeObject('tree', buildTree(entries));
  };
  return writeNode(root);
}

const FORGE_IDENT = 'Forge Bot <forge@localhost>';

function makeCommit(tree: string, parents: string[], message: string): string {
  const ts = nextTimestamp();
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${FORGE_IDENT} ${ts} +0000`);
  lines.push(`committer ${FORGE_IDENT} ${ts} +0000`);
  const data = Buffer.from(`${lines.join('\n')}\n\n${message}`, 'utf8');
  return storeObject('commit', data);
}

/** Every commit reachable from a tip, newest first (committer time, then discovery order). */
function listCommitsFrom(tip: string): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  const frontier: string[] = [tip];
  while (frontier.length > 0) {
    let bestIndex = 0;
    let bestTime = -1;
    for (let i = 0; i < frontier.length; i += 1) {
      const obj = getObject(frontier[i] as string);
      const time = obj !== undefined && obj.type === 'commit' ? parseCommit(obj.data).committerTime : 0;
      if (time >= bestTime) {
        bestTime = time;
        bestIndex = i;
      }
    }
    const current = frontier.splice(bestIndex, 1)[0] as string;
    if (seen.has(current)) continue;
    const obj = getObject(current);
    if (obj === undefined || obj.type !== 'commit') continue;
    seen.add(current);
    result.push(current);
    for (const parent of parseCommit(obj.data).parents) {
      if (!seen.has(parent)) frontier.push(parent);
    }
  }
  return result;
}

function ancestorsOf(tip: string): Set<string> {
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    if (seen.has(current)) continue;
    const obj = getObject(current);
    if (obj === undefined || obj.type !== 'commit') continue;
    seen.add(current);
    for (const parent of parseCommit(obj.data).parents) stack.push(parent);
  }
  return seen;
}

function isAncestor(ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  return ancestorsOf(descendant).has(ancestor);
}

/** The best common ancestor of two commits, or null when their histories are disjoint. */
function mergeBaseOf(a: string, b: string): string | null {
  const ancestorsA = ancestorsOf(a);
  for (const candidate of listCommitsFrom(b)) {
    if (ancestorsA.has(candidate)) return candidate;
  }
  return null;
}

// ---------------------------------------------------------------------------
// packfiles and pkt-lines

const TYPE_CODES: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPES: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/** Write a packfile holding the given objects, plain (no deltas), with its sha1 trailer. */
function writePack(oids: string[]): Buffer {
  const present = oids.filter((oid) => getObject(oid) !== undefined);
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(present.length, 8);
  parts.push(header);
  for (const oid of present) {
    const obj = getObject(oid) as StoredObject;
    const size = obj.data.length;
    const bytes: number[] = [];
    let rest = size >> 4;
    let first = ((TYPE_CODES[obj.type] as number) << 4) | (size & 0x0f);
    if (rest > 0) first |= 0x80;
    bytes.push(first);
    while (rest > 0) {
      let byte = rest & 0x7f;
      rest >>= 7;
      if (rest > 0) byte |= 0x80;
      bytes.push(byte);
    }
    parts.push(Buffer.from(bytes));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

/** The exact compressed length of the deflate stream starting at `offset` (binary search). */
function inflateAt(buffer: Buffer, offset: number): { data: Buffer; consumed: number } {
  let lo = 1;
  let hi = buffer.length - offset;
  let best = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      inflateSync(buffer.subarray(offset, offset + mid));
      best = mid;
      hi = mid - 1;
    } catch {
      lo = mid + 1;
    }
  }
  if (best === -1) throw new Error('corrupt deflate stream in pack');
  return { data: inflateSync(buffer.subarray(offset, offset + best)), consumed: best };
}

/** Apply a git delta (copy/insert instructions) to a base object. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset] as number;
      offset += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const targetSize = readVarint();
  const parts: Buffer[] = [];
  let produced = 0;
  while (offset < delta.length) {
    const op = delta[offset] as number;
    offset += 1;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      if (op & 0x01) { copyOffset = delta[offset] as number; offset += 1; }
      if (op & 0x02) { copyOffset |= (delta[offset] as number) << 8; offset += 1; }
      if (op & 0x04) { copyOffset |= (delta[offset] as number) << 16; offset += 1; }
      if (op & 0x08) { copyOffset |= (delta[offset] as number) << 24; offset += 1; }
      if (op & 0x10) { copySize = delta[offset] as number; offset += 1; }
      if (op & 0x20) { copySize |= (delta[offset] as number) << 8; offset += 1; }
      if (op & 0x40) { copySize |= (delta[offset] as number) << 16; offset += 1; }
      if (copySize === 0) copySize = 0x10000;
      parts.push(base.subarray(copyOffset, copyOffset + copySize));
      produced += copySize;
    } else if (op !== 0) {
      parts.push(delta.subarray(offset, offset + op));
      produced += op;
      offset += op;
    } else {
      throw new Error('delta opcode 0 is reserved');
    }
  }
  const out = Buffer.concat(parts);
  if (produced !== targetSize || out.length !== targetSize) throw new Error('delta target size mismatch');
  return out;
}

interface PackEntry {
  oid: string;
  type: GitObjectType;
}

/** Parse a packfile into the object store, resolving ofs/ref deltas. Returns the object ids added. */
function readPack(pack: Buffer): PackEntry[] {
  if (pack.length < 12 + 20 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const count = pack.readUInt32BE(8);
  let offset = 12;
  interface RawEntry {
    type: GitObjectType;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
    start: number;
  }
  const raw: RawEntry[] = [];
  const byOffset = new Map<number, RawEntry>();
  for (let i = 0; i < count; i += 1) {
    const start = offset;
    let byte = pack[offset] as number;
    offset += 1;
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = pack[offset] as number;
      offset += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    if (typeCode === 6) {
      let back = pack[offset] as number;
      offset += 1;
      let baseBack = back & 0x7f;
      while (back & 0x80) {
        back = pack[offset] as number;
        offset += 1;
        baseBack = ((baseBack + 1) << 7) | (back & 0x7f);
      }
      const inflated = inflateAt(pack, offset);
      offset += inflated.consumed;
      const entry: RawEntry = { type: 'commit', data: inflated.data, baseOffset: start - baseBack, start };
      raw.push(entry);
      byOffset.set(start, entry);
    } else if (typeCode === 7) {
      const baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
      const inflated = inflateAt(pack, offset);
      offset += inflated.consumed;
      const entry: RawEntry = { type: 'commit', data: inflated.data, baseOid, start };
      raw.push(entry);
      byOffset.set(start, entry);
    } else {
      const type = CODE_TYPES[typeCode];
      if (type === undefined) throw new Error(`unknown pack object type ${typeCode}`);
      const inflated = inflateAt(pack, offset);
      offset += inflated.consumed;
      if (inflated.data.length !== size) throw new Error('pack object size mismatch');
      const entry: RawEntry = { type, data: inflated.data, start };
      raw.push(entry);
      byOffset.set(start, entry);
    }
  }
  const resolved = new Map<number, PackEntry>();
  const resolve = (entry: RawEntry): PackEntry => {
    const cached = resolved.get(entry.start);
    if (cached !== undefined) return cached;
    let result: PackEntry;
    if (entry.baseOffset !== undefined) {
      const base = byOffset.get(entry.baseOffset);
      if (base === undefined) throw new Error('ofs-delta base missing from pack');
      const baseResolved = resolve(base);
      const baseObj = getObject(baseResolved.oid);
      if (baseObj === undefined) throw new Error('ofs-delta base not stored');
      const data = applyDelta(baseObj.data, entry.data);
      result = { oid: storeObject(baseResolved.type, data), type: baseResolved.type };
    } else if (entry.baseOid !== undefined) {
      const baseObj = getObject(entry.baseOid);
      if (baseObj === undefined) throw new Error('ref-delta base not available');
      const data = applyDelta(baseObj.data, entry.data);
      result = { oid: storeObject(baseObj.type, data), type: baseObj.type };
    } else {
      result = { oid: storeObject(entry.type, entry.data), type: entry.type };
    }
    resolved.set(entry.start, result);
    return result;
  };
  return raw.map((entry) => resolve(entry));
}

/** One pkt-line packet: a string payload, or the 'flush' / 'delim' control packets. */
type Pkt = string | Buffer | 'flush' | 'delim';

function pktEncode(items: Pkt[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') {
      parts.push(Buffer.from('0000', 'ascii'));
    } else if (item === 'delim') {
      parts.push(Buffer.from('0001', 'ascii'));
    } else {
      const payload = typeof item === 'string' ? Buffer.from(item, 'utf8') : item;
      const length = payload.length + 4;
      parts.push(Buffer.from(length.toString(16).padStart(4, '0'), 'ascii'));
      parts.push(payload);
    }
  }
  return Buffer.concat(parts);
}

interface PktPacket {
  kind: 'data' | 'flush' | 'delim';
  payload: Buffer;
}

/** Decode a pkt-line stream; throws on a malformed frame. */
function pktDecode(buffer: Buffer): PktPacket[] {
  const packets: PktPacket[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('truncated pkt-line');
    const hex = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('malformed pkt-line length');
    const length = parseInt(hex, 16);
    if (length === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
    } else if (length === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
    } else if (length === 2) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
    } else {
      if (length < 4 || offset + length > buffer.length) throw new Error('pkt-line overruns body');
      packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
      offset += length;
    }
  }
  return packets;
}

/** Wrap a byte stream in sideband band-1 pkt-lines (payload at most 65516 bytes, band byte included). */
function sidebandWrap(data: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let offset = 0; offset < data.length; offset += 65515) {
    const chunk = data.subarray(offset, Math.min(data.length, offset + 65515));
    const payload = Buffer.concat([Buffer.from([1]), chunk]);
    parts.push(Buffer.from((payload.length + 4).toString(16).padStart(4, '0'), 'ascii'));
    parts.push(payload);
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// fetch computation

interface FetchPlan {
  packOids: string[];
  shallow: string[];
  unshallow: string[];
  commonHaves: string[];
}

/** The closure of objects reachable from tips; commit parents of `shallowStop` commits are not walked. */
function closureOf(tips: string[], shallowStop: Set<string>): Set<string> {
  const out = new Set<string>();
  const stack = [...tips];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    if (out.has(current)) continue;
    const obj = getObject(current);
    if (obj === undefined) continue;
    out.add(current);
    if (obj.type === 'commit') {
      const info = parseCommit(obj.data);
      stack.push(info.tree);
      if (!shallowStop.has(current)) for (const parent of info.parents) stack.push(parent);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) stack.push(entry.oid);
    } else if (obj.type === 'tag') {
      stack.push(tagTarget(obj.data));
    }
  }
  return out;
}

/**
 * Plan a fetch: which objects to pack, and the shallow boundary movement.
 * Depth is counted in commit generations from the wants; the client's own shallow
 * boundary stops the history walk the same way it stops the have walk.
 */
function planFetch(
  wants: string[],
  haves: string[],
  clientShallow: Set<string>,
  depth: number | null,
  deepenSince: number | null = null,
  deepenNot: Set<string> = new Set(),
): FetchPlan {
  const haveObjs = closureOf(haves, clientShallow);

  // Distances (in commit generations) from the wants.
  const distance = new Map<string, number>();
  const queue: Array<{ oid: string; dist: number }> = [];
  const extraRoots: string[] = [];
  for (const want of wants) {
    const obj = getObject(want);
    if (obj === undefined || deepenNot.has(want)) continue;
    if (obj.type === 'commit') queue.push({ oid: want, dist: 0 });
    else extraRoots.push(want);
  }
  while (queue.length > 0) {
    const { oid, dist } = queue.shift() as { oid: string; dist: number };
    const known = distance.get(oid);
    if (known !== undefined && known <= dist) continue;
    distance.set(oid, dist);
    if (depth !== null && dist + 1 >= depth) continue;
    if (depth === null && deepenSince === null && clientShallow.has(oid)) continue;
    const obj = getObject(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    const info = parseCommit(obj.data);
    if (deepenSince !== null && info.committerTime > 0 && info.committerTime <= deepenSince) continue;
    for (const parent of info.parents) {
      if (!deepenNot.has(parent)) queue.push({ oid: parent, dist: dist + 1 });
    }
  }

  const included = new Set<string>();
  for (const root of extraRoots) {
    for (const oid of closureOf([root], new Set())) included.add(oid);
  }
  for (const oid of distance.keys()) {
    const obj = getObject(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    included.add(oid);
    for (const sub of closureOf([parseCommit(obj.data).tree], new Set())) included.add(sub);
  }

  const shallow: string[] = [];
  const unshallow: string[] = [];
  for (const oid of distance.keys()) {
    const obj = getObject(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    const parents = parseCommit(obj.data).parents;
    if (parents.length === 0) continue;
    const parentsIncluded = parents.every((parent) => included.has(parent) || haveObjs.has(parent));
    if (!parentsIncluded) shallow.push(oid);
    else if (clientShallow.has(oid)) unshallow.push(oid);
  }
  for (const oid of clientShallow) {
    if (included.has(oid) && !shallow.includes(oid) && !unshallow.includes(oid)) {
      const obj = getObject(oid);
      if (obj !== undefined && obj.type === 'commit' && parseCommit(obj.data).parents.length > 0) shallow.push(oid);
    }
  }

  const packOids: string[] = [];
  for (const oid of included) {
    if (!haveObjs.has(oid)) packOids.push(oid);
  }
  const commonHaves = haves.filter((have) => getObject(have) !== undefined);
  return { packOids, shallow, unshallow, commonHaves };
}

// ---------------------------------------------------------------------------
// HTTP plumbing

interface ReqInfo {
  method: string;
  segments: string[];
  query: URLSearchParams;
  headers: IncomingMessage['headers'];
  body: Buffer;
  host: string;
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = body === undefined ? '' : JSON.stringify(body);
  state.reqSeq += 1;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': `FORGE-${state.reqSeq.toString(16).toUpperCase().padStart(6, '0')}`,
    ...extra,
  });
  res.end(text);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  state.reqSeq += 1;
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': `FORGE-${state.reqSeq.toString(16).toUpperCase().padStart(6, '0')}`,
  });
  res.end(body);
}

function notFound(res: ServerResponse): void {
  sendJson(res, 404, { message: 'Not Found' });
}

function authed(info: ReqInfo): boolean {
  const header = info.headers.authorization;
  if (TOKEN !== '') return header === `Bearer ${TOKEN}`;
  return typeof header === 'string' && header.startsWith('Bearer ') && header.length > 7;
}

/** Parse a JSON body; on failure answers 400 and returns the sentinel. */
const BAD_JSON = Symbol('bad-json');
function jsonBody(info: ReqInfo, res: ServerResponse): unknown {
  if (info.body.length === 0) return {};
  try {
    return JSON.parse(info.body.toString('utf8'));
  } catch {
    sendJson(res, 400, { message: 'Problems parsing JSON' });
    return BAD_JSON;
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function strField(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === 'string' ? value : undefined;
}

// ---------------------------------------------------------------------------
// REST view builders

function repoJson(repo: RepoRec): Record<string, unknown> {
  const login = viewerLogin();
  const ts = isoOf(1767225600 + repo.seq * 61);
  return {
    id: repo.dbId,
    node_id: Buffer.from(`Repository:${repo.dbId}`).toString('base64'),
    name: repo.name,
    full_name: `${login}/${repo.name}`,
    owner: { login, id: 1000, node_id: Buffer.from(`User:${login}`).toString('base64'), type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    fork: false,
    html_url: `http://forge.local/${login}/${repo.name}`,
    clone_url: `http://forge.local/${login}/${repo.name}.git`,
    default_branch: repo.defaultBranch,
    created_at: ts,
    updated_at: ts,
    pushed_at: ts,
  };
}

function labelJson(label: LabelRec): Record<string, unknown> {
  return { name: label.name, color: label.color, description: label.description, default: false };
}

function issueJson(repo: RepoRec, issue: IssueRec): Record<string, unknown> {
  const login = viewerLogin();
  const ts = isoOf(1767225600 + issue.seq * 61);
  return {
    id: issue.dbId,
    node_id: Buffer.from(`Issue:${repo.dbId}:${issue.number}`).toString('base64'),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelJson(repo.labels.get(name) ?? { name, color: 'ededed', description: null })),
    user: { login, id: 1000, type: 'User' },
    comments: issue.comments.length,
    created_at: ts,
    updated_at: ts,
    closed_at: issue.state === 'closed' ? ts : null,
    html_url: `http://forge.local/${login}/${repo.name}/issues/${issue.number}`,
  };
}

function refSha(repo: RepoRec, refName: string): string | null {
  const oid = repo.refs.get(`refs/heads/${refName}`) ?? repo.refs.get(refName);
  return oid === undefined ? null : oid;
}

function pullJson(repo: RepoRec, pull: PullRec): Record<string, unknown> {
  const login = viewerLogin();
  const ts = isoOf(1767225600 + pull.seq * 61);
  const headSha = refSha(repo, pull.headRef);
  const baseSha = refSha(repo, pull.baseRef);
  return {
    id: pull.dbId,
    node_id: Buffer.from(`PullRequest:${repo.dbId}:${pull.number}`).toString('base64'),
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    user: { login, id: 1000, type: 'User' },
    head: {
      ref: pull.headRef,
      sha: headSha ?? ZERO_OID,
      label: `${login}:${pull.headRef}`,
      repo: repoJson(repo),
    },
    base: {
      ref: pull.baseRef,
      sha: baseSha ?? ZERO_OID,
      label: `${login}:${pull.baseRef}`,
      repo: repoJson(repo),
    },
    merged: pull.merged,
    merged_at: pull.merged ? ts : null,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pull.state === 'open' ? mergeSimulation(repo, pull).conflict === false : null,
    draft: false,
    created_at: ts,
    updated_at: ts,
    html_url: `http://forge.local/${login}/${repo.name}/pull/${pull.number}`,
  };
}

// ---------------------------------------------------------------------------
// merge machinery (three-way, per path, against the merge base)

interface MergeOutcome {
  conflict: boolean;
  tree: string | null;
}

/** Simulate (or perform) a squash of the pull's head onto its base branch. */
function mergeSimulation(repo: RepoRec, pull: PullRec): MergeOutcome {
  const headOid = refSha(repo, pull.headRef);
  const baseOid = refSha(repo, pull.baseRef);
  if (headOid === null || baseOid === null) return { conflict: true, tree: null };
  const headCommit = peelToCommit(headOid);
  const baseCommit = peelToCommit(baseOid);
  const base = mergeBaseOf(headCommit, baseCommit);
  if (base === null) return { conflict: true, tree: null };
  const baseMap = flatMapOfCommit(base);
  const headMap = flatMapOfCommit(headCommit);
  const targetMap = flatMapOfCommit(baseCommit);
  const result = new Map(targetMap);
  const paths = new Set<string>([...baseMap.keys(), ...headMap.keys()]);
  for (const path of paths) {
    const inBase = baseMap.get(path);
    const inHead = headMap.get(path);
    const inTarget = targetMap.get(path);
    const headChanged = (inHead?.oid ?? null) !== (inBase?.oid ?? null);
    if (!headChanged) continue;
    const targetChanged = (inTarget?.oid ?? null) !== (inBase?.oid ?? null);
    if (targetChanged && (inTarget?.oid ?? null) !== (inHead?.oid ?? null)) {
      return { conflict: true, tree: null };
    }
    if (inHead === undefined) result.delete(path);
    else result.set(path, inHead);
  }
  return { conflict: false, tree: storeTreeFromFlat(result) };
}

/** Perform the merge: one squash commit on the base branch; returns its sha, or null on conflict. */
function performMerge(repo: RepoRec, pull: PullRec, method: string): string | null {
  const outcome = mergeSimulation(repo, pull);
  if (outcome.conflict || outcome.tree === null) return null;
  const baseOid = refSha(repo, pull.baseRef) as string;
  const baseCommit = peelToCommit(baseOid);
  let sha: string;
  if (method === 'merge') {
    const headCommit = peelToCommit(refSha(repo, pull.headRef) as string);
    const ts = nextTimestamp();
    const lines = [
      `tree ${outcome.tree}`,
      `parent ${baseCommit}`,
      `parent ${headCommit}`,
      `author ${FORGE_IDENT} ${ts} +0000`,
      `committer ${FORGE_IDENT} ${ts} +0000`,
    ];
    sha = storeObject('commit', Buffer.from(`${lines.join('\n')}\n\nMerge pull request #${pull.number} from ${pull.headRef}\n\n${pull.title}`, 'utf8'));
  } else {
    sha = makeCommit(outcome.tree, [baseCommit], `${pull.title} (#${pull.number})`);
  }
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergeCommitSha = sha;
  return sha;
}

/** The files a pull request changes: head versus the merge base, with line counts. */
function pullFiles(repo: RepoRec, pull: PullRec): Array<Record<string, unknown>> {
  const headOid = refSha(repo, pull.headRef);
  const baseOid = refSha(repo, pull.baseRef);
  if (headOid === null || baseOid === null) return [];
  const headCommit = peelToCommit(headOid);
  const baseCommit = peelToCommit(baseOid);
  const base = mergeBaseOf(headCommit, baseCommit) ?? baseCommit;
  const baseMap = flatMapOfCommit(base);
  const headMap = flatMapOfCommit(headCommit);
  const files: Array<Record<string, unknown>> = [];
  const paths = new Set<string>([...baseMap.keys(), ...headMap.keys()]);
  const lineCount = (oid: string | undefined): number => {
    if (oid === undefined) return 0;
    const obj = getObject(oid);
    if (obj === undefined) return 0;
    return obj.data.toString('utf8').split('\n').length;
  };
  for (const path of [...paths].sort()) {
    const before = baseMap.get(path);
    const after = headMap.get(path);
    if ((before?.oid ?? null) === (after?.oid ?? null)) continue;
    const status = before === undefined ? 'added' : after === undefined ? 'removed' : 'modified';
    const additions = after === undefined ? 0 : lineCount(after.oid);
    const deletions = before === undefined ? 0 : lineCount(before.oid);
    files.push({
      sha: after?.oid ?? before?.oid,
      filename: path,
      status,
      additions,
      deletions,
      changes: additions + deletions,
    });
  }
  return files;
}

// ---------------------------------------------------------------------------
// REST v3

function pageParams(info: ReqInfo): { page: number; perPage: number } {
  const perPageRaw = Number(info.query.get('per_page') ?? '30');
  const pageRaw = Number(info.query.get('page') ?? '1');
  return {
    perPage: Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.floor(perPageRaw)) : 30,
    page: Number.isFinite(pageRaw) && pageRaw > 0 ? Math.floor(pageRaw) : 1,
  };
}

/** Slice one page out of a list and add GitHub's Link header when more pages exist. */
function paginate<T>(info: ReqInfo, res: ServerResponse, items: T[], basePath: string): T[] {
  const { page, perPage } = pageParams(info);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const slice = items.slice((page - 1) * perPage, page * perPage);
  if (page < totalPages) {
    const kept = new URLSearchParams();
    for (const [key, value] of info.query) {
      if (key !== 'page' && key !== 'per_page') kept.set(key, value);
    }
    kept.set('per_page', String(perPage));
    kept.set('page', String(page + 1));
    const next = `http://${info.host}${basePath}?${kept.toString()}`;
    kept.set('page', String(totalPages));
    const last = `http://${info.host}${basePath}?${kept.toString()}`;
    res.setHeader('link', `<${next}>; rel="next", <${last}>; rel="last"`);
  }
  return slice;
}

function createIssueRec(repo: RepoRec, title: string, body: string, labels: string[]): IssueRec {
  state.dbSeq += 1;
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const issue: IssueRec = {
    dbId: state.dbSeq,
    number,
    title,
    body,
    state: 'open',
    labels: [...labels],
    comments: [],
    seq: ++state.repoSeq,
  };
  repo.issues.set(number, issue);
  return issue;
}

function createPullRec(repo: RepoRec, title: string, body: string, headRef: string, baseRef: string): PullRec {
  state.dbSeq += 1;
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const pull: PullRec = {
    dbId: state.dbSeq,
    number,
    title,
    body,
    state: 'open',
    headRef,
    baseRef,
    merged: false,
    mergeCommitSha: null,
    seq: ++state.repoSeq,
  };
  repo.pulls.set(number, pull);
  return pull;
}

/** The branch a contents or commit operation addresses: the body's/query's branch or the default. */
function branchTip(repo: RepoRec, branch: string | undefined): { ref: string; tip: string | null } {
  const name = branch ?? repo.defaultBranch;
  const ref = `refs/heads/${name}`;
  return { ref, tip: repo.refs.get(ref) ?? null };
}

function handleContents(info: ReqInfo, res: ServerResponse, repo: RepoRec, path: string): void {
  const method = info.method;
  if (method === 'GET') {
    const ref = info.query.get('ref') ?? undefined;
    let tip: string | null;
    if (ref !== undefined && isOid(ref) && getObject(ref)?.type === 'commit') tip = ref;
    else tip = branchTip(repo, ref).tip;
    if (tip === null) {
      if (path === '') {
        sendJson(res, 200, []);
        return;
      }
      notFound(res);
      return;
    }
    const commit = getObject(tip);
    if (commit === undefined || commit.type !== 'commit') {
      notFound(res);
      return;
    }
    const flat = flatMapOfCommit(tip);
    const clean = path.replace(/^\/+|\/+$/g, '');
    if (clean !== '') {
      const file = flat.get(clean);
      if (file !== undefined) {
        const blob = getObject(file.oid);
        const data = blob?.data ?? Buffer.alloc(0);
        sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          content: data.toString('base64'),
          sha: file.oid,
          size: data.length,
          name: clean.split('/').pop(),
          path: clean,
        });
        return;
      }
    }
    // A directory (or the root): list its immediate entries.
    const prefix = clean === '' ? '' : `${clean}/`;
    const entries = new Map<string, { type: string; oid: string; size: number }>();
    let dirExists = clean === '';
    for (const [filePath, entry] of flat) {
      if (prefix !== '' && !filePath.startsWith(prefix)) continue;
      dirExists = true;
      const rest = filePath.slice(prefix.length);
      const slash = rest.indexOf('/');
      if (slash === -1) {
        const blob = getObject(entry.oid);
        entries.set(rest, { type: 'file', oid: entry.oid, size: blob?.data.length ?? 0 });
      } else {
        const dirName = rest.slice(0, slash);
        if (!entries.has(dirName)) {
          const subTree = treeOidAtPath(tip, prefix + dirName);
          entries.set(dirName, { type: 'dir', oid: subTree ?? ZERO_OID, size: 0 });
        }
      }
    }
    if (!dirExists) {
      notFound(res);
      return;
    }
    const list = [...entries.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([name, entry]) => ({
        type: entry.type,
        name,
        path: prefix + name,
        sha: entry.oid,
        size: entry.size,
      }));
    sendJson(res, 200, list);
    return;
  }
  if (method === 'PUT' || method === 'DELETE') {
    const parsed = jsonBody(info, res);
    if (parsed === BAD_JSON) return;
    const body = asRecord(parsed);
    const message = strField(body, 'message') ?? (method === 'PUT' ? 'add file' : 'delete file');
    const branch = strField(body, 'branch');
    const { ref, tip } = branchTip(repo, branch);
    if (branch !== undefined && tip === null && !(branch === repo.defaultBranch)) {
      sendJson(res, 404, { message: 'Branch not found' });
      return;
    }
    const flat = tip === null ? new Map<string, FlatEntry>() : flatMapOfCommit(tip);
    const clean = path.replace(/^\/+/, '');
    const existing = flat.get(clean);
    if (method === 'PUT') {
      const contentB64 = strField(body, 'content');
      if (contentB64 === undefined) {
        sendJson(res, 422, { message: 'content is required' });
        return;
      }
      const shaGiven = strField(body, 'sha');
      if (existing !== undefined) {
        if (shaGiven === undefined) {
          sendJson(res, 422, { message: 'sha is required when updating a file' });
          return;
        }
        if (shaGiven !== existing.oid) {
          sendJson(res, 409, { message: 'The supplied sha does not match the current file' });
          return;
        }
      }
      const data = Buffer.from(contentB64, 'base64');
      const blobOid = storeObject('blob', data);
      flat.set(clean, { mode: '100644', oid: blobOid });
      const tree = storeTreeFromFlat(flat);
      const commitSha = makeCommit(tree, tip === null ? [] : [tip], message);
      repo.refs.set(ref, commitSha);
      sendJson(res, existing === undefined ? 201 : 200, {
        content: {
          type: 'file',
          encoding: 'base64',
          sha: blobOid,
          size: data.length,
          name: clean.split('/').pop(),
          path: clean,
        },
        commit: { sha: commitSha, message },
      });
      return;
    }
    // DELETE
    if (existing === undefined) {
      notFound(res);
      return;
    }
    const shaGiven = strField(body, 'sha');
    if (shaGiven !== undefined && shaGiven !== existing.oid) {
      sendJson(res, 409, { message: 'The supplied sha does not match the current file' });
      return;
    }
    flat.delete(clean);
    const tree = storeTreeFromFlat(flat);
    const commitSha = makeCommit(tree, tip === null ? [] : [tip], message);
    repo.refs.set(ref, commitSha);
    sendJson(res, 200, { content: null, commit: { sha: commitSha, message } });
    return;
  }
  notFound(res);
}

/** The tree id at a directory path inside a commit, or null. */
function treeOidAtPath(commitOid: string, dirPath: string): string | null {
  const commit = getObject(commitOid);
  if (commit === undefined || commit.type !== 'commit') return null;
  let current = parseCommit(commit.data).tree;
  for (const part of dirPath.split('/').filter((part) => part !== '')) {
    const tree = getObject(current);
    if (tree === undefined || tree.type !== 'tree') return null;
    const entry = parseTree(tree.data).find((candidate) => candidate.name === part && candidate.mode === '40000');
    if (entry === undefined) return null;
    current = entry.oid;
  }
  return current;
}

function handleRest(info: ReqInfo, res: ServerResponse): void {
  const seg = info.segments;
  // seg: ['api', 'v3', ...]
  const rest = seg.slice(2);
  if (rest.length === 0 || (rest.length === 1 && rest[0] === '')) {
    if (info.method === 'GET') {
      sendJson(
        res,
        200,
        {
          current_user_url: '/api/v3/user',
          repository_url: '/api/v3/repos/{owner}/{repo}',
          issue_search_url: '/api/v3/search/issues',
          rate_limit_url: '/api/v3/rate_limit',
        },
        { 'x-oauth-scopes': 'repo, read:org', 'x-accepted-oauth-scopes': 'repo' },
      );
      return;
    }
    notFound(res);
    return;
  }
  if (!authed(info)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  if (rest[0] === 'meta' && info.method === 'GET') {
    sendJson(res, 200, { installed_version: '1.0.0-forge', verifiable_password_authentication: false });
    return;
  }
  if (rest[0] === 'user' && rest[1] === 'repos') {
    if (info.method === 'GET') {
      const all = [...state.repos.values()].sort((a, b) => a.seq - b.seq).map((repo) => repoJson(repo));
      sendJson(res, 200, paginate(info, res, all, '/api/v3/user/repos'));
      return;
    }
    if (info.method === 'POST') {
      const parsed = jsonBody(info, res);
      if (parsed === BAD_JSON) return;
      const body = asRecord(parsed);
      const name = strField(body, 'name');
      if (name === undefined || name === '') {
        sendJson(res, 422, { message: 'name is required' });
        return;
      }
      if (state.repos.has(name.toLowerCase())) {
        sendJson(res, 422, { message: 'name already exists on this account' });
        return;
      }
      const repo = createRepo(name, strField(body, 'description') ?? null, body.private === true);
      sendJson(res, 201, repoJson(repo));
      return;
    }
    notFound(res);
    return;
  }
  if (rest[0] === 'user' && info.method === 'GET') {
    sendJson(res, 200, { login: viewerLogin(), id: 1000, type: 'User' });
    return;
  }
  if (rest[0] !== 'repos' || rest.length < 3) {
    notFound(res);
    return;
  }
  const owner = rest[1] as string;
  const repoName = rest[2] as string;
  const repo = findRepo(owner, repoName);
  if (repo === null) {
    notFound(res);
    return;
  }
  const tail = rest.slice(3);
  handleRepoRoutes(info, res, repo, tail);
}

function handleRepoRoutes(info: ReqInfo, res: ServerResponse, repo: RepoRec, tail: string[]): void {
  const method = info.method;
  if (tail.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'PATCH') {
      const parsed = jsonBody(info, res);
      if (parsed === BAD_JSON) return;
      const body = asRecord(parsed);
      const description = strField(body, 'description');
      if (description !== undefined) repo.description = description;
      const name = strField(body, 'name');
      if (name !== undefined && name !== repo.name) {
        state.repos.delete(repo.name.toLowerCase());
        repo.name = name;
        state.repos.set(name.toLowerCase(), repo);
      }
      if (typeof body.private === 'boolean') repo.isPrivate = body.private;
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'DELETE') {
      state.repos.delete(repo.name.toLowerCase());
      sendJson(res, 204, undefined);
      return;
    }
    notFound(res);
    return;
  }
  if (tail[0] === 'contents') {
    handleContents(info, res, repo, tail.slice(1).join('/'));
    return;
  }
  if (tail[0] === 'branches' && method === 'GET') {
    const branches: Array<Record<string, unknown>> = [];
    for (const [ref, oid] of repo.refs) {
      if (!ref.startsWith('refs/heads/')) continue;
      branches.push({ name: ref.slice('refs/heads/'.length), commit: { sha: oid }, protected: false });
    }
    branches.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    sendJson(res, 200, branches);
    return;
  }
  if (tail[0] === 'git' && tail[1] === 'refs' && method === 'POST') {
    const parsed = jsonBody(info, res);
    if (parsed === BAD_JSON) return;
    const body = asRecord(parsed);
    const ref = strField(body, 'ref');
    const sha = strField(body, 'sha');
    if (ref === undefined || sha === undefined || !ref.startsWith('refs/')) {
      sendJson(res, 422, { message: 'ref and sha are required' });
      return;
    }
    if (repo.refs.has(ref)) {
      sendJson(res, 422, { message: 'Reference already exists' });
      return;
    }
    const target = getObject(sha);
    if (target === undefined) {
      sendJson(res, 422, { message: 'The sha does not name an object in this repository' });
      return;
    }
    repo.refs.set(ref, sha);
    sendJson(res, 201, { ref, object: { sha, type: target.type } });
    return;
  }
  if (tail[0] === 'commits' && method === 'GET') {
    const shaParam = info.query.get('sha') ?? undefined;
    let tip: string | null;
    if (shaParam !== undefined && isOid(shaParam) && getObject(shaParam)?.type === 'commit') tip = shaParam;
    else tip = branchTip(repo, shaParam).tip;
    if (tip === null) {
      sendJson(res, 200, []);
      return;
    }
    const commits = listCommitsFrom(tip).map((oid) => {
      const obj = getObject(oid) as StoredObject;
      const parsedCommit = parseCommit(obj.data);
      return {
        sha: oid,
        commit: {
          message: parsedCommit.message,
          tree: { sha: parsedCommit.tree },
          author: { name: 'Forge Bot', email: 'forge@localhost', date: isoOf(parsedCommit.committerTime || 1767225600) },
          committer: { name: 'Forge Bot', email: 'forge@localhost', date: isoOf(parsedCommit.committerTime || 1767225600) },
        },
        parents: parsedCommit.parents.map((parent) => ({ sha: parent })),
      };
    });
    sendJson(res, 200, paginate(info, res, commits, `/api/v3/repos/${viewerLogin()}/${repo.name}/commits`));
    return;
  }
  if (tail[0] === 'labels') {
    if (method === 'POST') {
      const parsed = jsonBody(info, res);
      if (parsed === BAD_JSON) return;
      const body = asRecord(parsed);
      const name = strField(body, 'name');
      if (name === undefined || name === '') {
        sendJson(res, 422, { message: 'name is required' });
        return;
      }
      if (repo.labels.has(name)) {
        sendJson(res, 422, { message: 'Label already exists' });
        return;
      }
      const label: LabelRec = {
        name,
        color: (strField(body, 'color') ?? 'ededed').replace(/^#/, ''),
        description: strField(body, 'description') ?? null,
      };
      repo.labels.set(name, label);
      sendJson(res, 201, labelJson(label));
      return;
    }
    if (method === 'GET' && tail.length === 1) {
      sendJson(res, 200, [...repo.labels.values()].map((label) => labelJson(label)));
      return;
    }
    notFound(res);
    return;
  }
  if (tail[0] === 'issues') {
    handleIssues(info, res, repo, tail.slice(1));
    return;
  }
  if (tail[0] === 'pulls') {
    handlePulls(info, res, repo, tail.slice(1));
    return;
  }
  notFound(res);
}

function handleIssues(info: ReqInfo, res: ServerResponse, repo: RepoRec, tail: string[]): void {
  const method = info.method;
  if (tail.length === 0) {
    if (method === 'POST') {
      const parsed = jsonBody(info, res);
      if (parsed === BAD_JSON) return;
      const body = asRecord(parsed);
      const title = strField(body, 'title');
      if (title === undefined || title === '') {
        sendJson(res, 422, { message: 'title is required' });
        return;
      }
      const labelNames: string[] = [];
      if (Array.isArray(body.labels)) {
        for (const raw of body.labels) {
          const name = typeof raw === 'string' ? raw : strField(asRecord(raw), 'name');
          if (name === undefined) continue;
          if (!repo.labels.has(name)) {
            sendJson(res, 422, { message: `Label "${name}" does not exist in this repository` });
            return;
          }
          labelNames.push(name);
        }
      }
      const issue = createIssueRec(repo, title, strField(body, 'body') ?? '', labelNames);
      sendJson(res, 201, issueJson(repo, issue));
      return;
    }
    if (method === 'GET') {
      const stateFilter = info.query.get('state') ?? 'open';
      let issues = [...repo.issues.values()];
      if (stateFilter === 'open') issues = issues.filter((issue) => issue.state === 'open');
      else if (stateFilter === 'closed') issues = issues.filter((issue) => issue.state === 'closed');
      const direction = info.query.get('direction') ?? 'desc';
      issues.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
      const rendered = issues.map((issue) => issueJson(repo, issue));
      sendJson(res, 200, paginate(info, res, rendered, `/api/v3/repos/${viewerLogin()}/${repo.name}/issues`));
      return;
    }
    notFound(res);
    return;
  }
  const number = Number(tail[0]);
  const issue = Number.isInteger(number) ? repo.issues.get(number) : undefined;
  if (tail.length === 1) {
    if (issue === undefined) {
      notFound(res);
      return;
    }
    if (method === 'GET') {
      sendJson(res, 200, issueJson(repo, issue));
      return;
    }
    if (method === 'PATCH') {
      const parsed = jsonBody(info, res);
      if (parsed === BAD_JSON) return;
      const body = asRecord(parsed);
      const newState = strField(body, 'state');
      if (newState === 'open' || newState === 'closed') issue.state = newState;
      const newTitle = strField(body, 'title');
      if (newTitle !== undefined) issue.title = newTitle;
      const newBody = strField(body, 'body');
      if (newBody !== undefined) issue.body = newBody;
      sendJson(res, 200, issueJson(repo, issue));
      return;
    }
    notFound(res);
    return;
  }
  if (tail[1] === 'comments') {
    if (issue === undefined) {
      notFound(res);
      return;
    }
    if (method === 'POST') {
      const parsed = jsonBody(info, res);
      if (parsed === BAD_JSON) return;
      const body = asRecord(parsed);
      const text = strField(body, 'body');
      if (text === undefined) {
        sendJson(res, 422, { message: 'body is required' });
        return;
      }
      state.dbSeq += 1;
      const comment: CommentRec = { dbId: state.dbSeq, body: text, seq: ++state.repoSeq };
      issue.comments.push(comment);
      sendJson(res, 201, {
        id: comment.dbId,
        body: comment.body,
        user: { login: viewerLogin(), id: 1000, type: 'User' },
        created_at: isoOf(1767225600 + comment.seq * 61),
        updated_at: isoOf(1767225600 + comment.seq * 61),
      });
      return;
    }
    if (method === 'GET') {
      sendJson(
        res,
        200,
        issue.comments.map((comment) => ({
          id: comment.dbId,
          body: comment.body,
          user: { login: viewerLogin(), id: 1000, type: 'User' },
          created_at: isoOf(1767225600 + comment.seq * 61),
          updated_at: isoOf(1767225600 + comment.seq * 61),
        })),
      );
      return;
    }
    notFound(res);
    return;
  }
  notFound(res);
}

function handlePulls(info: ReqInfo, res: ServerResponse, repo: RepoRec, tail: string[]): void {
  const method = info.method;
  const stripOwnerPrefix = (ref: string): string => {
    const colon = ref.indexOf(':');
    return colon === -1 ? ref : ref.slice(colon + 1);
  };
  if (tail.length === 0) {
    if (method === 'POST') {
      const parsed = jsonBody(info, res);
      if (parsed === BAD_JSON) return;
      const body = asRecord(parsed);
      const title = strField(body, 'title');
      const head = strField(body, 'head');
      const base = strField(body, 'base');
      if (title === undefined || head === undefined || base === undefined) {
        sendJson(res, 422, { message: 'title, head and base are required' });
        return;
      }
      const headRef = stripOwnerPrefix(head);
      const baseRef = stripOwnerPrefix(base);
      if (refSha(repo, headRef) === null) {
        sendJson(res, 422, { message: `Head branch "${headRef}" does not exist` });
        return;
      }
      if (refSha(repo, baseRef) === null) {
        sendJson(res, 422, { message: `Base branch "${baseRef}" does not exist` });
        return;
      }
      for (const existing of repo.pulls.values()) {
        if (existing.state === 'open' && existing.headRef === headRef && existing.baseRef === baseRef) {
          sendJson(res, 422, { message: 'A pull request already exists for this head and base' });
          return;
        }
      }
      const pull = createPullRec(repo, title, strField(body, 'body') ?? '', headRef, baseRef);
      sendJson(res, 201, pullJson(repo, pull));
      return;
    }
    if (method === 'GET') {
      const stateFilter = info.query.get('state') ?? 'open';
      let pulls = [...repo.pulls.values()];
      if (stateFilter === 'open') pulls = pulls.filter((pull) => pull.state === 'open');
      else if (stateFilter === 'closed') pulls = pulls.filter((pull) => pull.state === 'closed');
      pulls.sort((a, b) => b.number - a.number);
      const rendered = pulls.map((pull) => pullJson(repo, pull));
      sendJson(res, 200, paginate(info, res, rendered, `/api/v3/repos/${viewerLogin()}/${repo.name}/pulls`));
      return;
    }
    notFound(res);
    return;
  }
  const number = Number(tail[0]);
  const pull = Number.isInteger(number) ? repo.pulls.get(number) : undefined;
  if (pull === undefined) {
    notFound(res);
    return;
  }
  if (tail.length === 1 && method === 'GET') {
    sendJson(res, 200, pullJson(repo, pull));
    return;
  }
  if (tail.length === 2 && tail[1] === 'files' && method === 'GET') {
    sendJson(res, 200, pullFiles(repo, pull));
    return;
  }
  if (tail.length === 2 && tail[1] === 'merge' && method === 'PUT') {
    const parsed = info.body.length > 0 ? jsonBody(info, res) : {};
    if (parsed === BAD_JSON) return;
    const body = asRecord(parsed);
    if (pull.merged) {
      sendJson(res, 405, { message: 'Pull Request has already been merged' });
      return;
    }
    if (pull.state !== 'open') {
      sendJson(res, 405, { message: 'Pull Request is not open' });
      return;
    }
    const methodWanted = (strField(body, 'merge_method') ?? 'squash').toLowerCase();
    const sha = performMerge(repo, pull, methodWanted === 'merge' ? 'merge' : 'squash');
    if (sha === null) {
      sendJson(res, 405, { message: 'Pull Request is not mergeable: it has conflicts' });
      return;
    }
    sendJson(res, 200, { sha, merged: true, message: 'Pull Request successfully merged' });
    return;
  }
  notFound(res);
}

// ---------------------------------------------------------------------------
// git smart HTTP

const AGENT = 'git/forge-1.0';
const UPLOAD_CAPS_V0 = `side-band-64k ofs-delta thin-pack shallow symref=HEAD:refs/heads/main agent=${AGENT}`;
const RECEIVE_CAPS_V0 = `report-status side-band-64k delete-refs ofs-delta agent=${AGENT}`;

/** Every advertised ref of a repo, sorted, with HEAD first (pointing at the default branch). */
function advertisedRefs(repo: RepoRec): Array<{ oid: string; name: string; peeled?: string }> {
  const refs: Array<{ oid: string; name: string; peeled?: string }> = [];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  if (headOid !== undefined) refs.push({ oid: headOid, name: 'HEAD' });
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name) as string;
    const entry: { oid: string; name: string; peeled?: string } = { oid, name };
    const obj = getObject(oid);
    if (obj !== undefined && obj.type === 'tag') {
      entry.peeled = peelToCommit(oid);
    }
    refs.push(entry);
  }
  return refs;
}

function handleInfoRefs(info: ReqInfo, res: ServerResponse, repo: RepoRec, service: string): void {
  const isUpload = service === 'git-upload-pack';
  const wantsV2 = isUpload && (info.headers['git-protocol'] ?? '') === 'version=2';
  if (wantsV2) {
    const body = pktEncode([
      'version 2\n',
      `agent=${AGENT}\n`,
      'ls-refs=unborn\n',
      'fetch=shallow thin-pack ofs-delta\n',
      'object-format=sha1\n',
      'flush',
    ]);
    sendRaw(res, 200, body, 'application/x-git-upload-pack-advertisement');
    return;
  }
  const caps = isUpload ? UPLOAD_CAPS_V0 : RECEIVE_CAPS_V0;
  const lines: Pkt[] = [`# service=${service}\n`, 'flush'];
  const refs = advertisedRefs(repo);
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    refs.forEach((ref, index) => {
      lines.push(index === 0 ? `${ref.oid} ${ref.name}\0${caps}\n` : `${ref.oid} ${ref.name}\n`);
      if (ref.peeled !== undefined) lines.push(`${ref.peeled} ${ref.name}^{}\n`);
    });
  }
  lines.push('flush');
  sendRaw(res, 200, pktEncode(lines), `application/x-${service}-advertisement`);
}

/** Split a pkt data payload into its text (before any NUL) and its capability string. */
function splitCaps(payload: Buffer): { text: string; caps: string } {
  const nul = payload.indexOf(0);
  if (nul === -1) return { text: payload.toString('utf8'), caps: '' };
  return { text: payload.subarray(0, nul).toString('utf8'), caps: payload.subarray(nul + 1).toString('utf8') };
}

function handleLsRefs(info: ReqInfo, res: ServerResponse, repo: RepoRec, packets: PktPacket[]): void {
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  let inArgs = false;
  for (const packet of packets) {
    if (packet.kind === 'delim') {
      inArgs = true;
      continue;
    }
    if (packet.kind === 'flush') break;
    if (!inArgs) continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line === 'peel') peel = true;
    else if (line === 'symrefs') symrefs = true;
    else if (line === 'unborn') unborn = true;
    else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
  }
  const matches = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: Pkt[] = [];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  if (matches('HEAD')) {
    if (headOid !== undefined) {
      lines.push(symrefs ? `${headOid} HEAD symref-target:${headTarget}\n` : `${headOid} HEAD\n`);
    } else if (unborn) {
      lines.push(symrefs ? `unborn HEAD symref-target:${headTarget}\n` : 'unborn HEAD\n');
    }
  }
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    if (!matches(name)) continue;
    const oid = repo.refs.get(name) as string;
    let line = `${oid} ${name}`;
    if (peel) {
      const obj = getObject(oid);
      if (obj !== undefined && obj.type === 'tag') line += ` peeled:${peelToCommit(oid)}`;
    }
    lines.push(`${line}\n`);
  }
  lines.push('flush');
  sendRaw(res, 200, pktEncode(lines), 'application/x-git-upload-pack-result');
}

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: Set<string>;
  depth: number | null;
  deepenSince: number | null;
  deepenNot: Set<string>;
  done: boolean;
}

function parseFetchLines(lines: string[], args: FetchArgs): void {
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line === 'done') args.done = true;
    else if (line.startsWith('want ')) args.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) args.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) args.shallow.add(line.slice(8).trim());
    else if (line.startsWith('deepen-not ')) args.deepenNot.add(line.slice('deepen-not '.length).trim());
    else if (line.startsWith('deepen-since ')) {
      const value = Number(line.slice('deepen-since '.length));
      if (Number.isFinite(value)) args.deepenSince = value;
    } else if (line.startsWith('deepen ')) {
      const value = Number(line.slice('deepen '.length));
      if (Number.isFinite(value) && value > 0) args.depth = value;
    }
  }
}

function handleFetchV2(info: ReqInfo, res: ServerResponse, repo: RepoRec, packets: PktPacket[]): void {
  const args: FetchArgs = { wants: [], haves: [], shallow: new Set(), depth: null, deepenSince: null, deepenNot: new Set(), done: false };
  let inArgs = false;
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'delim') {
      inArgs = true;
      continue;
    }
    if (packet.kind === 'flush') break;
    if (inArgs && packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  parseFetchLines(lines, args);
  const plan = planFetch(args.wants, args.haves, args.shallow, args.depth, args.deepenSince, args.deepenNot);
  const ackLines: Pkt[] = ['acknowledgments\n'];
  if (plan.commonHaves.length > 0) {
    for (const have of plan.commonHaves) ackLines.push(`ACK ${have}\n`);
    ackLines.push('ready\n');
  } else {
    ackLines.push('NAK\n');
  }
  if (!args.done && plan.commonHaves.length === 0) {
    // A negotiation round with no common base yet: only the acknowledgments section goes back,
    // and the client offers more haves (or `done`) in a follow-up request.
    sendRaw(res, 200, pktEncode([...ackLines, 'flush']), 'application/x-git-upload-pack-result');
    return;
  }
  // Once a common base exists the server declares `ready`, and real git then expects the
  // shallow-info and packfile sections to follow in this same response, with or without `done`.
  const head: Pkt[] = [];
  // Real git rejects an acknowledgments section when the request carried no haves (it goes
  // straight to expecting the packfile); the section is only for have negotiation.
  if (args.haves.length > 0) {
    head.push(...ackLines, 'delim');
  }
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    head.push('shallow-info\n');
    for (const oid of plan.shallow) head.push(`shallow ${oid}\n`);
    for (const oid of plan.unshallow) head.push(`unshallow ${oid}\n`);
    head.push('delim');
  }
  const parts: Buffer[] = [];
  if (plan.packOids.length > 0) {
    head.push('packfile\n');
    parts.push(pktEncode(head), sidebandWrap(writePack(plan.packOids)), pktEncode(['flush']));
  } else {
    parts.push(pktEncode([...head, 'flush']));
  }
  sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}

function handleFetchV0(info: ReqInfo, res: ServerResponse, repo: RepoRec, packets: PktPacket[]): void {
  const args: FetchArgs = { wants: [], haves: [], shallow: new Set(), depth: null, deepenSince: null, deepenNot: new Set(), done: false };
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'data') lines.push(splitCaps(packet.payload).text);
  }
  parseFetchLines(lines, args);
  const plan = planFetch(args.wants, args.haves, args.shallow, args.depth, args.deepenSince, args.deepenNot);
  const out: Pkt[] = [];
  for (const oid of plan.shallow) out.push(`shallow ${oid}\n`);
  for (const oid of plan.unshallow) out.push(`unshallow ${oid}\n`);
  if (plan.commonHaves.length > 0) {
    for (const have of plan.commonHaves) out.push(`ACK ${have}\n`);
  } else {
    out.push('NAK\n');
  }
  const parts: Buffer[] = [pktEncode(out)];
  if (plan.packOids.length > 0) parts.push(sidebandWrap(writePack(plan.packOids)));
  parts.push(pktEncode(['flush']));
  sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
}

function handleUploadPack(info: ReqInfo, res: ServerResponse, repo: RepoRec): void {
  let packets: PktPacket[];
  try {
    packets = pktDecode(info.body);
  } catch {
    sendRaw(res, 400, Buffer.from('error: malformed pkt-line\n'), 'application/x-git-upload-pack-result');
    return;
  }
  let command = '';
  for (const packet of packets) {
    if (packet.kind === 'data') {
      const line = packet.payload.toString('utf8').replace(/\n$/, '');
      if (line.startsWith('command=')) command = line.slice('command='.length);
      break;
    }
  }
  if ((info.headers['git-protocol'] ?? '') === 'version=2' || command !== '') {
    if (command === 'ls-refs') {
      handleLsRefs(info, res, repo, packets);
      return;
    }
    if (command === 'fetch') {
      handleFetchV2(info, res, repo, packets);
      return;
    }
    sendRaw(res, 400, Buffer.from('error: unknown command\n'), 'application/x-git-upload-pack-result');
    return;
  }
  handleFetchV0(info, res, repo, packets);
}

interface PushCommandRec {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(info: ReqInfo, res: ServerResponse, repo: RepoRec): void {
  // Find the end of the pkt-line command block; the pack (if any) follows it.
  let offset = 0;
  const commands: PushCommandRec[] = [];
  let caps = '';
  let malformed = false;
  while (offset + 4 <= info.body.length) {
    const hex = info.body.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
      malformed = true;
      break;
    }
    const length = parseInt(hex, 16);
    if (length === 0) {
      offset += 4;
      break;
    }
    if (length < 4 || offset + length > info.body.length) {
      malformed = true;
      break;
    }
    const payload = info.body.subarray(offset + 4, offset + length);
    const { text, caps: lineCaps } = splitCaps(payload);
    if (caps === '') caps = lineCaps;
    const match = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(text.replace(/\n$/, ''));
    if (match) commands.push({ oldOid: match[1] as string, newOid: match[2] as string, ref: match[3] as string });
    offset += length;
  }
  if (malformed || commands.length === 0) {
    // A malformed push must not kill the server; answer an HTTP error and keep serving.
    sendRaw(res, 400, Buffer.from('error: malformed receive-pack request\n'), 'application/x-git-receive-pack-result');
    return;
  }
  const useSideband = caps.includes('side-band-64k');
  const useReport = caps.includes('report-status');
  const packBytes = info.body.subarray(offset);
  let unpackOk = true;
  if (packBytes.length > 0) {
    try {
      readPack(packBytes);
    } catch {
      unpackOk = false;
    }
  }
  const results: Array<{ ref: string; ok: boolean; reason?: string }> = [];
  if (!unpackOk) {
    for (const command of commands) results.push({ ref: command.ref, ok: false, reason: 'unpack failed' });
  } else {
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      if (command.newOid === ZERO_OID) {
        // Delete.
        if (command.ref === `refs/heads/${repo.defaultBranch}`) {
          results.push({ ref: command.ref, ok: false, reason: 'denied: cannot delete the default branch' });
          continue;
        }
        if (current !== undefined) repo.refs.delete(command.ref);
        results.push({ ref: command.ref, ok: true });
        continue;
      }
      const target = getObject(command.newOid);
      if (target === undefined) {
        results.push({ ref: command.ref, ok: false, reason: 'bad object' });
        continue;
      }
      if (current !== undefined) {
        const currentCommit = peelToCommit(current);
        const newCommit = peelToCommit(command.newOid);
        const objNew = getObject(newCommit);
        if (objNew !== undefined && objNew.type === 'commit' && currentCommit !== newCommit && !isAncestor(currentCommit, newCommit)) {
          results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
          continue;
        }
      }
      repo.refs.set(command.ref, command.newOid);
      results.push({ ref: command.ref, ok: true });
    }
  }
  if (!useReport) {
    sendRaw(res, 200, Buffer.alloc(0), 'application/x-git-receive-pack-result');
    return;
  }
  const reportLines: Pkt[] = [`unpack ${unpackOk ? 'ok' : 'index-pack failed'}\n`];
  for (const result of results) {
    reportLines.push(result.ok ? `ok ${result.ref}\n` : `ng ${result.ref} ${result.reason ?? 'rejected'}\n`);
  }
  reportLines.push('flush');
  const report = pktEncode(reportLines);
  const body = useSideband ? Buffer.concat([sidebandWrap(report), pktEncode(['flush'])]) : report;
  sendRaw(res, 200, body, 'application/x-git-receive-pack-result');
}

/** Route /{owner}/{repo}.git/... — the repo must exist (a push cannot invent one). */
function handleGit(info: ReqInfo, res: ServerResponse): void {
  const seg = info.segments;
  const repoName = (seg[1] as string).replace(/\.git$/, '');
  const repo = findRepo(seg[0] as string, repoName);
  if (repo === null) {
    notFound(res);
    return;
  }
  const tail = seg.slice(2).join('/');
  if (tail === 'info/refs' && info.method === 'GET') {
    const service = info.query.get('service') ?? '';
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      sendJson(res, 400, { message: 'Missing or unknown service' });
      return;
    }
    handleInfoRefs(info, res, repo, service);
    return;
  }
  if (tail === 'git-upload-pack' && info.method === 'POST') {
    handleUploadPack(info, res, repo);
    return;
  }
  if (tail === 'git-receive-pack' && info.method === 'POST') {
    handleReceivePack(info, res, repo);
    return;
  }
  notFound(res);
}

// ---------------------------------------------------------------------------
// GraphQL v4: a small parser and executor for the document shapes gh sends

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'string'; value: string }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlSelection {
  alias: string | null;
  name: string;
  args: Map<string, GqlValue>;
  selectionSet: GqlSelection[] | null;
  fragmentSpread: string | null;
  inlineOn: string | null;
}

interface GqlOperation {
  type: 'query' | 'mutation';
  name: string | null;
  selectionSet: GqlSelection[];
}

interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, { on: string; selectionSet: GqlSelection[] }>;
}

function tokenizeGql(source: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',' || ch === '﻿') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (source.startsWith('...', i)) {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}()[]:=!$@|&'.includes(ch)) {
      tokens.push(ch);
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (source.startsWith('"""', i)) {
        const end = source.indexOf('"""', i + 3);
        const raw = source.slice(i + 3, end === -1 ? source.length : end);
        tokens.push(`"${raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`);
        i = end === -1 ? source.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          out += source[j] + (source[j + 1] as string);
          j += 2;
        } else {
          out += source[j];
          j += 1;
        }
      }
      tokens.push(`"${out}"`);
      i = j + 1;
      continue;
    }
    const match = /^[A-Za-z0-9_.-]+/.exec(source.slice(i));
    if (match) {
      tokens.push(match[0]);
      i += match[0].length;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = tokenizeGql(source);
  }

  private peek(): string | undefined {
    return this.tokens[this.pos];
  }

  private next(): string {
    const token = this.tokens[this.pos];
    this.pos += 1;
    if (token === undefined) throw new Error('unexpected end of GraphQL document');
    return token;
  }

  private expect(token: string): void {
    const got = this.next();
    if (got !== token) throw new Error(`expected ${token}, found ${got}`);
  }

  private skipBalanced(open: string, close: string): void {
    this.expect(open);
    let depth = 1;
    while (depth > 0) {
      const token = this.next();
      if (token === open) depth += 1;
      else if (token === close) depth -= 1;
    }
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, { on: string; selectionSet: GqlSelection[] }>();
    while (this.pos < this.tokens.length) {
      const token = this.peek();
      if (token === 'query' || token === 'mutation' || token === 'subscription') {
        this.next();
        let name: string | null = null;
        const maybeName = this.peek();
        if (maybeName !== undefined && maybeName !== '(' && maybeName !== '{' && maybeName !== '@') name = this.next();
        if (this.peek() === '(') this.skipBalanced('(', ')');
        while (this.peek() === '@') {
          this.next();
          this.next();
          if (this.peek() === '(') this.skipBalanced('(', ')');
        }
        const selectionSet = this.parseSelectionSet();
        operations.push({ type: token === 'mutation' ? 'mutation' : 'query', name, selectionSet });
      } else if (token === 'fragment') {
        this.next();
        const fragName = this.next();
        this.expect('on');
        const on = this.next();
        const selectionSet = this.parseSelectionSet();
        fragments.set(fragName, { on, selectionSet });
      } else if (token === '{') {
        operations.push({ type: 'query', name: null, selectionSet: this.parseSelectionSet() });
      } else {
        this.next();
      }
    }
    return { operations, fragments };
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const selections: GqlSelection[] = [];
    while (this.peek() !== '}') {
      if (this.peek() === undefined) throw new Error('unterminated selection set');
      selections.push(this.parseSelection());
    }
    this.expect('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    if (this.peek() === '...') {
      this.next();
      if (this.peek() === 'on') {
        this.next();
        const on = this.next();
        const selectionSet = this.parseSelectionSet();
        return { alias: null, name: '', args: new Map(), selectionSet, fragmentSpread: null, inlineOn: on };
      }
      const spread = this.next();
      return { alias: null, name: '', args: new Map(), selectionSet: null, fragmentSpread: spread, inlineOn: null };
    }
    let name = this.next();
    let alias: string | null = null;
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    const args = new Map<string, GqlValue>();
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')') {
        const argName = this.next();
        this.expect(':');
        args.set(argName, this.parseValue());
      }
      this.expect(')');
    }
    while (this.peek() === '@') {
      this.next();
      this.next();
      if (this.peek() === '(') this.skipBalanced('(', ')');
    }
    let selectionSet: GqlSelection[] | null = null;
    if (this.peek() === '{') selectionSet = this.parseSelectionSet();
    return { alias, name, args, selectionSet, fragmentSpread: null, inlineOn: null };
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token === '$') return { kind: 'variable', name: this.next() };
    if (token === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']') values.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', values };
    }
    if (token === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (this.peek() !== '}') {
        const name = this.next();
        this.expect(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expect('}');
      return { kind: 'object', fields };
    }
    if (token.startsWith('"')) {
      return { kind: 'string', value: JSON.parse(token) as string };
    }
    if (token === 'true' || token === 'false') return { kind: 'boolean', value: token === 'true' };
    if (token === 'null') return { kind: 'null' };
    if (/^-?\d+$/.test(token)) return { kind: 'int', value: Number(token) };
    if (/^-?\d*\.\d+/.test(token)) return { kind: 'float', value: Number(token) };
    return { kind: 'enum', value: token };
  }
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable':
      return variables[value.name];
    case 'int':
    case 'float':
    case 'string':
    case 'boolean':
    case 'enum':
      return value.value;
    case 'null':
      return null;
    case 'list':
      return value.values.map((entry) => resolveGqlValue(entry, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = resolveGqlValue(field.value, variables);
      return out;
    }
  }
}

// --- GraphQL sources and global ids

/** Global (Relay) id: base64 of `Type:part[:part]`, opaque and stable. */
function globalId(type: string, ...parts: Array<string | number>): string {
  return Buffer.from(`${type}:${parts.join(':')}`, 'utf8').toString('base64');
}

function parseGlobalId(id: string): { type: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const parts = text.split(':');
    const type = parts.shift();
    if (type === undefined || type === '') return null;
    return { type, parts };
  } catch {
    return null;
  }
}

function repoByDbId(dbId: number): RepoRec | null {
  for (const repo of state.repos.values()) if (repo.dbId === dbId) return repo;
  return null;
}

type GqlSource =
  | { gqlType: 'User' }
  | { gqlType: 'Repository'; repo: RepoRec }
  | { gqlType: 'Issue'; repo: RepoRec; issue: IssueRec }
  | { gqlType: 'PullRequest'; repo: RepoRec; pull: PullRec }
  | { gqlType: 'IssueComment'; repo: RepoRec; issue: IssueRec; comment: CommentRec }
  | { gqlType: 'Ref'; name: string }
  | { gqlType: 'IssueConnection'; nodes: GqlSource[]; pageInfo: Record<string, unknown>; totalCount: number }
  | { gqlType: 'PullRequestConnection'; nodes: GqlSource[]; pageInfo: Record<string, unknown>; totalCount: number }
  | { gqlType: 'PullRequestChangedFile'; path: string; additions: number; deletions: number }
  | { gqlType: 'PullRequestFileConnection'; nodes: GqlSource[] }
  | { gqlType: '__Type'; typeName: string }
  | { gqlType: '__Field'; fieldName: string }
  | { gqlType: '__EnumValue'; enumName: string }
  | { gqlType: 'CreateIssuePayload'; issue: GqlSource | null }
  | { gqlType: 'CloseIssuePayload'; issue: GqlSource | null }
  | { gqlType: 'CreatePullRequestPayload'; pull: GqlSource | null }
  | { gqlType: 'MergePullRequestPayload'; pull: GqlSource | null }
  | { gqlType: 'AddCommentPayload'; comment: GqlSource | null }
  | { gqlType: 'CommentEdge'; node: GqlSource | null };

const SCHEMA_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', 'user', 'organization', 'search', '__type', '__schema'],
  Mutation: [
    'createIssue',
    'closeIssue',
    'reopenIssue',
    'createPullRequest',
    'mergePullRequest',
    'addComment',
    'updateIssue',
    'updatePullRequest',
  ],
  User: ['id', 'databaseId', 'login', 'name', 'url', 'email', 'repositories', 'issues', 'pullRequests', 'createdAt', 'updatedAt'],
  Repository: [
    'id',
    'databaseId',
    'name',
    'nameWithOwner',
    'owner',
    'description',
    'isPrivate',
    'isFork',
    'url',
    'homepageUrl',
    'defaultBranchRef',
    'viewerPermission',
    'hasIssuesEnabled',
    'hasPullRequestsEnabled',
    'issue',
    'issues',
    'pullRequest',
    'pullRequests',
    'createdAt',
    'updatedAt',
    'refs',
    'stargazerCount',
    'forkCount',
  ],
  Issue: [
    'id',
    'databaseId',
    'number',
    'title',
    'state',
    'body',
    'bodyText',
    'bodyHTML',
    'url',
    'author',
    'repository',
    'labels',
    'comments',
    'assignees',
    'createdAt',
    'updatedAt',
    'closedAt',
    'locked',
  ],
  PullRequest: [
    'id',
    'databaseId',
    'number',
    'title',
    'body',
    'bodyText',
    'state',
    'merged',
    'mergedAt',
    'mergeable',
    'headRefName',
    'baseRefName',
    'headRef',
    'baseRef',
    'headRefOid',
    'baseRefOid',
    'mergeCommit',
    'files',
    'commits',
    'comments',
    'author',
    'repository',
    'additions',
    'deletions',
    'changedFiles',
    'createdAt',
    'updatedAt',
    'closedAt',
    'url',
    'isDraft',
  ],
  IssueComment: ['id', 'databaseId', 'body', 'bodyText', 'author', 'createdAt', 'updatedAt', 'url'],
  Ref: ['id', 'name', 'prefix', 'target', 'repository'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'additions', 'deletions'],
  PullRequestFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId'],
  CommentEdge: ['node', 'cursor'],
  __Type: ['kind', 'name', 'description', 'fields', 'enumValues', 'possibleTypes', 'inputFields', 'interfaces', 'ofType'],
  __Field: ['name', 'description', 'args', 'type', 'isDeprecated', 'deprecationReason'],
  __EnumValue: ['name', 'description', 'isDeprecated', 'deprecationReason'],
  __InputValue: ['name', 'description', 'type', 'defaultValue'],
};

const SCHEMA_ENUMS: Record<string, string[]> = {
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
  DefaultPeriod: [],
};

function cursorOf(index: number): string {
  return Buffer.from(`cursor:${index}`, 'utf8').toString('base64');
}

function indexOfCursor(cursor: unknown): number {
  if (typeof cursor !== 'string' || cursor === '') return -1;
  const text = Buffer.from(cursor, 'base64').toString('utf8');
  const match = /^cursor:(\d+)$/.exec(text);
  return match ? Number(match[1]) : -1;
}

interface GqlCtx {
  variables: Record<string, unknown>;
  fragments: Map<string, { on: string; selectionSet: GqlSelection[] }>;
  errors: Array<{ message: string }>;
}

function argOf(selection: GqlSelection, ctx: GqlCtx, name: string): unknown {
  const value = selection.args.get(name);
  return value === undefined ? undefined : resolveGqlValue(value, ctx.variables);
}

function repoSource(repo: RepoRec): GqlSource {
  return { gqlType: 'Repository', repo };
}

function issueSource(repo: RepoRec, issue: IssueRec): GqlSource {
  return { gqlType: 'Issue', repo, issue };
}

function pullSource(repo: RepoRec, pull: PullRec): GqlSource {
  return { gqlType: 'PullRequest', repo, pull };
}

function sourceId(source: GqlSource): string {
  switch (source.gqlType) {
    case 'User':
      return globalId('User', 1000);
    case 'Repository':
      return globalId('Repository', source.repo.dbId);
    case 'Issue':
      return globalId('Issue', source.repo.dbId, source.issue.number);
    case 'PullRequest':
      return globalId('PullRequest', source.repo.dbId, source.pull.number);
    case 'IssueComment':
      return globalId('IssueComment', source.comment.dbId);
    case 'Ref':
      return globalId('Ref', source.name);
    default:
      return globalId(source.gqlType, 1);
  }
}

/** Decode a global id back to its source (for node(id:) and mutation inputs). */
function sourceFromGlobalId(id: string): GqlSource | null {
  const parsed = parseGlobalId(id);
  if (parsed === null) return null;
  if (parsed.type === 'Repository') {
    const repo = repoByDbId(Number(parsed.parts[0]));
    return repo === null ? null : repoSource(repo);
  }
  if (parsed.type === 'Issue') {
    const repo = repoByDbId(Number(parsed.parts[0]));
    const issue = repo?.issues.get(Number(parsed.parts[1]));
    return repo !== null && repo !== undefined && issue !== undefined ? issueSource(repo, issue) : null;
  }
  if (parsed.type === 'PullRequest') {
    const repo = repoByDbId(Number(parsed.parts[0]));
    const pull = repo?.pulls.get(Number(parsed.parts[1]));
    return repo !== null && repo !== undefined && pull !== undefined ? pullSource(repo, pull) : null;
  }
  if (parsed.type === 'User') return { gqlType: 'User' };
  return null;
}

function issueConnection(repo: RepoRec, selection: GqlSelection, ctx: GqlCtx): GqlSource {
  let issues = [...repo.issues.values()];
  const states = argOf(selection, ctx, 'states');
  if (Array.isArray(states)) {
    const wanted = states.map((entry) => String(entry).toLowerCase());
    issues = issues.filter((issue) => wanted.includes(issue.state));
  }
  const orderBy = argOf(selection, ctx, 'orderBy');
  let descending = false;
  if (typeof orderBy === 'object' && orderBy !== null) {
    descending = (orderBy as Record<string, unknown>).direction === 'DESC';
  }
  issues.sort((a, b) => (descending ? b.number - a.number : a.number - b.number));
  const after = argOf(selection, ctx, 'after');
  const startIndex = Math.max(0, indexOfCursor(after) + 1);
  const firstRaw = argOf(selection, ctx, 'first');
  const first = typeof firstRaw === 'number' ? firstRaw : 30;
  const slice = issues.slice(startIndex, startIndex + first);
  const hasNext = startIndex + slice.length < issues.length;
  const pageInfo: Record<string, unknown> = {
    hasNextPage: hasNext,
    hasPreviousPage: startIndex > 0,
    startCursor: slice.length > 0 ? cursorOf(startIndex) : null,
    endCursor: slice.length > 0 ? cursorOf(startIndex + slice.length - 1) : null,
  };
  return {
    gqlType: 'IssueConnection',
    nodes: slice.map((issue) => issueSource(repo, issue)),
    pageInfo,
    totalCount: issues.length,
  };
}

function pullConnection(repo: RepoRec, selection: GqlSelection, ctx: GqlCtx): GqlSource {
  let pulls = [...repo.pulls.values()];
  const states = argOf(selection, ctx, 'states');
  if (Array.isArray(states)) {
    const wanted = states.map((entry) => String(entry));
    pulls = pulls.filter((pull) => {
      const gqlState = pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
      return wanted.includes(gqlState);
    });
  } else {
    pulls = pulls.filter((pull) => pull.state === 'open');
  }
  pulls.sort((a, b) => b.number - a.number);
  const after = argOf(selection, ctx, 'after');
  const startIndex = Math.max(0, indexOfCursor(after) + 1);
  const firstRaw = argOf(selection, ctx, 'first');
  const first = typeof firstRaw === 'number' ? firstRaw : 30;
  const slice = pulls.slice(startIndex, startIndex + first);
  const pageInfo: Record<string, unknown> = {
    hasNextPage: startIndex + slice.length < pulls.length,
    hasPreviousPage: startIndex > 0,
    startCursor: slice.length > 0 ? cursorOf(startIndex) : null,
    endCursor: slice.length > 0 ? cursorOf(startIndex + slice.length - 1) : null,
  };
  return {
    gqlType: 'PullRequestConnection',
    nodes: slice.map((pull) => pullSource(repo, pull)),
    pageInfo,
    totalCount: pulls.length,
  };
}

type GqlRaw = unknown;

/** Resolve one field on one source. Returns a scalar, a source, an array of either, or null. */
function resolveGqlField(typeName: string, source: GqlSource | null, selection: GqlSelection, ctx: GqlCtx): GqlRaw {
  const name = selection.name;
  if (name === '__typename') return source?.gqlType ?? typeName;
  if (typeName === 'Query') {
    if (name === 'viewer') return { gqlType: 'User' } as GqlSource;
    if (name === 'repository') {
      const owner = String(argOf(selection, ctx, 'owner') ?? '');
      const repoName = String(argOf(selection, ctx, 'name') ?? '');
      if (state.login === null) learnLogin(owner);
      if (owner !== viewerLogin()) return null;
      const repo = state.repos.get(repoName.toLowerCase());
      return repo === undefined ? null : repoSource(repo);
    }
    if (name === 'node') {
      const id = String(argOf(selection, ctx, 'id') ?? '');
      return sourceFromGlobalId(id);
    }
    if (name === '__type') {
      const typeArg = String(argOf(selection, ctx, 'name') ?? '');
      if (SCHEMA_FIELDS[typeArg] !== undefined || SCHEMA_ENUMS[typeArg] !== undefined || typeArg === 'PageInfo') {
        return { gqlType: '__Type', typeName: typeArg } as GqlSource;
      }
      return null;
    }
    if (name === 'user') return { gqlType: 'User' } as GqlSource;
    return undefined;
  }
  if (typeName === 'Mutation') return resolveGqlMutation(name, selection, ctx);
  if (source === null) return null;
  switch (source.gqlType) {
    case 'User':
      if (name === 'login') return viewerLogin();
      if (name === 'id') return sourceId(source);
      if (name === 'databaseId') return 1000;
      if (name === 'name') return viewerLogin();
      return null;
    case 'Repository': {
      const repo = source.repo;
      switch (name) {
        case 'id': return sourceId(source);
        case 'databaseId': return repo.dbId;
        case 'name': return repo.name;
        case 'nameWithOwner': return `${viewerLogin()}/${repo.name}`;
        case 'owner': return { gqlType: 'User' } as GqlSource;
        case 'description': return repo.description;
        case 'isPrivate': return repo.isPrivate;
        case 'isFork': return false;
        case 'url': return `http://forge.local/${viewerLogin()}/${repo.name}`;
        case 'homepageUrl': return null;
        case 'defaultBranchRef': return { gqlType: 'Ref', name: repo.defaultBranch } as GqlSource;
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': return true;
        case 'hasPullRequestsEnabled': return true;
        case 'stargazerCount': return 0;
        case 'forkCount': return 0;
        case 'createdAt':
        case 'updatedAt': return isoOf(1767225600 + repo.seq * 61);
        case 'issue': {
          const number = Number(argOf(selection, ctx, 'number'));
          const issue = repo.issues.get(number);
          return issue === undefined ? null : issueSource(repo, issue);
        }
        case 'issues': return issueConnection(repo, selection, ctx);
        case 'pullRequest': {
          const number = Number(argOf(selection, ctx, 'number'));
          const pull = repo.pulls.get(number);
          return pull === undefined ? null : pullSource(repo, pull);
        }
        case 'pullRequests': return pullConnection(repo, selection, ctx);
        default: return null;
      }
    }
    case 'Issue': {
      const { issue } = source;
      switch (name) {
        case 'id': return sourceId(source);
        case 'databaseId': return issue.dbId;
        case 'number': return issue.number;
        case 'title': return issue.title;
        case 'state': return issue.state === 'open' ? 'OPEN' : 'CLOSED';
        case 'body':
        case 'bodyText': return issue.body;
        case 'bodyHTML': return issue.body;
        case 'url': return `http://forge.local/${viewerLogin()}/${source.repo.name}/issues/${issue.number}`;
        case 'author': return { gqlType: 'User' } as GqlSource;
        case 'repository': return repoSource(source.repo);
        case 'createdAt':
        case 'updatedAt': return isoOf(1767225600 + issue.seq * 61);
        case 'closedAt': return issue.state === 'closed' ? isoOf(1767225600 + issue.seq * 61) : null;
        case 'locked': return false;
        default: return null;
      }
    }
    case 'PullRequest': {
      const { pull, repo } = source;
      switch (name) {
        case 'id': return sourceId(source);
        case 'databaseId': return pull.dbId;
        case 'number': return pull.number;
        case 'title': return pull.title;
        case 'body':
        case 'bodyText': return pull.body;
        case 'state': return pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
        case 'merged': return pull.merged;
        case 'mergedAt': return pull.merged ? isoOf(1767225600 + pull.seq * 61) : null;
        case 'mergeable': {
          if (pull.state !== 'open') return 'UNKNOWN';
          return mergeSimulation(repo, pull).conflict ? 'CONFLICTING' : 'MERGEABLE';
        }
        case 'headRefName': return pull.headRef;
        case 'baseRefName': return pull.baseRef;
        case 'headRef': return { gqlType: 'Ref', name: pull.headRef } as GqlSource;
        case 'baseRef': return { gqlType: 'Ref', name: pull.baseRef } as GqlSource;
        case 'headRefOid': return refSha(repo, pull.headRef) ?? ZERO_OID;
        case 'baseRefOid': return refSha(repo, pull.baseRef) ?? ZERO_OID;
        case 'mergeCommit': return null;
        case 'author': return { gqlType: 'User' } as GqlSource;
        case 'repository': return repoSource(repo);
        case 'createdAt':
        case 'updatedAt': return isoOf(1767225600 + pull.seq * 61);
        case 'closedAt': return pull.state === 'closed' ? isoOf(1767225600 + pull.seq * 61) : null;
        case 'url': return `http://forge.local/${viewerLogin()}/${repo.name}/pull/${pull.number}`;
        case 'isDraft': return false;
        case 'files': {
          const files = pullFiles(repo, pull);
          const firstRaw = argOf(selection, ctx, 'first');
          const first = typeof firstRaw === 'number' ? firstRaw : 100;
          return {
            gqlType: 'PullRequestFileConnection',
            nodes: files.slice(0, first).map((file) => ({
              gqlType: 'PullRequestChangedFile',
              path: String(file.filename),
              additions: Number(file.additions),
              deletions: Number(file.deletions),
            })),
          } as GqlSource;
        }
        case 'additions': return pullFiles(repo, pull).reduce((sum, file) => sum + Number(file.additions), 0);
        case 'deletions': return pullFiles(repo, pull).reduce((sum, file) => sum + Number(file.deletions), 0);
        case 'changedFiles': return pullFiles(repo, pull).length;
        default: return null;
      }
    }
    case 'IssueComment':
      switch (name) {
        case 'id': return sourceId(source);
        case 'databaseId': return source.comment.dbId;
        case 'body':
        case 'bodyText': return source.comment.body;
        case 'author': return { gqlType: 'User' } as GqlSource;
        case 'createdAt':
        case 'updatedAt': return isoOf(1767225600 + source.comment.seq * 61);
        case 'url': return `http://forge.local/${viewerLogin()}/${source.repo.name}/issues/${source.issue.number}`;
        default: return null;
      }
    case 'Ref':
      if (name === 'name') return source.name;
      if (name === 'prefix') return 'refs/heads/';
      if (name === 'id') return sourceId(source);
      return null;
    case 'IssueConnection':
    case 'PullRequestConnection':
      if (name === 'nodes') return source.nodes;
      if (name === 'totalCount') return source.totalCount;
      if (name === 'pageInfo') return source.pageInfo;
      if (name === 'edges') {
        return source.nodes.map((node, index) => ({ node, cursor: cursorOf(index) }));
      }
      return null;
    case 'PullRequestFileConnection':
      if (name === 'nodes') return source.nodes;
      if (name === 'totalCount') return source.nodes.length;
      if (name === 'pageInfo') return { hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null };
      return null;
    case 'PullRequestChangedFile':
      if (name === 'path') return source.path;
      if (name === 'additions') return source.additions;
      if (name === 'deletions') return source.deletions;
      return null;
    case '__Type': {
      const fields = SCHEMA_FIELDS[source.typeName];
      const enums = SCHEMA_ENUMS[source.typeName];
      if (name === 'kind') return enums !== undefined ? 'ENUM' : 'OBJECT';
      if (name === 'name') return source.typeName;
      if (name === 'description') return null;
      if (name === 'fields') {
        return (fields ?? []).map((fieldName) => ({ gqlType: '__Field', fieldName }) as GqlSource);
      }
      if (name === 'enumValues') {
        return (enums ?? []).map((enumName) => ({ gqlType: '__EnumValue', enumName }) as GqlSource);
      }
      if (name === 'possibleTypes' || name === 'interfaces' || name === 'inputFields') return [];
      return null;
    }
    case '__Field':
      if (name === 'name') return source.fieldName;
      if (name === 'description') return null;
      if (name === 'isDeprecated') return false;
      if (name === 'args') return [];
      return null;
    case '__EnumValue':
      if (name === 'name') return source.enumName;
      if (name === 'description') return null;
      if (name === 'isDeprecated') return false;
      return null;
    case 'CreateIssuePayload':
    case 'CloseIssuePayload':
      if (name === 'issue') return source.issue;
      if (name === 'clientMutationId') return null;
      return null;
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload':
      if (name === 'pullRequest') return source.pull;
      if (name === 'clientMutationId') return null;
      return null;
    case 'AddCommentPayload':
      if (name === 'commentEdge') return { gqlType: 'CommentEdge', node: source.comment } as GqlSource;
      if (name === 'clientMutationId') return null;
      if (name === 'subject') return source.comment && source.comment.gqlType === 'IssueComment' ? issueSource(source.comment.repo, source.comment.issue) : null;
      return null;
    case 'CommentEdge':
      if (name === 'node') return source.node;
      if (name === 'cursor') return cursorOf(0);
      return null;
    default:
      return null;
  }
}

function resolveGqlMutation(name: string, selection: GqlSelection, ctx: GqlCtx): GqlRaw {
  const input = asRecord(argOf(selection, ctx, 'input'));
  if (name === 'createIssue') {
    const repoSourceFound = typeof input.repositoryId === 'string' ? sourceFromGlobalId(input.repositoryId) : null;
    if (repoSourceFound === null || repoSourceFound.gqlType !== 'Repository') {
      ctx.errors.push({ message: 'Could not resolve the repository for createIssue' });
      return { gqlType: 'CreateIssuePayload', issue: null } as GqlSource;
    }
    const repo = repoSourceFound.repo;
    const issue = createIssueRec(repo, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '', []);
    return { gqlType: 'CreateIssuePayload', issue: issueSource(repo, issue) } as GqlSource;
  }
  if (name === 'closeIssue') {
    const found = typeof input.issueId === 'string' ? sourceFromGlobalId(input.issueId) : null;
    if (found === null || found.gqlType !== 'Issue') {
      ctx.errors.push({ message: 'Could not resolve the issue for closeIssue' });
      return { gqlType: 'CloseIssuePayload', issue: null } as GqlSource;
    }
    found.issue.state = 'closed';
    return { gqlType: 'CloseIssuePayload', issue: issueSource(found.repo, found.issue) } as GqlSource;
  }
  if (name === 'createPullRequest') {
    const repoSourceFound = typeof input.repositoryId === 'string' ? sourceFromGlobalId(input.repositoryId) : null;
    if (repoSourceFound === null || repoSourceFound.gqlType !== 'Repository') {
      ctx.errors.push({ message: 'Could not resolve the repository for createPullRequest' });
      return { gqlType: 'CreatePullRequestPayload', pull: null } as GqlSource;
    }
    const repo = repoSourceFound.repo;
    const headRef = String(input.headRefName ?? '');
    const baseRef = String(input.baseRefName ?? '');
    if (refSha(repo, headRef) === null || refSha(repo, baseRef) === null) {
      ctx.errors.push({ message: 'Head or base branch does not exist' });
      return { gqlType: 'CreatePullRequestPayload', pull: null } as GqlSource;
    }
    const pull = createPullRec(repo, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '', headRef, baseRef);
    return { gqlType: 'CreatePullRequestPayload', pull: pullSource(repo, pull) } as GqlSource;
  }
  if (name === 'mergePullRequest') {
    const found = typeof input.pullRequestId === 'string' ? sourceFromGlobalId(input.pullRequestId) : null;
    if (found === null || found.gqlType !== 'PullRequest') {
      ctx.errors.push({ message: 'Could not resolve the pull request for mergePullRequest' });
      return { gqlType: 'MergePullRequestPayload', pull: null } as GqlSource;
    }
    const method = String(input.mergeMethod ?? 'SQUASH').toUpperCase();
    const sha = performMerge(found.repo, found.pull, method === 'MERGE' ? 'merge' : 'squash');
    if (sha === null) {
      ctx.errors.push({ message: 'Pull request is not mergeable' });
      return { gqlType: 'MergePullRequestPayload', pull: null } as GqlSource;
    }
    return { gqlType: 'MergePullRequestPayload', pull: pullSource(found.repo, found.pull) } as GqlSource;
  }
  if (name === 'addComment') {
    const found = typeof input.subjectId === 'string' ? sourceFromGlobalId(input.subjectId) : null;
    if (found === null || found.gqlType !== 'Issue') {
      ctx.errors.push({ message: 'Could not resolve the subject for addComment' });
      return { gqlType: 'AddCommentPayload', comment: null } as GqlSource;
    }
    state.dbSeq += 1;
    const comment: CommentRec = { dbId: state.dbSeq, body: String(input.body ?? ''), seq: ++state.repoSeq };
    found.issue.comments.push(comment);
    return {
      gqlType: 'AddCommentPayload',
      comment: { gqlType: 'IssueComment', repo: found.repo, issue: found.issue, comment } as GqlSource,
    } as GqlSource;
  }
  return undefined;
}

/** Execute a selection set against a typed source; returns the JSON-shaped data object. */
function executeSelectionSet(typeName: string, source: GqlSource | null, selections: GqlSelection[], ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.inlineOn !== null) {
      if (source !== null && (source.gqlType === selection.inlineOn || selection.inlineOn === 'Node')) {
        Object.assign(out, executeSelectionSet(source.gqlType, source, selection.selectionSet ?? [], ctx));
      }
      continue;
    }
    if (selection.fragmentSpread !== null) {
      const fragment = ctx.fragments.get(selection.fragmentSpread);
      if (fragment !== undefined && source !== null && (source.gqlType === fragment.on || fragment.on === 'Node')) {
        Object.assign(out, executeSelectionSet(source.gqlType, source, fragment.selectionSet, ctx));
      }
      continue;
    }
    const key = selection.alias ?? selection.name;
    const knownFields = SCHEMA_FIELDS[typeName];
    if (selection.name !== '__typename' && knownFields !== undefined && !knownFields.includes(selection.name)) {
      ctx.errors.push({ message: `Field '${selection.name}' doesn't exist on type '${typeName}'` });
      out[key] = null;
      continue;
    }
    const raw = resolveGqlField(typeName, source, selection, ctx);
    if (raw === undefined) {
      ctx.errors.push({ message: `Field '${selection.name}' doesn't exist on type '${typeName}'` });
      out[key] = null;
      continue;
    }
    out[key] = completeGqlValue(raw, selection, ctx);
  }
  return out;
}

function completeGqlValue(raw: GqlRaw, selection: GqlSelection, ctx: GqlCtx): unknown {
  if (raw === null || raw === undefined) return null;
  if (Array.isArray(raw)) return raw.map((entry) => completeGqlValue(entry, selection, ctx));
  if (typeof raw === 'object' && raw !== null && 'gqlType' in raw) {
    const source = raw as GqlSource;
    if (selection.selectionSet === null) return sourceId(source);
    return executeSelectionSet(source.gqlType, source, selection.selectionSet, ctx);
  }
  if (typeof raw === 'object') {
    // A plain value object (pageInfo): project the requested subfields.
    if (selection.selectionSet === null) return raw;
    const record = raw as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const sub of selection.selectionSet) {
      out[sub.alias ?? sub.name] = completeGqlValue(record[sub.name] ?? null, sub, ctx);
    }
    return out;
  }
  return raw;
}

function executeGqlOperation(operation: GqlOperation, doc: GqlDocument, variables: Record<string, unknown>): Record<string, unknown> {
  const ctx: GqlCtx = { variables, fragments: doc.fragments, errors: [] };
  const rootType = operation.type === 'mutation' ? 'Mutation' : 'Query';
  const data = executeSelectionSet(rootType, null, operation.selectionSet, ctx);
  const result: Record<string, unknown> = { data };
  if (ctx.errors.length > 0) result.errors = ctx.errors.map((error) => ({ message: error.message, type: 'VALIDATION' }));
  return result;
}

function handleGraphql(info: ReqInfo, res: ServerResponse): void {
  if (info.method !== 'POST') {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  if (!authed(info)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(info.body.toString('utf8'));
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    const record = asRecord(entry);
    const query = strField(record, 'query');
    if (query === undefined) return { errors: [{ message: 'No query string supplied' }] };
    const variables = asRecord(record.variables);
    let doc: GqlDocument;
    try {
      doc = new GqlParser(query).parseDocument();
    } catch (err) {
      return { errors: [{ message: err instanceof Error ? err.message : 'Could not parse the query' }] };
    }
    if (doc.operations.length === 0) return { errors: [{ message: 'No operation found in the document' }] };
    const operationName = strField(record, 'operationName');
    const operation = (operationName !== undefined ? doc.operations.find((op) => op.name === operationName) : undefined) ?? doc.operations[0] as GqlOperation;
    return executeGqlOperation(operation, doc, variables);
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map((entry) => runOne(entry)));
    return;
  }
  sendJson(res, 200, runOne(parsed));
}

// ---------------------------------------------------------------------------
// MCP (streamable HTTP, JSON-RPC 2.0)

const MCP_SERVER_INFO = { name: 'forge-mcp', version: '1.0.0' };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'];

interface McpToolDef {
  name: string;
  description: string;
  properties: Record<string, { type: string; description: string }>;
  required: string[];
}

const MCP_TOOL_DEFS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    properties: {
      name: { type: 'string', description: 'The repository name.' },
      description: { type: 'string', description: 'A short description of the repository.' },
      private: { type: 'boolean', description: 'Whether the repository is private.' },
    },
    required: ['name'],
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The issue title.' },
      body: { type: 'string', description: 'The issue body.' },
    },
    required: ['owner', 'repo', 'title'],
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository, optionally filtered by state.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      state: { type: 'string', description: 'Filter by state: open, closed or all.' },
    },
    required: ['owner', 'repo'],
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      title: { type: 'string', description: 'The pull request title.' },
      body: { type: 'string', description: 'The pull request body.' },
      head: { type: 'string', description: 'The head branch name.' },
      base: { type: 'string', description: 'The base branch name.' },
    },
    required: ['owner', 'repo', 'title', 'head', 'base'],
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request by number (squash).',
    properties: {
      owner: { type: 'string', description: 'The repository owner login.' },
      repo: { type: 'string', description: 'The repository name.' },
      pull_number: { type: 'number', description: 'The pull request number.' },
    },
    required: ['owner', 'repo', 'pull_number'],
  },
];

/** The tools/list payload, built once so repeated calls are byte-identical. */
const MCP_TOOLS_JSON: unknown = MCP_TOOL_DEFS.map((def) => ({
  name: def.name,
  description: def.description,
  inputSchema: {
    type: 'object',
    properties: def.properties,
    required: def.required,
    additionalProperties: false,
  },
}));

function mcpToolResult(value: unknown): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: JSON.stringify(value) }],
    structuredContent: value as Record<string, unknown>,
    isError: false,
  };
}

function mcpToolError(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

/** Run one MCP tool against the shared store; a string return is an error message. */
function runMcpTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const def = MCP_TOOL_DEFS.find((candidate) => candidate.name === name);
  if (def === undefined) return { rpcError: -32601, message: `Method not found: unknown tool ${name}` };
  const missing = def.required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
  if (missing.length > 0) {
    return { rpcError: -32602, message: `Missing required argument(s): ${missing.join(', ')}` };
  }
  const owner = String(args.owner ?? viewerLogin());
  const repoName = String(args.repo ?? '');
  const needRepo = (): RepoRec | null => (name === 'create_repo' ? null : findRepo(owner, repoName));
  switch (name) {
    case 'create_repo': {
      const repoArg = String(args.name ?? '');
      if (repoArg === '') return mcpToolError('name is required');
      if (state.repos.has(repoArg.toLowerCase())) return mcpToolError(`Repository ${repoArg} already exists`);
      const repo = createRepo(repoArg, typeof args.description === 'string' ? args.description : null, args.private === true);
      return mcpToolResult(repoJson(repo));
    }
    case 'get_repo': {
      const repo = needRepo();
      if (repo === null) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      return mcpToolResult(repoJson(repo));
    }
    case 'create_issue': {
      const repo = needRepo();
      if (repo === null) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const issue = createIssueRec(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', []);
      return mcpToolResult(issueJson(repo, issue));
    }
    case 'list_issues': {
      const repo = needRepo();
      if (repo === null) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const wanted = typeof args.state === 'string' ? args.state.toLowerCase() : 'open';
      let issues = [...repo.issues.values()];
      if (wanted === 'open') issues = issues.filter((issue) => issue.state === 'open');
      else if (wanted === 'closed') issues = issues.filter((issue) => issue.state === 'closed');
      issues.sort((a, b) => b.number - a.number);
      return mcpToolResult(issues.map((issue) => issueJson(repo, issue)));
    }
    case 'create_pull_request': {
      const repo = needRepo();
      if (repo === null) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const head = String(args.head ?? '');
      const base = String(args.base ?? '');
      if (refSha(repo, head) === null) return mcpToolError(`Head branch ${head} does not exist`);
      if (refSha(repo, base) === null) return mcpToolError(`Base branch ${base} does not exist`);
      const pull = createPullRec(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', head, base);
      return mcpToolResult(pullJson(repo, pull));
    }
    case 'merge_pull_request': {
      const repo = needRepo();
      if (repo === null) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const pull = repo.pulls.get(Number(args.pull_number));
      if (pull === undefined) return mcpToolError(`Pull request ${String(args.pull_number)} not found`);
      if (pull.merged) return mcpToolResult(pullJson(repo, pull));
      const sha = performMerge(repo, pull, 'squash');
      if (sha === null) return mcpToolError('Pull request is not mergeable: it has conflicts');
      return mcpToolResult(pullJson(repo, pull));
    }
    default:
      return { rpcError: -32601, message: `Method not found: unknown tool ${name}` };
  }
}

function handleMcp(info: ReqInfo, res: ServerResponse): void {
  if (info.method !== 'POST') {
    sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  if (!authed(info)) {
    res.writeHead(401, { 'content-type': JSON_TYPE });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32001, message: 'Unauthorized' } }));
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(info.body.toString('utf8'));
  } catch {
    res.writeHead(400, { 'content-type': JSON_TYPE });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
    return;
  }
  const entries = Array.isArray(parsed) ? parsed : [parsed];
  const responses: Array<Record<string, unknown>> = [];
  let sawNotificationOnly = entries.length > 0;
  for (const entry of entries) {
    const record = asRecord(entry);
    const method = typeof record.method === 'string' ? record.method : '';
    const id = 'id' in record ? record.id : undefined;
    if (id === undefined || method.startsWith('notifications/')) continue;
    sawNotificationOnly = false;
    const params = asRecord(record.params);
    const rpc = (result: unknown): Record<string, unknown> => ({ jsonrpc: '2.0', id: id ?? null, result });
    const rpcErr = (code: number, message: string): Record<string, unknown> => ({
      jsonrpc: '2.0',
      id: id ?? null,
      error: { code, message },
    });
    if (method === 'server/discover') {
      responses.push(
        rpc({
          resultType: 'complete',
          supportedVersions: MCP_SUPPORTED_VERSIONS,
          capabilities: { tools: {} },
          serverInfo: MCP_SERVER_INFO,
          _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
        }),
      );
    } else if (method === 'initialize') {
      const requested = typeof params.protocolVersion === 'string' ? params.protocolVersion : MCP_SUPPORTED_VERSIONS[1];
      const chosen = (MCP_SUPPORTED_VERSIONS as string[]).includes(requested as string) ? requested : MCP_SUPPORTED_VERSIONS[1];
      responses.push(
        rpc({
          protocolVersion: chosen,
          capabilities: { tools: {} },
          serverInfo: MCP_SERVER_INFO,
          _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
        }),
      );
    } else if (method === 'tools/list') {
      responses.push(rpc({ tools: MCP_TOOLS_JSON }));
    } else if (method === 'tools/call') {
      const toolName = typeof params.name === 'string' ? params.name : '';
      const args = asRecord(params.arguments);
      const outcome = runMcpTool(toolName, args);
      if (typeof outcome.rpcError === 'number') {
        responses.push(rpcErr(outcome.rpcError, String(outcome.message ?? 'Error')));
      } else {
        responses.push(rpc(outcome));
      }
    } else if (method === 'ping') {
      responses.push(rpc({}));
    } else {
      responses.push(rpcErr(-32601, `Method not found: ${method}`));
    }
  }
  if (sawNotificationOnly) {
    res.writeHead(202, { 'content-type': JSON_TYPE });
    res.end('');
    return;
  }
  const payload = Array.isArray(parsed) ? responses : responses[0] ?? { jsonrpc: '2.0', id: null, result: {} };
  res.writeHead(200, { 'content-type': JSON_TYPE });
  res.end(JSON.stringify(payload));
}

// ---------------------------------------------------------------------------
// the server

/** Read a request body with a generous cap (bench packs and issue bodies stay well under it). */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 512 * 1024 * 1024) {
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Build the forge server. It binds nothing until the caller listens. */
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://forge.local');
        const segments = url.pathname
          .split('/')
          .filter((segment) => segment !== '')
          .map((segment) => decodeURIComponent(segment));
        const body = await readBody(req);
        const info: ReqInfo = {
          method: (req.method ?? 'GET').toUpperCase(),
          segments,
          query: url.searchParams,
          headers: req.headers,
          body,
          host: req.headers.host ?? 'forge.local',
        };
        if (info.method === 'GET' && url.pathname === '/healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (segments[0] === 'api' && segments[1] === 'v3') {
          handleRest(info, res);
          return;
        }
        if (segments[0] === 'api' && segments[1] === 'graphql') {
          handleGraphql(info, res);
          return;
        }
        if (segments[0] === 'mcp') {
          handleMcp(info, res);
          return;
        }
        if (segments.length >= 2 && (segments[1] as string).endsWith('.git')) {
          handleGit(info, res);
          return;
        }
        notFound(res);
      } catch {
        if (!res.headersSent) sendJson(res, 500, { message: 'Internal Server Error' });
        else res.end();
      }
    })();
  });
}
