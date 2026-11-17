/** What admitted a call, handed to the module so that no handler names a
 * permission. The Go library's admitted.go, reading for reading.
 *
 * The hop admits a call on its method's declaration and stamps, beside who the
 * call is for, everything the call holds with the selection each grant carries:
 * the whole kind, one owner's resources, or named resources (ADMITTED_KEY).
 * Verifier holds that stamp to the Work Context it authenticated, reads the
 * method's declaration from the table the module hands it, and hands the
 * handler an Admission: for what the method requires, and for what it carries,
 * which owners and which resources the call holds it on.
 *
 * A handler that must narrow a query reads admitted(identity).required() (the
 * owners the caller may see) or .carried() (how far the narrower of two
 * declared scopes reaches, content against metadata), and writes no kind and no
 * action. Admission was decided by the hop; nothing here decides it again.
 *
 * testdata/stamps.json holds every reading here to Go's. */
import type { WorkContextV1 } from "./src/gen/host/authority/v1/work_context_pb.js";

/** What the admitted call holds, each grant with its selection: encodeGrants of
 * Identity.grants. Like every stamp key it is the hop's to write: a caller's is
 * stripped, and a module refuses one that is not what the authenticated Work
 * Context says. */
export const ADMITTED_KEY = "x-codefly-hop-admitted";
/** The action a fixture grant holds every action with. */
export const ANY_ACTION = "*";

/** One action on one resource kind, carried apart and never joined and
 * re-split: a kind is matched as it was declared. */
export interface Permission {
  readonly kind: string;
  readonly action: string;
}

/** One method's declaration (authority.hop.v1.Policy): every permission of
 * requires, or anyCheckedCaller and nothing. carries is what a call may
 * exercise beyond what it requires; no decision reads it. */
export interface Method {
  readonly anyCheckedCaller?: boolean;
  readonly requires?: readonly Permission[];
  readonly carries?: readonly Permission[];
}

/** One action on one resource kind as the call holds it, with its selection: no
 * owner and no resources is the whole kind; an owner alone is every resource
 * that owner holds; resources are named resources, of owner when it is set. An
 * action of ANY_ACTION holds every action. */
export interface Grant {
  readonly kind: string;
  readonly action: string;
  readonly owner: string;
  readonly resources: readonly string[];
}

/** One term of a Selection: every resource of owner, or the resources named, of
 * owner when it is set. No owner and no resources is the whole kind. */
export interface Named {
  readonly owner: string;
  readonly resources: readonly string[];
}

/** Strings in the order of their UTF-8 bytes, which Go sorts by; the default
 * sort orders UTF-16 units, which differs past the surrogates. */
const bytewise = (a: string, b: string): number => Buffer.compare(Buffer.from(a), Buffer.from(b));

function compareGrants(a: Grant, b: Grant): number {
  for (const [x, y] of [[a.kind, b.kind], [a.action, b.action], [a.owner, b.owner]]) {
    const c = bytewise(x, y);
    if (c !== 0) return c;
  }
  for (let i = 0; i < Math.min(a.resources.length, b.resources.length); i++) {
    const c = bytewise(a.resources[i], b.resources[i]);
    if (c !== 0) return c;
  }
  return a.resources.length - b.resources.length;
}

/** Each grant once, its ids sorted and each once, the grants sorted by kind,
 * action, owner, then ids. */
function canonical(grants: readonly Grant[]): Grant[] {
  const sorted = grants
    .map(g => ({ kind: g.kind, action: g.action, owner: g.owner, resources: [...new Set(g.resources)].sort(bytewise) }))
    .sort(compareGrants);
  return sorted.filter((g, i) => i === 0 || compareGrants(sorted[i - 1], g) !== 0);
}

/** What a Work Context holds once every actor has narrowed it: the last actor's
 * granted scopes, which the authority attenuated from each hop before it, or
 * the owner's authority scopes when no one acts for them. One grant per action,
 * canonical, so the hop and the module derive the same value. */
export function grantsHeld(context: WorkContextV1): readonly Grant[] {
  const scopes = context.actorChain.at(-1)?.grantedScopes ?? context.authorityScopes;
  return Object.freeze(canonical(scopes.flatMap(scope => scope.actions.map(action => (
    { kind: scope.resourceKind, action, owner: scope.resourceOwnerId, resources: scope.resourceIds }
  )))).map(g => Object.freeze({ ...g, resources: Object.freeze(g.resources) })));
}

/** ADMITTED_KEY's value: unpadded base64url of a JSON array with one
 * [kind, action, owner, [resource ids]] entry per grant, canonical, in the
 * bytes Go's encoding/json writes (no spaces; <, >, &, U+2028 and U+2029
 * escaped), because a stamp is held to this value byte for byte. */
export function encodeGrants(grants: readonly Grant[]): string {
  const escapes: Record<string, string> = { "<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "\u2028": "\\u2028", "\u2029": "\\u2029" };
  const raw = JSON.stringify(canonical(grants).map(g => [g.kind, g.action, g.owner, g.resources]))
    .replace(/[<>&\u2028\u2029]/g, c => escapes[c]);
  return Buffer.from(raw, "utf8").toString("base64url");
}

/** Decode ADMITTED_KEY's value, or throw. It authenticates nothing: a module
 * reads admitted, which the Verifier established. */
export function grantsOf(value: string): Grant[] {
  const malformed = (): Error => new Error("hop: the admission stamp is malformed");
  const text = value.replace(/[\r\n]/g, "");
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw malformed();
  let entries: unknown;
  try {
    entries = JSON.parse(Buffer.from(text, "base64url").toString("utf8"));
  } catch {
    throw malformed();
  }
  if (entries === null) return [];
  if (!Array.isArray(entries)) throw malformed();
  const textOf = (field: unknown): string => {
    if (field === null) return "";
    if (typeof field !== "string") throw malformed();
    return field;
  };
  return entries.map(entry => {
    if (!Array.isArray(entry) || entry.length !== 4) throw malformed();
    const ids: unknown = entry[3] === null ? [] : entry[3];
    if (!Array.isArray(ids)) throw malformed();
    return { kind: textOf(entry[0]), action: textOf(entry[1]), owner: textOf(entry[2]), resources: ids.map(textOf) };
  });
}

/** How far a call reaches for what its method declares: the union of its
 * terms. A Selection of no terms reaches nothing. */
export class Selection {
  readonly #terms: readonly Named[];

  constructor(terms: readonly Named[] = []) {
    this.#terms = terms.map(t => Object.freeze({ owner: t.owner, resources: Object.freeze([...t.resources]) }));
  }

  /** Whether the selection reaches nothing. */
  empty(): boolean { return this.#terms.length === 0; }

  /** Whether the call holds the declaration on the whole kind, with no owner
   * selected. A module whose resources have owners decides for itself whether
   * an unselected grant reaches them; ownerSelected drops it. */
  whole(): boolean { return this.#terms.some(t => t.owner === "" && t.resources.length === 0); }

  /** The owners whose every resource the call reaches, sorted: what a list
   * narrows its query to. Never undefined, so "no owner" is never read as "no
   * filter". */
  owners(): string[] {
    return [...new Set(this.#terms.filter(t => t.owner !== "" && t.resources.length === 0).map(t => t.owner))].sort(bytewise);
  }

  /** The terms that name resources, for a module that honours them. */
  named(): Named[] {
    return this.#terms.filter(t => t.resources.length > 0).map(t => ({ owner: t.owner, resources: [...t.resources] }));
  }

  /** The selection without the terms that name no owner: what a module reads
   * when a grant that selects no owner must reach none of its owned resources. */
  ownerSelected(): Selection { return new Selection(this.#terms.filter(t => t.owner !== "")); }

  /** Whether the selection reaches the resource id that owner holds, as the
   * module's own record names them. An empty id asks for every resource of that
   * owner, which named resources never cover; a term naming an owner covers
   * only that owner. */
  allows(owner: string, id: string): boolean {
    return this.#terms.some(t => (t.owner === "" || t.owner === owner) &&
      (t.resources.length === 0 || (id !== "" && t.resources.includes(id))));
  }

  /** The selection both this and other reach. */
  both(other: Selection): Selection {
    const out: Named[] = [];
    for (const x of this.#terms) {
      for (const y of other.#terms) {
        if (x.owner !== "" && y.owner !== "" && x.owner !== y.owner) continue;
        const owner = x.owner !== "" ? x.owner : y.owner;
        let resources: readonly string[];
        if (x.resources.length === 0) resources = y.resources;
        else if (y.resources.length === 0) resources = x.resources;
        else {
          resources = x.resources.filter(id => y.resources.includes(id));
          if (resources.length === 0) continue;
        }
        const same = (have: Named): boolean => have.owner === owner && have.resources.length === resources.length &&
          have.resources.every((id, i) => id === resources[i]);
        if (!out.some(same)) out.push({ owner, resources });
      }
    }
    return new Selection(out);
  }
}

/** One permission a method declares and how far the call holds it. carried is
 * true for what the method carries rather than requires. */
export interface Held {
  readonly permission: Permission;
  readonly carried: boolean;
  readonly selection: Selection;
}

/** What admitted one call: the method (the procedure, or the HTTP request, the
 * call was admitted on), what it declares, and how far the call holds each
 * permission of that declaration.
 *
 * declared is false when the module declares nothing for the method that this
 * verifier could read; nothing is then selected. anyCheckedCaller is the
 * method's declaration that it requires nothing: the call was admitted as a
 * checked caller, on no scope at all. stamped is false only for the admission
 * admitted() answers when the hop stamped none. */
export class Admission {
  readonly #held: readonly Held[];

  constructor(readonly method: string = "", readonly declared: boolean = false, readonly anyCheckedCaller: boolean = false,
              held: readonly Held[] = [], readonly stamped: boolean = true) {
    this.#held = Object.freeze(held.map(h => Object.freeze({ ...h, permission: Object.freeze({ ...h.permission }) })));
    Object.freeze(this);
  }

  /** How far the call holds everything the method requires: the owners and
   * resources on which it holds every required permission. A method that
   * requires nothing selects nothing. When a method requires permissions of
   * different kinds on named resources, read each. */
  required(): Selection { return this.#all(false); }

  /** How far the call holds everything the method carries, within what it
   * requires: the narrower of two declared scopes, such as content within
   * metadata. Empty when the call holds only what the method requires. */
  carried(): Selection {
    if (!this.#held.some(h => h.carried)) return new Selection();
    const carried = this.#all(true);
    return this.#held.some(h => !h.carried) ? this.#all(false).both(carried) : carried;
  }

  /** Every permission the method declares with its own selection, for the
   * method that carries more than one thing. The permissions are the
   * declaration's; a handler still writes none. */
  each(): readonly Held[] { return this.#held; }

  #all(carried: boolean): Selection {
    let out: Selection | undefined;
    for (const h of this.#held) {
      if (h.carried === carried) out = out === undefined ? h.selection : out.both(h.selection);
    }
    return out ?? new Selection();
  }
}

/** What admitted() answers for a call the hop stamped no admission on: it
 * selects nothing, so a handler that narrows reaches nothing. */
const NOTHING = new Admission("", false, false, [], false);

/** What admitted the call Verifier authenticated, for a handler to narrow by.
 * For a call the hop stamped no admission on (a hop older than this contract),
 * and for no identity at all, it answers an admission that selects nothing,
 * with stamped false; identity.admitted is then undefined. Never read an absent
 * admission as "no filter". */
export function admitted(identity: { readonly admitted?: Admission } | undefined | null): Admission {
  return identity?.admitted ?? NOTHING;
}

/** Read grants against one method's declaration: for each permission the
 * method requires or carries, the selection of every grant that holds it. It is
 * what the Verifier hands a handler; a test of a module's own narrowing builds
 * one the same way. */
export function admissionOf(declared: Method, method: string, grants: readonly Grant[]): Admission {
  const any = declared.anyCheckedCaller === true, requires = declared.requires ?? [], carries = declared.carries ?? [];
  // A declaration that says two things was refused by the hop; it is never
  // read as one of them here.
  if (any && requires.length + carries.length > 0) return new Admission(method, false, any);
  const held: Held[] = [], seen = new Set<string>(), all = canonical(grants);
  // What a method requires is read first: a permission it also lists as
  // carried is required.
  for (const [carried, permissions] of [[false, requires], [true, carries]] as const) {
    for (const p of permissions) {
      const key = JSON.stringify([p.kind, p.action]);
      if (seen.has(key)) continue;
      seen.add(key);
      held.push({
        permission: { kind: p.kind, action: p.action }, carried,
        selection: new Selection(all.filter(g => g.kind === p.kind && (g.action === p.action || g.action === ANY_ACTION))
          .map(g => ({ owner: g.owner, resources: g.resources }))),
      });
    }
  }
  const name = (h: Held): string => `${h.permission.kind}:${h.permission.action}`;
  // Array.prototype.sort is stable, as Go's SortStableFunc is.
  held.sort((x, y) => x.carried !== y.carried ? (y.carried ? -1 : 1) : bytewise(name(x), name(y)));
  return new Admission(method, any || requires.length > 0, any, held);
}

/** What the module declares for method: an exact entry of the table it handed
 * over, keyed "/package.Service/Method" or, for an HTTP route,
 * "<VERB> <template>", or the one route template an HTTP request is an instance
 * of. A method the table does not hold declares nothing. */
export function declaration(declared: Readonly<Record<string, Method>> | undefined, method: string): Method {
  const table = declared ?? {};
  if (Object.hasOwn(table, method)) return table[method];
  const space = method.indexOf(" ");
  if (space < 0 || !method.startsWith("/", space + 1)) return {};
  const verb = method.slice(0, space), path = method.slice(space + 1);
  const found = Object.keys(table).filter(route => {
    const cut = route.indexOf(" ");
    return cut >= 0 && route.slice(0, cut) === verb && routeMatches(route.slice(cut + 1), path);
  });
  // Two templates matching one request is the ambiguity the authority refuses;
  // it selects nothing here.
  return found.length === 1 ? table[found[0]] : {};
}

/** Go's routing.CanonicalPath: rooted, no dot segment, no repeated or trailing
 * separator, no backslash and no escape. */
function canonicalPath(path: string): boolean {
  if (!path.startsWith("/") || path.includes("\\") || path.includes("%")) return false;
  return path === "/" || path.split("/").slice(1).every(segment => segment !== "" && segment !== "." && segment !== "..");
}

/** Go's routing.RouteMatches, the hop's own template matcher: a final
 * {name=**} spans at least one character; ordinary variables span one segment. */
function routeMatches(template: string, path: string): boolean {
  if (!canonicalPath(path)) return false;
  let want = template.split("/"), got = path.split("/");
  const last = want[want.length - 1];
  if (last.includes("=**}")) {
    if (got.length < want.length) return false;
    const open = last.indexOf("{");
    if (open < 0) return false;
    const prefix = last.slice(0, open), suffix = last.slice(last.indexOf("=**}") + 4);
    const rest = got.slice(want.length - 1).join("/");
    if (!rest.startsWith(prefix) || !rest.endsWith(suffix) || rest.length <= prefix.length + suffix.length) return false;
    got = got.slice(0, want.length - 1);
    want = want.slice(0, want.length - 1);
  }
  return want.length === got.length && want.every((segment, i) => segmentMatches(segment, got[i]));
}

function segmentMatches(template: string, segment: string): boolean {
  const open = template.indexOf("{");
  if (open < 0) return template === segment;
  const end = template.slice(open).indexOf("}");
  if (end < 0 || !segment.startsWith(template.slice(0, open))) return false;
  const rest = segment.slice(open), tail = template.slice(open + end + 1);
  for (let i = 1; i <= rest.length; i++) {
    if (segmentMatches(tail, rest.slice(i))) return true;
  }
  return false;
}
