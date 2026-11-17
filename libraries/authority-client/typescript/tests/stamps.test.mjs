// The wire-level half of the hop conformance target, replayed by TypeScript.
//
// ../../testdata/stamps.json is written by the Go hop library's test
// (libraries/hop/go/vectors_test.go): signed admissions on the wire, as the hop
// forwards them, each with the verdict the contract names at a fixed clock. This
// verifier must reach the same verdict, for the same reason, reading the same
// identity. The behavioural half of the target is libraries/conformance/hop/go.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fromJson } from '@bufbuild/protobuf';
import { KeysResponseSchema } from '@codefly-dev/authority-client';
import { ADMITTED_KEY, Admission, Replayed, Unauthenticated, Verifier, admissionOf, admitted, declaration, encodeGrants, grantsOf } from '@codefly-dev/authority-client/work-context';

// Every verifier here runs in the local run, which alone may use a
// process-local replay store.
process.env.CODEFLY__ENVIRONMENT = 'local';

const vectors = JSON.parse(readFileSync(new URL('../../testdata/stamps.json', import.meta.url), 'utf8'));

// One store the verifiers of a vector share.
const replay = () => { const seen = new Set(); return { async consume(nonce) { if (seen.has(nonce)) throw new Replayed(); seen.add(nonce); } }; };
// The authority's Keys as the vector publishes them, or one that cannot be read.
const source = vector => ({ keys: () => vector.keys === null
  ? Promise.reject(new Error('dial authority.internal:4000: connection refused'))
  : Promise.resolve(fromJson(KeysResponseSchema, vector.keys)) });

// What the module hands its verifier: each method's declaration, or none.
const declarations = vector => vector.declared && Object.fromEntries(Object.entries(vector.declared).map(([method, d]) => {
  const pairs = rows => rows.map(([kind, action]) => ({ kind, action }));
  return [method, { anyCheckedCaller: d.any_checked_caller, requires: pairs(d.requires), carries: pairs(d.carries) }];
}));
// Strings in the order of their UTF-8 bytes, which is Go's.
const bytewise = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
// Every reading an Admission answers, in the vectors' shape: Go's admissionRead
// (libraries/hop/go/vectors_test.go), probed the same way.
const reading = (admission, grants) => {
  const owners = [...new Set(['', 'another-owner', ...grants.map(g => g.owner)])].sort(bytewise);
  const ids = [...new Set(['', 'another-id', ...grants.flatMap(g => g.resources)])].sort(bytewise);
  const read = (selection, nested = false) => ({
    empty: selection.empty(), whole: selection.whole(), owners: selection.owners(),
    named: selection.named().map(n => ({ owner: n.owner, resources: [...n.resources] })),
    allows: owners.flatMap(owner => ids.map(id => ({ owner, id, allowed: selection.allows(owner, id) }))),
    ...(nested ? {} : { owner_selected: read(selection.ownerSelected(), true) }),
  });
  return {
    method: admission.method, declared: admission.declared, any_checked_caller: admission.anyCheckedCaller,
    grants: grants.map(g => [g.kind, g.action, g.owner, [...g.resources]]),
    required: read(admission.required()), carried: read(admission.carried()),
    each: admission.each().map(h => ({ kind: h.permission.kind, action: h.permission.action, carried: h.carried, selection: read(h.selection) })),
  };
};

for (const vector of vectors) {
  test(`stamp vector, the contract's verdict: ${vector.name}`, async () => {
    const store = replay();
    const headers = vector.headers.map(([key, value]) => [key, value]);
    const deliver = () => new Verifier(source(vector), vector.audience, store, () => vector.now * 1000, undefined, declarations(vector)).verify(headers, vector.method);
    if (!vector.accept) {
      await assert.rejects(deliver(), error => {
        assert.ok(error instanceof Unauthenticated, `refused otherwise: ${error}`);
        assert.equal(error.code, vector.reason);
        for (const [key, value] of headers) assert.ok(value.length <= 16 || !error.message.includes(value), `the refusal names the call's ${key}`);
        return true;
      });
      return;
    }
    const id = await deliver();
    const want = vector.identity;
    assert.deepEqual([id.owner, id.ownerKind, id.tenant, id.binding, id.task, id.expires], [want.owner, want.owner_kind, want.tenant, want.binding, want.task, want.expires]);
    assert.deepEqual([...id.actors], want.actors);
    assert.deepEqual([...id.scopes], want.scopes);
    assert.equal(id.advisory, '');
    assert.equal(id.context, Object.fromEntries(headers)['x-codefly-work-context']);
    await assert.rejects(deliver(), error => error instanceof Unauthenticated && error.code === vector.replay);
    // What admitted the call: every reading Go hands a handler, or none at all
    // for a call the hop stamped no admission on.
    if (vector.admission === undefined) {
      assert.equal(id.admitted, undefined, 'an admission was invented for a call the hop stamped none on');
      const nothing = admitted(id);
      assert.ok(!nothing.stamped && nothing.required().empty() && nothing.carried().empty() && nothing.each().length === 0);
      assert.ok(!nothing.required().allows('installation-a', 'c-1'));
      assert.deepEqual(nothing.required().owners(), []);
      return;
    }
    assert.ok(id.admitted instanceof Admission && admitted(id) === id.admitted && id.admitted.stamped);
    assert.deepEqual(reading(id.admitted, id.grants), vector.admission);
    const stamped = Object.fromEntries(headers)[ADMITTED_KEY];
    assert.equal(encodeGrants(id.grants), stamped);
    assert.deepEqual(grantsOf(stamped), id.grants.map(g => ({ ...g, resources: [...g.resources] })));
  });
}

// Go's AdmissionOf: a test of a module's own narrowing builds an admission from
// a declaration and grants, given in any order and repeated.
test('a module reads its own narrowing in a test without a verifier', () => {
  const declared = { requires: [{ kind: 'records.records', action: 'read' }], carries: [{ kind: 'records.records', action: 'read_content' }] };
  const grant = (action, owner, resources = []) => ({ kind: 'records.records', action, owner, resources });
  const read = admissionOf(declared, '/records.v1.Records/Content',
    [grant('read_content', 'installation-a', ['r-2', 'r-1', 'r-2']), grant('read', 'installation-a'), grant('read', 'installation-a'), grant('read', 'installation-b')]);
  assert.ok(read.declared);
  assert.deepEqual(read.required().owners(), ['installation-a', 'installation-b']);
  const carried = read.carried();
  assert.deepEqual(carried.owners(), []);
  assert.deepEqual(carried.named(), [{ owner: 'installation-a', resources: ['r-1', 'r-2'] }]);
  assert.ok(carried.allows('installation-a', 'r-1') && !carried.allows('installation-a', 'r-3') && !carried.allows('installation-b', 'r-1'));
  assert.ok(!carried.allows('installation-a', ''), 'named resources never cover every resource of their owner');
  assert.ok(admitted(undefined).required().empty(), 'no identity reads as an admission');
  // A table is read by its own entries, never by what every object inherits.
  assert.ok(!admissionOf(declaration({}, 'constructor'), 'constructor', []).declared);
});

for (const value of ['', 'W10=', 'bm90IGpzb24', 'WzFd', 'W1siayIsImEiLCIiXV0', 'W1siayIsImEiLCIiLFsxXV1d', 'W1siayIsImEiLDEsW11dXQ', 'e30']) {
  test(`a malformed admission stamp decodes to no grants: ${JSON.stringify(value)}`, () => {
    assert.throws(() => grantsOf(value), /malformed/);
  });
}
