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
import { Replayed, Unauthenticated, Verifier } from '@codefly-dev/authority-client/work-context';

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

for (const vector of vectors) {
  test(`stamp vector, the contract's verdict: ${vector.name}`, async () => {
    const store = replay();
    const headers = vector.headers.map(([key, value]) => [key, value]);
    const deliver = () => new Verifier(source(vector), vector.audience, store, () => vector.now * 1000).verify(headers, vector.method);
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
  });
}
