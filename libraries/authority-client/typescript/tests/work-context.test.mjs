import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { create, fromBinary, fromJson, toBinary } from '@bufbuild/protobuf';
import { KeysResponseSchema, PublicKeySchema, WorkContextV1Schema, WorkScopeV1Schema } from '@codefly-dev/authority-client';
import { authenticateClaims, identityOf, trustFromKeys, Unauthenticated, Verifier, Reason } from '@codefly-dev/authority-client/work-context';

const fixtures = JSON.parse(readFileSync(new URL('../../testdata/claims.json',import.meta.url),'utf8'));
const encode = bytes => Buffer.from(bytes).toString('base64url');
// The test authority: a key of the test's own, never Core's public fixture key.
const signer = createPrivateKey({key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), Buffer.alloc(32)]), format: 'der', type: 'pkcs8'});
const publicKey = Buffer.from(signer.export({format:'jwk'}).x,'base64url');
const body = name => fromBinary(WorkContextV1Schema, Buffer.from(fixtures.find(f=>f.name===name).token.split('.')[0],'base64url'));
const signed = (context, key=signer) => { const payload = toBinary(WorkContextV1Schema,context); return encode(payload)+'.'+encode(sign(null,payload,key)); };
const trustFor = (context, at=(Number(context.notBeforeUnix)+1)*1000) => trustFromKeys(create(KeysResponseSchema,{issuer:context.issuer,keys:[create(PublicKeySchema,{keyId:context.keyId,algorithm:'Ed25519',publicKey})]}), ()=>at);
const stamped = (token, proof='test-proof') => ({'x-codefly-work-context':token,'x-codefly-hop-proof':proof,'x-codefly-hop-context':createHash('sha256').update(token).digest('hex')});
const read = context => authenticateClaims(stamped(signed(context)),'test-proof',context.audience,trustFor(context));
const scope = (actions, resourceIds=[]) => create(WorkScopeV1Schema,{resourceKind:'profiles',actions,resourceIds});

for (const fixture of fixtures) {
  test(`Core-minted fixture authenticates: ${fixture.name}`, () => {
    const claims = read(body(fixture.name));
    assert.equal(claims.audience,fixture.audience);
    assert.deepEqual(claims.scopes, fixture.scopes.map(s=>({resourceKind:s.resource_kind,actions:s.actions??[],resourceIds:s.resource_ids??[],resourceOwnerId:s.resource_owner_id??''})));
    for (const probe of fixture.probes) {
      const got = 'owner' in probe ? claims.allowsOwned(probe.kind,probe.action,probe.resource_id,probe.owner) : claims.allows(probe.kind,probe.action,probe.resource_id);
      assert.equal(got,probe.allowed,JSON.stringify(probe));
    }
  });
}

test('grants are evaluated one at a time and literally', () => {
  const context = body('session');
  context.authorityScopes = [scope(['read'],['a']), scope(['invoke'],['b'])];
  const claims = read(context);
  assert.ok(claims.allows('profiles','read','a') && claims.allows('profiles','invoke','b'));
  assert.ok(!claims.allows('profiles','invoke','a') && !claims.allows('profiles','read','b') && !claims.allows('profiles','read'));
  assert.throws(()=>{ claims.scopes[0].actions.push('admin'); });
});

// The defect this reader closes: whoever holds the proof writes the proof and any
// token's digest. Only signature, issuer, audience and window make it authentic.
test('a forged, unsigned, misaddressed or expired context is refused by name', () => {
  const context = body('session'), trust = trustFor(context);
  const foreign = create(WorkContextV1Schema,{...context, issuer:'https://forger.example'});
  const payload = signed(context).split('.')[0];
  for (const [token, audience, use, reason] of [
    [signed(context, generateKeyPairSync('ed25519').privateKey), context.audience, trust, /signature/],
    [payload+'.'+encode(new Uint8Array(64)), context.audience, trust, /signature/],
    [signed(foreign), context.audience, trust, /issued by/],
    [signed(context), 'another-module', trust, /audience/],
    [signed(context), context.audience, trustFor(context,(Number(context.expiresAtUnix)+3600)*1000), /expired/],
    [signed(context), context.audience, trustFor(context,(Number(context.notBeforeUnix)-3600)*1000), /not valid before/],
    [signed(create(WorkContextV1Schema,{...context, keyId:'rotated'})), context.audience, trust, /no verification key/],
    [signed(context), '', trust, /configuration/],
  ]) {
    assert.throws(()=>authenticateClaims(stamped(token),'test-proof',audience,use), e => e instanceof Unauthenticated && reason.test(e.message));
  }
});

test('the stamp must bind the token under this run\'s proof', () => {
  const context = body('session'), token = signed(context), trust = trustFor(context);
  for (const headers of [
    {...stamped(token), 'x-codefly-hop-proof':'forged'},
    {...stamped(token), 'x-codefly-hop-context':'0'.repeat(64)},
    {...stamped(token), 'x-codefly-work-context':signed(body('operation'))},
    [...Object.entries(stamped(token)), ['x-codefly-work-context',token]],
  ]) assert.throws(()=>authenticateClaims(headers,'test-proof',context.audience,trust),Unauthenticated);
  assert.throws(()=>authenticateClaims(stamped(token),'',context.audience,trust),Unauthenticated);
  for (const bad of ['abc','a.b.c','é.x', payloadOnly(token)+'.AA']) {
    assert.throws(()=>authenticateClaims(stamped(bad),'test-proof',context.audience,trust),Unauthenticated);
  }
});

test('trust comes only from published Ed25519 keys', () => {
  const key = create(PublicKeySchema,{keyId:'k',algorithm:'Ed25519',publicKey});
  assert.throws(()=>trustFromKeys(create(KeysResponseSchema,{keys:[key]})),Unauthenticated);
  assert.throws(()=>trustFromKeys(create(KeysResponseSchema,{issuer:'i',keys:[key,key]})),Unauthenticated);
  assert.throws(()=>trustFromKeys(create(KeysResponseSchema,{issuer:'i',keys:[create(PublicKeySchema,{keyId:'k',algorithm:'Ed25519',publicKey:new Uint8Array(3)})]})),Unauthenticated);
});

function payloadOnly(token) { return token.split('.')[0]; }

const vectors = JSON.parse(readFileSync(new URL('../../testdata/vectors.json',import.meta.url),'utf8'));
// Go writes the vectors and its verdict on each (workcontext/vectors_test.go):
// this reader must reach the same verdict, for the same reason, on every one.
for (const v of vectors) {
  test(`shared vector, Go's verdict: ${v.name}`, () => {
    const trust = {issuer: v.issuer, keys: new Map(Object.entries(v.keys).map(([kid, raw]) => [kid, new Uint8Array(Buffer.from(raw,'base64'))])), now: () => v.now*1000};
    const run = () => authenticateClaims(stamped(v.token),'test-proof',v.audience,trust);
    if (v.accept) run();
    else assert.throws(run, e => e instanceof Unauthenticated && e.message.includes(v.reason), v.reason);
  });
}

const fixture = JSON.parse(readFileSync(new URL('../../../hop/testdata/stamped.json',import.meta.url),'utf8'));
const published = fromJson(KeysResponseSchema, fixture.keys);
const source = (answer = () => Promise.resolve(published)) => { const s = {reads: 0, keys: () => { s.reads++; return answer(); }}; return s; };
const settle = () => new Promise(resolve => setImmediate(resolve));

test('the Verifier reads the hop fixture as Go reads it', async () => {
  const keys = source();
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => fixture.now*1000);
  const id = await v.verify(fixture.headers);
  assert.equal(id.owner, fixture.identity.owner);
  assert.equal(id.tenant, fixture.identity.tenant);
  assert.deepEqual([...id.scopes], fixture.identity.scopes);
  assert.equal(id.advisory, fixture.identity.advisory);
  assert.ok(id.claims.allows('documents.collection','write','c-1'));
  for (const [key, value, reason] of [['x-codefly-hop-tenant','globex',/stamp_identity/],['x-codefly-hop-scopes','documents.collection:admin',/stamp_identity/],['x-codefly-hop-proof','another-run',/proof/]]) {
    await assert.rejects(v.verify({...fixture.headers, [key]: value}), e => e instanceof Unauthenticated && reason.test(e.message));
  }
});

// Review r44 B1: nothing unauthenticated reaches the key read, and a hung read
// never stalls a call whose key is already held.
test('a call without the proof never reads the keys, and a hung read stalls no held key', async () => {
  let release;
  let hang = false;
  const keys = source(() => hang ? new Promise(resolve => { release = () => resolve(published); }) : Promise.resolve(published));
  let clock = fixture.now*1000;
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => clock);
  await settle();
  assert.equal(keys.reads, 1);
  for (let i = 0; i < 20; i++) {
    clock += 11_000;
    await assert.rejects(v.verify({'x-codefly-work-context': 'garbage'}), Unauthenticated);
  }
  assert.equal(keys.reads, 1, 'a proof-less call read the keys');
  hang = true;
  clock = fixture.now*1000 + 400_000; // keys older than max age: a background re-read starts and hangs
  const id = await v.verify(fixture.headers);
  assert.equal(id.owner, fixture.identity.owner);
  assert.equal(keys.reads, 2);
  release();
});

test('a Verifier starts before the authority serves keys and refuses with a reason until it does', async () => {
  let up = false;
  const keys = source(() => up ? Promise.resolve(published) : Promise.reject(new Error('dial authority:4000: connection refused')));
  let clock = fixture.now*1000;
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => clock);
  await settle();
  await assert.rejects(v.verify(fixture.headers), e => e instanceof Unauthenticated && /unavailable/.test(e.message) && !/4000/.test(e.message));
  up = true;
  clock += 11_000;
  assert.equal((await v.verify(fixture.headers)).owner, fixture.identity.owner);
});

// The robin playground's model gateway, live: its first call after 39 idle
// minutes, with no readiness poll between, was refused while the re-read it
// started succeeded in the background. Held keys past the stale window cannot
// judge a call, so the call waits for the read, as it does for a key not held.
// The keys are read before the fixture's token is minted, so the token is live.
for (const mode of ['stamped', 'bare']) {
 const check = v => mode === 'bare' ? v.verifyToken(fixture.headers['x-codefly-work-context']) : v.verify(fixture.headers);
test(mode + ': a call on keys past the stale window waits for the re-read', async () => {
  const keys = source();
  let clock = (fixture.now - 960)*1000;
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => clock);
  await settle();
  clock = fixture.now*1000;
  assert.equal((await check(v)).owner, fixture.identity.owner);
  assert.equal(keys.reads, 2);
});

// The wait fails closed: a re-read that fails refuses the call with the fixed
// reason, and only once the read has ended.
test(mode + ': a call on keys past the stale window is refused when the re-read fails', async () => {
  let fail;
  const keys = source(() => keys.reads === 1 ? Promise.resolve(published) : new Promise((_, reject) => { fail = reject; }));
  let clock = (fixture.now - 960)*1000;
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => clock);
  await settle();
  clock = fixture.now*1000;
  let judged = false;
  const call = check(v).finally(() => { judged = true; });
  for (let i = 0; i < 5; i++) await settle();
  assert.equal(judged, false, 'the call was judged before its re-read ended');
  fail(new Error('dial authority.internal:4000: connection refused'));
  await assert.rejects(call, e => e instanceof Unauthenticated && /unavailable/.test(e.message) && !/4000/.test(e.message));
  assert.match(String(v.keysError), /4000/);
});

// Review r159 f1: the wait bounds itself. A re-read that never answers, from a
// source that ignores its timeout and signal, refuses the call with the fixed
// reason once the verifier's own timeout passes, and holds no later read.
test(mode + ': a call on keys past the stale window is refused when the re-read hangs', {timeout: 3_000}, async () => {
  let hang = false;
  const keys = source(() => hang ? new Promise(() => {}) : Promise.resolve(published));
  let clock = (fixture.now - 960)*1000;
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => clock, 100);
  await settle();
  hang = true;
  clock = fixture.now*1000;
  const started = performance.now();
  await assert.rejects(check(v), e => e instanceof Unauthenticated && /unavailable/.test(e.message));
  assert.ok(performance.now() - started >= 90, 'refused before the read timed out');
  assert.equal(v.keysError?.name, 'TimeoutError');
  hang = false;
  clock += 11_000;
  assert.equal((await check(v)).owner, fixture.identity.owner);
  assert.equal(keys.reads, 3);
});

}

test('an actor granted nothing narrows the identity to nothing', () => {
  const context = body('delegated');
  context.actorChain[0].grantedScopes = [];
  assert.deepEqual(identityOf(context).scopes, []);
});

test('readiness follows trust, not the last read', async () => {
  let failing = false;
  const keys = source(() => failing ? Promise.reject(new Error('authority down')) : Promise.resolve(published));
  let clock = fixture.now*1000;
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => clock);
  await settle();
  assert.equal(v.ready(), true);
  failing = true;
  clock += 400_000; // old keys: ready() starts a re-read, which fails
  v.ready();
  await settle();
  assert.ok(v.keysError && v.ready());
  clock += 900_000;
  assert.equal(v.ready(), false);
});

// Review r74 B1: an unready replica gets no calls; polling ready() alone must read
// again and turn it ready once the authority serves keys.
test('an unready replica becomes ready by polling alone', async () => {
  let serving = false;
  const keys = source(() => serving ? Promise.resolve(published) : Promise.reject(new Error('not serving yet')));
  let clock = fixture.now*1000;
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => clock);
  await settle();
  let ready = false;
  for (let poll = 0; poll < 30 && !ready; poll++) {
    if (poll === 3) serving = true;
    clock += 1_000;
    v.ready();
    await settle();
    ready = v.ready();
  }
  assert.ok(ready && keys.reads <= 3, `ready=${ready} reads=${keys.reads}`);
});

// Review r74 B1: an idle replica polled for readiness past the stale window
// re-reads as its keys age and stays ready.
test('an idle replica polled for readiness stays ready', async () => {
  const keys = source();
  let clock = fixture.now*1000;
  const v = new Verifier(keys, fixture.audience, fixture.proof, () => clock);
  await settle();
  for (let minute = 1; minute <= 60; minute++) {
    clock += 60_000;
    v.ready();
    await settle();
    assert.ok(v.ready(), `unready at minute ${minute}`);
  }
  assert.ok(keys.reads >= 10 && keys.reads <= 14, `reads=${keys.reads}`);
});

for (const row of vectors) {
 test(`bare token matches shared verdict: ${row.name}`, async () => {
  const response = create(KeysResponseSchema, {issuer: row.issuer, keys: Object.entries(row.keys).map(([keyId, raw]) => create(PublicKeySchema,{keyId,algorithm:'Ed25519',publicKey:Buffer.from(raw,'base64')}))});
  const v = new Verifier(source(()=>Promise.resolve(response)), row.audience, 'proof', ()=>row.now*1000);
  if (row.accept) assert.equal((await v.verifyToken(row.token)).claims.audience,row.audience);
  else await assert.rejects(v.verifyToken(row.token), e=> e instanceof Unauthenticated && e.code === row.reason && !e.message.includes(row.token));
 });
}
test('every named reason has distinct code and safe text', () => {
 const reasons=Object.values(Reason);
 assert.equal(new Set(reasons).size,reasons.length);
 const messages=reasons.map(r=>new Unauthenticated(r).text);
 assert.equal(new Set(messages).size,reasons.length);
});

test('stamp failures retain distinct safe codes', async () => {
 const v=new Verifier(source(),fixture.audience,fixture.proof,()=>fixture.now*1000);
 for (const [change,code] of [
  [{'x-codefly-hop-proof':'private-proof'},Reason.StampProof],
  [{'x-codefly-work-context':''},Reason.StampToken],
  [{'x-codefly-hop-context':'private-digest'},Reason.StampDigest],
  [{'x-codefly-hop-tenant':'private-tenant'},Reason.StampIdentity],
 ]) await assert.rejects(v.verify({...fixture.headers,...change}), e=>e.code===code && !e.message.includes('private-'));
});
