import { createPrivateKey as hopPrivateKey, randomBytes as hopRandom, sign as hopSign } from "node:crypto";
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { create, fromBinary, fromJson, toBinary } from '@bufbuild/protobuf';
import { KeysResponseSchema, PublicKeySchema, WorkContextV1Schema, WorkScopeV1Schema } from '@codefly-dev/authority-client';
import { authenticateToken, boundToken, identityOf, trustFromKeys, Unauthenticated, Verifier, Replayed, Expired, Reason, SKEW, NoAdmissionKeys } from '@codefly-dev/authority-client/work-context';

// Every verifier here runs in the local run, which alone may use a
// process-local replay store; the startup guard's test sets its own.
process.env.CODEFLY__ENVIRONMENT = 'local';

const fixtures = JSON.parse(readFileSync(new URL('../../testdata/claims.json',import.meta.url),'utf8'));
const encode = bytes => Buffer.from(bytes).toString('base64url');
// The test authority: a key of the test's own, never Core's public fixture key.
const signer = createPrivateKey({key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), Buffer.alloc(32)]), format: 'der', type: 'pkcs8'});
const publicKey = Buffer.from(signer.export({format:'jwk'}).x,'base64url');
const body = name => fromBinary(WorkContextV1Schema, Buffer.from(fixtures.find(f=>f.name===name).token.split('.')[0],'base64url'));
const signed = (context, key=signer) => { const payload = toBinary(WorkContextV1Schema,context); return encode(payload)+'.'+encode(sign(null,payload,key)); };
const trustFor = (context, at=(Number(context.notBeforeUnix)+1)*1000) => trustFromKeys(create(KeysResponseSchema,{issuer:context.issuer,keys:[create(PublicKeySchema,{keyId:context.keyId,algorithm:'Ed25519',publicKey})]}), ()=>at);
const stamped = (token, proof='test-proof') => ({'x-codefly-work-context':token,'x-codefly-hop-proof':proof,'x-codefly-hop-context':createHash('sha256').update(token).digest('hex')});
const read = context => authenticateToken(signed(context), context.audience, trustFor(context));
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
    assert.throws(()=>authenticateToken(token, audience, use), e => e instanceof Unauthenticated && reason.test(e.message));
  }
});

test('the stamp must bind the token under this run\'s proof', () => {
  const context = body('session'), token = signed(context), trust = trustFor(context);
  for (const headers of [
    {...stamped(token), 'x-codefly-hop-context':'0'.repeat(64)},
    {...stamped(token), 'x-codefly-work-context':signed(body('operation'))},
    [...Object.entries(stamped(token)), ['x-codefly-work-context',token]],
  // boundToken refuses the binding; authenticateToken then the token. Two
  // calls, because neither of them admits a call (review r164 R4).
  ]) assert.throws(()=>authenticateToken(boundToken(headers), context.audience, trust),Unauthenticated);
  for (const bad of ['abc','a.b.c','é.x', payloadOnly(token)+'.AA']) {
    assert.throws(()=>authenticateToken(bad, context.audience, trust),Unauthenticated);
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
    const run = () => authenticateToken(v.token, v.audience, trust);
    if (v.accept) run();
    else assert.throws(run, e => e instanceof Unauthenticated && e.message.includes(v.reason), v.reason);
  });
}

const fixture = JSON.parse(readFileSync(new URL('../../../hop/testdata/stamped.json',import.meta.url),'utf8'));
const METHOD = "/test.Service/Read";
const replay = () => { const seen = new Set(); return { async consume(nonce) { if (seen.has(nonce)) throw new Replayed(); seen.add(nonce); } }; };
const hopKey = label => hopPrivateKey({key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), createHash("sha256").update(label).digest()]), format: "der", type: "pkcs8"});
const fresh = (now, method = METHOD, audience = fixture.audience, headers = fixture.headers, hop = "fixture-proof") => {
 const payload = Buffer.from(JSON.stringify(["codefly-hop-v1", method, audience, createHash("sha256").update(headers["x-codefly-work-context"]).digest("hex"), hopRandom(32).toString("hex"), Math.floor(now/1000), Math.floor(now/1000)+30]));
 return {...headers, "x-codefly-hop-proof": payload.toString("base64url")+"."+hopSign(null,payload,hopKey(hop)).toString("base64url")};
};
// The admission key of the test hop that signs as label, as Keys publishes it.
const hopPublished = label => create(PublicKeySchema, {keyId: `hop-${label}`, algorithm: 'Ed25519', purpose: 'hop-admission',
 publicKey: Buffer.from(hopKey(label).export({format: 'jwk'}).x, 'base64url')});
// The fixture's Work Context keys, and the admission keys of these hops.
const publishing = (...labels) => create(KeysResponseSchema, {issuer: fromJson(KeysResponseSchema, fixture.keys).issuer, keys: fromJson(KeysResponseSchema, fixture.keys).keys, admissionKeys: labels.map(hopPublished)});

const published = fromJson(KeysResponseSchema, fixture.keys);
const source = (answer = () => Promise.resolve(published)) => { const s = {reads: 0, keys: () => { s.reads++; return answer(); }}; return s; };
const settle = () => new Promise(resolve => setImmediate(resolve));

test('the Verifier reads the hop fixture as Go reads it', async () => {
  const keys = source();
  const v = new Verifier(keys, fixture.audience, replay(), () => fixture.now*1000);
  const id = await v.verify(fresh(v.now()), METHOD);
  assert.equal(id.owner, fixture.identity.owner);
  assert.equal(id.tenant, fixture.identity.tenant);
  assert.deepEqual([...id.scopes], fixture.identity.scopes);
  assert.equal(id.advisory, fixture.identity.advisory);
  assert.ok(id.claims.allows('documents.collection','write','c-1'));
  for (const [key, value, reason] of [['x-codefly-hop-tenant','globex',/stamp_identity/],['x-codefly-hop-scopes','documents.collection:admin',/stamp_identity/],['x-codefly-hop-proof','another-run',/stamp_proof/]]) {
    await assert.rejects(v.verify({...fresh(v.now()), [key]: value}, METHOD), e => e instanceof Unauthenticated && reason.test(e.message));
  }
});

// Review r44 B1: nothing unauthenticated reaches the key read, and a hung read
// never stalls a call whose key is already held.
test('a call without the proof never reads the keys, and a hung read stalls no held key', async () => {
  let release;
  let hang = false;
  const keys = source(() => hang ? new Promise(resolve => { release = () => resolve(published); }) : Promise.resolve(published));
  let clock = fixture.now*1000;
  const v = new Verifier(keys, fixture.audience, replay(), () => clock);
  await settle();
  assert.equal(keys.reads, 1);
  for (let i = 0; i < 20; i++) {
    clock += 11_000;
    await assert.rejects(v.verify({'x-codefly-work-context': 'garbage'}, METHOD), Unauthenticated);
  }
  assert.equal(keys.reads, 1, 'a proof-less call read the keys');
  hang = true;
  clock = fixture.now*1000 + 400_000; // keys older than max age: a background re-read starts and hangs
  const id = await v.verify(fresh(v.now()), METHOD);
  assert.equal(id.owner, fixture.identity.owner);
  assert.equal(keys.reads, 2);
  release();
});

test('a Verifier starts before the authority serves keys and refuses with a reason until it does', async () => {
  let up = false;
  const keys = source(() => up ? Promise.resolve(published) : Promise.reject(new Error('dial authority:4000: connection refused')));
  let clock = fixture.now*1000;
  const v = new Verifier(keys, fixture.audience, replay(), () => clock);
  await settle();
  await assert.rejects(v.verify(fresh(v.now()), METHOD), e => e instanceof Unauthenticated && /unavailable/.test(e.message) && !/4000/.test(e.message));
  up = true;
  clock += 11_000;
  assert.equal((await v.verify(fresh(v.now()), METHOD)).owner, fixture.identity.owner);
});

// The robin playground's model gateway, live: its first call after 39 idle
// minutes, with no readiness poll between, was refused while the re-read it
// started succeeded in the background. Held keys past the stale window cannot
// judge a call, so the call waits for the read, as it does for a key not held.
// The keys are read before the fixture's token is minted, so the token is live.
for (const mode of ['stamped', 'bare']) {
 // Each admission is single-use, so the stamped mode signs a fresh one per call.
 const check = v => mode === 'bare' ? v.verifyToken(fixture.headers['x-codefly-work-context']) : v.verify(fresh(v.now()), METHOD);
test(mode + ': a call on keys past the stale window waits for the re-read', async () => {
  const keys = source();
  let clock = (fixture.now - 960)*1000;
  const v = new Verifier(keys, fixture.audience, replay(), () => clock);
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
  const v = new Verifier(keys, fixture.audience, replay(), () => clock);
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
  const v = new Verifier(keys, fixture.audience, replay(), () => clock, 100);
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
  const v = new Verifier(keys, fixture.audience, replay(), () => clock);
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
  const v = new Verifier(keys, fixture.audience, replay(), () => clock);
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
  const v = new Verifier(keys, fixture.audience, replay(), () => clock);
  await settle();
  for (let minute = 1; minute <= 60; minute++) {
    clock += 60_000;
    v.ready();
    await settle();
    assert.ok(v.ready(), `unready at minute ${minute}`);
  }
  assert.ok(keys.reads >= 10 && keys.reads <= 14, `reads=${keys.reads}`);
});

test('review probes: read stamp cannot retarget, cross audiences or replay across replicas', async () => {
  const store = replay();
  const first = new Verifier(source(), fixture.audience, store, () => fixture.now*1000);
  const second = new Verifier(source(), fixture.audience, store, () => fixture.now*1000);
  for (const method of ['/documents.v1.Service/Delete','/datasets.v1.Service/Register','Read','','POST '+METHOD]) {
    await assert.rejects(first.verify(fixture.headers, method), /stamp_method/);
  }
  const other = new Verifier(source(), 'records', store, () => fixture.now*1000);
  await assert.rejects(other.verify(fixture.headers, METHOD), /stamp_audience/);
  assert.equal((await first.verify(fixture.headers, METHOD)).claims.context.replayPolicy, "single-use");
  await assert.rejects(first.verify(fixture.headers, METHOD), /stamp_replayed/);
  await assert.rejects(second.verify(fixture.headers, METHOD), /stamp_replayed/);
  await assert.rejects(second.verify({...fixture.headers, 'x-codefly-hop-proof': 'fixture-proof'}, METHOD), /proof/);
});

test('concurrent replay has one winner and a failed store refuses admission', async () => {
  const store = replay();
  const replicas = [0,1].map(() => new Verifier(source(), fixture.audience, store, () => fixture.now*1000));
  const results = await Promise.allSettled(Array.from({length:32}, (_,n) => replicas[n%2].verify(fixture.headers, METHOD)));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const v = new Verifier(source(), fixture.audience, {async consume(){throw Error('store down');}}, () => fixture.now*1000);
  await assert.rejects(v.verify(fixture.headers, METHOD), /stamp_store/);
});

test('expired stamps and repeated binding headers refuse before consumption', async () => {
  const expired = new Verifier(source(), fixture.audience, replay(), () => (fixture.now+30+SKEW)*1000);
  await assert.rejects(expired.verify(fixture.headers, METHOD), /stamp_window/);
  for (const key of ['x-codefly-hop-proof', 'x-codefly-work-context','x-codefly-hop-context']) {
    const v = new Verifier(source(), fixture.audience, replay(), () => fixture.now*1000);
    await assert.rejects(v.verify([...Object.entries(fixture.headers),[key,fixture.headers[key]]], METHOD), Unauthenticated);
    await v.verify(fixture.headers, METHOD);
  }
});

for (const row of vectors) {
 test(`bare token matches shared verdict: ${row.name}`, async () => {
  const response = create(KeysResponseSchema, {issuer: row.issuer, keys: Object.entries(row.keys).map(([keyId, raw]) => create(PublicKeySchema,{keyId,algorithm:'Ed25519',publicKey:Buffer.from(raw,'base64')}))});
  const v = new Verifier(source(()=>Promise.resolve(response)), row.audience, undefined, ()=>row.now*1000);
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
 const v=new Verifier(source(),fixture.audience,replay(),()=>fixture.now*1000);
 for (const [change,code] of [
  [{'x-codefly-hop-proof':'private-proof'},Reason.StampProof],
  [{'x-codefly-work-context':''},Reason.StampToken],
  [{'x-codefly-hop-context':'private-digest'},Reason.StampDigest],
  [{'x-codefly-hop-tenant':'private-tenant'},Reason.StampIdentity],
 ]) await assert.rejects(v.verify({...fixture.headers,...change}, METHOD), e=>e.code===code && !e.message.includes('private-'));
});

test('bare-only process needs no admission keys and cannot accept stamps', async () => {
 const v = new Verifier(source(),fixture.audience,undefined,()=>fixture.now*1000);
 assert.equal((await v.verifyToken(fixture.headers['x-codefly-work-context'])).owner,fixture.identity.owner);
 // Without the hop public key and a shared replay store it admits nothing.
 await assert.rejects(v.verify(fixture.headers, METHOD), e=>e.code===Reason.Configuration);
});

test('invalid publication and unreadable keys have distinct safe codes', async () => {
 for (const [answer, code] of [
  [()=>Promise.resolve(create(KeysResponseSchema,{issuer:'issuer'})), Reason.InvalidKey],
  [()=>Promise.reject(new Error('private-source-detail')), Reason.KeysUnavailable],
 ]) {
  const v=new Verifier(source(answer),fixture.audience,undefined,()=>fixture.now*1000);
  await assert.rejects(v.verifyToken(fixture.headers['x-codefly-work-context']), e=>e.code===code && !e.message.includes('private-'));
 }
});

// Review r164 R1: a verifier whose clock lags the hop refused genuine calls
// whenever the signing instant fell just after a second boundary, under a
// reason that read as an expiry. Go, Python and TypeScript allow the same SKEW.
for (const lag of [0, 1, SKEW]) {
 test(`a clock difference of ${lag}s inside the allowance still admits`, async () => {
  const v = new Verifier(source(), fixture.audience, replay(), () => (fixture.now-lag)*1000);
  assert.equal((await v.verify(fresh(fixture.now*1000), METHOD)).owner, fixture.identity.owner);
 });
}

for (const [lag, code] of [[SKEW+1, Reason.StampIssued], [-(30+SKEW), Reason.StampWindow]]) {
 test(`a clock difference of ${lag}s beyond the allowance is refused as ${code}`, async () => {
  const v = new Verifier(source(), fixture.audience, replay(), () => (fixture.now-lag)*1000);
  await assert.rejects(v.verify(fresh(fixture.now*1000), METHOD), e => e instanceof Unauthenticated && e.code === code);
 });
}

// Review r164 R2: the reservation outlives the admission by the same
// allowance, so a store evicting on its own clock cannot release a nonce a
// lagging verifier would still admit.
test('a reservation is retained past expiry by the allowance', async () => {
 const retained = [];
 const recording = { async consume(_nonce, retainUntil) { retained.push(retainUntil); } };
 const v = new Verifier(source(), fixture.audience, recording, () => fixture.now*1000);
 const headers = fresh(fixture.now*1000);
 const payload = JSON.parse(Buffer.from(headers['x-codefly-hop-proof'].split('.')[0], 'base64url').toString('utf8'));
 await v.verify(headers, METHOD);
 assert.deepEqual(retained, [payload[6] + SKEW]);
});

// A reservation store as replaypg is: a nonce is held until it is finished AND
// its retention has passed, and a reservation past its retention is refused
// rather than inserted. collect removes what has aged out.
const reservations = clock => {
 const store = { shared: true, held: new Map(), active: new Set(),
  async reserve(nonce, until) {
   if (until * 1000 <= clock()) throw new Expired();
   if (store.held.has(nonce)) throw new Replayed();
   store.held.set(nonce, until); store.active.add(nonce);
  },
  async finish(nonce) { store.active.delete(nonce); },
  async consume() { throw new Error('a reservation store is reserved, never consumed'); },
  collect() { for (const [nonce, until] of store.held) if (!store.active.has(nonce) && until * 1000 < clock()) store.held.delete(nonce); },
 };
 return store;
};

// Review of #28 at 8a3e953b: a single-use admission is consumed exactly once.
// Two deliveries of one admission arrive inside its window; the first holds its
// reservation while its handler runs, past its retention and collection; the
// second is refused by name, and so is a delivery after the handler returned.
test('a second delivery of one admission is refused while and after the first runs', async () => {
 let now = fixture.now * 1000;
 const store = reservations(() => now);
 const v = new Verifier(source(), fixture.audience, store, () => now);
 const headers = fresh(now);
 let ran = 0;
 await v.admit(headers, METHOD, async identity => {
  ran++;
  assert.equal(identity.owner, fixture.identity.owner);
  await assert.rejects(v.verify(headers, METHOD), e => e.code === Reason.StampReplayed);
  now += (30 + SKEW + 5) * 1000; // past the retention while the handler still runs
  store.collect();
  assert.equal(store.held.size, 1, 'collection removed the reservation of a running call');
  await assert.rejects(v.admit(headers, METHOD, async () => { ran++; }), e => e.code === Reason.StampWindow);
 });
 store.collect();
 assert.equal(store.held.size, 0);
 assert.equal(ran, 1);
});

// The reservation is taken before the Work Context is authenticated, and a
// refusal there ends the hold rather than leaving it pinned; a second delivery
// still meets it. An admission judged on no keys reserves nothing.
test('the reservation is taken before the work context and released on refusal', async () => {
 const now = fixture.now * 1000;
 const store = reservations(() => now);
 const v = new Verifier(source(), fixture.audience, store, () => now);
 const token = fixture.headers['x-codefly-work-context'];
 const forged = token.split('.')[0] + '.' + Buffer.alloc(64).toString('base64url');
 const headers = fresh(now, METHOD, fixture.audience, {...fixture.headers, 'x-codefly-work-context': forged, 'x-codefly-hop-context': createHash('sha256').update(forged).digest('hex')});
 await assert.rejects(v.verify(headers, METHOD), e => e.code === Reason.Signature);
 assert.equal(store.held.size, 1, 'the call never reserved');
 assert.equal(store.active.size, 0, 'a refused call kept its hold');
 await assert.rejects(v.verify(headers, METHOD), e => e.code === Reason.StampReplayed);
 const unread = reservations(() => now);
 const down = new Verifier(source(() => Promise.reject(new Error('authority down'))), fixture.audience, unread, () => now, 50);
 await assert.rejects(down.verify(fresh(now), METHOD), e => e.code === Reason.KeysUnavailable);
 assert.equal(unread.held.size, 0, 'an admission judged on no keys was reserved');
});

// Review r3 B1: the hop's admission key comes from the authority's Keys, the
// read the verifier already makes; nothing about the hop is configured.
test('a verifier takes the hop key from the authority keys alone', async () => {
 const v = new Verifier(source(() => Promise.resolve(publishing('the-hop'))), fixture.audience, replay(), () => fixture.now * 1000);
 const id = await v.verify(fresh(fixture.now * 1000, METHOD, fixture.audience, fixture.headers, 'the-hop'), METHOD);
 assert.equal(id.owner, fixture.identity.owner);
});

// A stamp signed by a key the authority does not publish is refused by name,
// and causes no read of the authority's keys.
test('a stamp signed by an unpublished key is refused by name', async () => {
 const keys = source(() => Promise.resolve(publishing('the-hop')));
 const v = new Verifier(keys, fixture.audience, replay(), () => fixture.now * 1000);
 await settle();
 const reads = keys.reads;
 await assert.rejects(v.verify(fresh(fixture.now * 1000, METHOD, fixture.audience, fixture.headers, 'an-unpublished-hop'), METHOD), e => e.code === Reason.StampProof);
 await settle();
 assert.equal(keys.reads, reads);
});

// While a hop's key rotates both are published and admitted; once the retiring
// key is withdrawn, the next read stops admitting it.
test('a rotation overlap admits both keys until the retiring one is withdrawn', async () => {
 let now = fixture.now * 1000, answer = publishing('retiring', 'current');
 const v = new Verifier(source(() => Promise.resolve(answer)), fixture.audience, replay(), () => now);
 for (const hop of ['retiring', 'current']) await v.verify(fresh(now, METHOD, fixture.audience, fixture.headers, hop), METHOD);
 answer = publishing('current');
 now += 301_000; // past KEY_MAX_AGE: readiness re-reads
 v.ready();
 await settle();
 await assert.rejects(v.verify(fresh(now, METHOD, fixture.audience, fixture.headers, 'retiring'), METHOD), e => e.code === Reason.StampProof);
 await v.verify(fresh(now, METHOD, fixture.audience, fixture.headers, 'current'), METHOD);
});

// Each key serves its own purpose only: an admission key published among the
// Work Context keys admits nothing, and is never trusted for a Work Context.
test('a key is used for its own purpose only', async () => {
 const response = publishing();
 response.keys.push(hopPublished('misplaced'));
 const v = new Verifier(source(() => Promise.resolve(response)), fixture.audience, replay(), () => fixture.now * 1000);
 await assert.rejects(v.verify(fresh(fixture.now * 1000, METHOD, fixture.audience, fixture.headers, 'misplaced'), METHOD), e => e.code === Reason.KeysUnavailable);
 assert.ok(!trustFromKeys(response).keys.has('hop-misplaced'));
});

// An authority that publishes no admission key admits nothing, under a fixed
// reason, and says why in the module's logs.
test('no published admission key refuses every call and says why', async () => {
 const v = new Verifier(source(() => Promise.resolve(publishing())), fixture.audience, replay(), () => fixture.now * 1000);
 await assert.rejects(v.verify(fresh(fixture.now * 1000), METHOD), e => e.code === Reason.KeysUnavailable);
 assert.ok(v.keysError instanceof NoAdmissionKeys);
});

test('admit releases its hold however the handler ends', async () => {
 const now = fixture.now * 1000;
 const store = reservations(() => now);
 const v = new Verifier(source(), fixture.audience, store, () => now);
 await assert.rejects(v.admit(fresh(now), METHOD, async () => { assert.equal(store.active.size, 1); throw new Error('handler failed'); }), /handler failed/);
 assert.equal(store.held.size, 1);
 assert.equal(store.active.size, 0);
});

// A store without reserve keeps a nonce to its retention and may then evict it.
// A delivery that arrived inside the window, but whose consumption completed
// after the retention, found an evicted nonce: it is refused on the window.
test('a consumption completing past its retention is refused', async t => {
 let slow = 0, calls = 0;
 const real = performance.now.bind(performance);
 t.mock.method(performance, 'now', () => real() + slow);
 const evicted = { async consume() { if (++calls === 2) slow = 60_000; } };
 const v = new Verifier(source(), fixture.audience, evicted, () => fixture.now * 1000);
 await v.verify(fresh(fixture.now * 1000), METHOD);
 await assert.rejects(v.verify(fresh(fixture.now * 1000), METHOD), e => e.code === Reason.StampWindow);
});

// Outside the run named exactly "local", a store that does not declare itself
// the durable one every replica shares is refused at startup, as Go refuses it.
test('startup requires a shared store outside exactly local', () => {
 try {
  for (const environment of [undefined, '', 'production', 'staging', 'local-production', 'local-docker', ' local', 'local ', 'local']) {
   if (environment === undefined) delete process.env.CODEFLY__ENVIRONMENT;
   else process.env.CODEFLY__ENVIRONMENT = environment;
   const build = store => new Verifier(source(), fixture.audience, store);
   if (environment === 'local') build(replay());
   else assert.throws(() => build(replay()), e => e.code === Reason.StoreNotShared);
   build({ ...replay(), shared: true });
   new Verifier(source(), fixture.audience); // a token-only verifier holds no store
  }
 } finally { process.env.CODEFLY__ENVIRONMENT = 'local'; }
});
