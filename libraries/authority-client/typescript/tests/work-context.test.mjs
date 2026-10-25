import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { KeysResponseSchema, PublicKeySchema, WorkContextV1Schema, WorkScopeV1Schema } from '@codefly-dev/authority-client';
import { authenticateClaims, trustFromKeys, Unauthenticated } from '@codefly-dev/authority-client/work-context';

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
    assert.deepEqual(claims.scopes, fixture.scopes.map(s=>({resourceKind:s.resource_kind,actions:s.actions??[],resourceIds:s.resource_ids??[]})));
    for (const probe of fixture.probes) assert.equal(claims.allows(probe.kind,probe.action,probe.resource_id),probe.allowed);
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
    [signed(context), 'another-module', trust, /minted for audience/],
    [signed(context), context.audience, trustFor(context,(Number(context.expiresAtUnix)+3600)*1000), /expired/],
    [signed(context), context.audience, trustFor(context,(Number(context.notBeforeUnix)-3600)*1000), /not valid before/],
    [signed(create(WorkContextV1Schema,{...context, keyId:'rotated'})), context.audience, trust, /no verification key/],
    [signed(context), '', trust, /no audience/],
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
