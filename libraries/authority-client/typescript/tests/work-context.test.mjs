import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { WorkContextV1Schema, WorkScopeV1Schema } from '@codefly-dev/authority-client';
import { readClaims as boundClaims, UnreadableContext } from '@codefly-dev/authority-client/work-context';

const stamped = token => ({'x-codefly-work-context':token,'x-codefly-hop-proof':'test-proof','x-codefly-hop-context':createHash('sha256').update(token).digest('hex')});
const readClaims = token => boundClaims(stamped(token),'test-proof');

const fixtures = JSON.parse(readFileSync(new URL('../../testdata/claims.json',import.meta.url),'utf8'));
const encode = bytes => Buffer.from(bytes).toString('base64url');
// Projection-only inputs: synthetic signatures never represent authenticated calls.
const tokenFor = context => encode(toBinary(WorkContextV1Schema,context))+'.'+encode(new Uint8Array(64));
const scope = (actions, resourceIds=[]) => create(WorkScopeV1Schema,{resourceKind:'profiles',actions,resourceIds});

for (const fixture of fixtures) {
  test(`Core-minted fixture: ${fixture.name}`, () => {
    const claims = readClaims(fixture.token);
    assert.equal(claims.audience,fixture.audience);
    assert.deepEqual(claims.scopes, fixture.scopes.map(s=>({resourceKind:s.resource_kind,actions:s.actions??[],resourceIds:s.resource_ids??[]})));
    for (const probe of fixture.probes) {
      assert.equal(claims.allows(probe.kind,probe.action,probe.resource_id),probe.allowed);
    }
  });
}

test('later matching grant works without merging actions and resource IDs',()=>{
  const context = create(WorkContextV1Schema,{audience:'model',authorityScopes:[scope(['read'],['a']),scope(['invoke'],['b'])]});
  const claims = readClaims(tokenFor(context));
  assert.equal(claims.allows('profiles','read','a'),true);
  assert.equal(claims.allows('profiles','invoke','b'),true);
  assert.equal(claims.allows('profiles','invoke','a'),false);
  assert.equal(claims.allows('profiles','read','b'),false);
  assert.equal(claims.allows('profiles','read'),false);
  assert.equal(claims.allows('other','read','a'),false);
  assert.throws(()=>{claims.audience='other';},TypeError);
  assert.throws(()=>{claims.scopes[0].actions.push('invoke');},TypeError);
  assert.throws(()=>{claims.scopes[0].resourceIds.push('b');},TypeError);
});

test('final actor grants including an empty list override earlier scopes',()=>{
  const fixture=fixtures.find(f=>f.name==='delegated');
  const context=fromBinary(WorkContextV1Schema,Buffer.from(fixture.token.split('.')[0],'base64url'));
  context.actorChain.at(-1).grantedScopes=[];
  const claims=readClaims(tokenFor(context));
  assert.deepEqual(claims.scopes,[]);
  assert.equal(claims.allows('record','read','record-conformance'),false);
});

test('whole-kind grants include exact resources, with no action implication',()=>{
  const claims=readClaims(tokenFor(create(WorkContextV1Schema,{audience:'model',authorityScopes:[scope(['read','admin','*'])]})));
  assert.equal(claims.allows('profiles','read'),true);
  assert.equal(claims.allows('profiles','read','a'),true);
  assert.equal(claims.allows('profiles','invoke','a'),false);
  assert.equal(claims.allows('profiles',''),false);
  assert.equal(claims.allows('','read'),false);
});

test('malformed, oversized and noncanonical envelopes refuse by name',()=>{
  const valid=fixtures[0].token, payload=valid.split('.')[0];
  for(const token of ['', 'abc','a.b.c','.','a.b','é.x','a'.repeat(32769),valid+'=',payload+'.AA',payload+'.'+'A'.repeat(85)+'B']) {
    assert.throws(()=>readClaims(token),UnreadableContext);
  }
});

test('unknown root/nested fields, duplicate payload and absent audience refuse',()=>{
  const context=create(WorkContextV1Schema,{audience:'model',authorityScopes:[scope(['read'])]});
  const payload=toBinary(WorkContextV1Schema,context), signature=encode(new Uint8Array(64));
  assert.throws(()=>readClaims(encode(new Uint8Array([...payload,0xf8,7,1]))+'.'+signature),UnreadableContext);
  assert.throws(()=>readClaims(encode(new Uint8Array([...payload,...payload]))+'.'+signature),UnreadableContext);
  const original=toBinary(WorkScopeV1Schema,context.authorityScopes[0]);
  context.authorityScopes[0]=fromBinary(WorkScopeV1Schema,new Uint8Array([...original,0x78,1]));
  assert.throws(()=>readClaims(tokenFor(context)),UnreadableContext);
  assert.throws(()=>readClaims(tokenFor(create(WorkContextV1Schema))),UnreadableContext);
});

test('projection is not authentication or Core structural validation',()=>{
  const payload=fixtures[0].token.split('.')[0];
  assert.deepEqual(readClaims(payload+'.'+encode(new Uint8Array(64))).scopes,readClaims(fixtures[0].token).scopes);
  // Like Python, this projection accepts readable but structurally incomplete
  // claims. Go deliberately retains Core Decode's stronger structural refusal.
  assert.equal(readClaims(tokenFor(create(WorkContextV1Schema,{audience:'model'}))).audience,'model');
});


test('the reader refuses missing, forged and substituted stamps',()=>{
 const token=fixtures[0].token;
 for (const change of [
  h=>delete h['x-codefly-hop-proof'],h=>h['x-codefly-hop-proof']='forged',
  h=>delete h['x-codefly-hop-context'],h=>h['x-codefly-hop-context']='0'.repeat(64),
  h=>h['x-codefly-work-context']=fixtures[1].token,
  h=>h['x-codefly-work-context']=[token,token],
 ]) {
  const headers=stamped(token);change(headers);
  assert.throws(()=>boundClaims(headers,'test-proof'),UnreadableContext);
 }
 assert.throws(()=>boundClaims(stamped(token),''),UnreadableContext);
 assert.throws(()=>boundClaims([...Object.entries(stamped(token)),['X-Codefly-Work-Context',token]],'test-proof'),UnreadableContext);
});
