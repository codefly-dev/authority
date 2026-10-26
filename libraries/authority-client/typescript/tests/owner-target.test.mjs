// TARGET (solution principal; conformance RunSolutionPrincipalTarget). Run with
// AUTHORITY_TARGET=solution-principal. A module served in TypeScript never reads
// an owner-selected scope as the whole kind: the owner-blind allows refuses it,
// and allowsOwned admits a resource only for its owner (an owner with ids only
// when both match; a plain scope names resources, not owners).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { KeysResponseSchema, PublicKeySchema, WorkContextV1Schema, WorkScopeV1Schema } from '@codefly-dev/authority-client';
import { authenticateClaims, trustFromKeys } from '@codefly-dev/authority-client/work-context';

const skip = process.env.AUTHORITY_TARGET !== 'solution-principal' && 'target contract, not yet implemented: run with AUTHORITY_TARGET=solution-principal';
const fixtures = JSON.parse(readFileSync(new URL('../../testdata/claims.json',import.meta.url),'utf8'));
const encode = bytes => Buffer.from(bytes).toString('base64url');
const signer = createPrivateKey({key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), Buffer.alloc(32)]), format: 'der', type: 'pkcs8'});
const publicKey = Buffer.from(signer.export({format:'jwk'}).x,'base64url');
const body = name => fromBinary(WorkContextV1Schema, Buffer.from(fixtures.find(f=>f.name===name).token.split('.')[0],'base64url'));
const signed = context => { const payload = toBinary(WorkContextV1Schema,context); return encode(payload)+'.'+encode(sign(null,payload,signer)); };
const trustFor = context => trustFromKeys(create(KeysResponseSchema,{issuer:context.issuer,keys:[create(PublicKeySchema,{keyId:context.keyId,algorithm:'Ed25519',publicKey})]}), ()=>(Number(context.notBeforeUnix)+1)*1000);
const stamped = token => ({'x-codefly-work-context':token,'x-codefly-hop-proof':'test-proof','x-codefly-hop-context':createHash('sha256').update(token).digest('hex')});
const read = context => authenticateClaims(stamped(signed(context)),'test-proof',context.audience,trustFor(context));

test('claims admit an owner-selected scope only for its owner', {skip}, () => {
  assert.ok(WorkScopeV1Schema.fields.some(f => f.name === 'resource_owner_id'), 'target: WorkScopeV1 has no resource_owner_id');
  const context = body('session');
  context.authorityScopes = [
    create(WorkScopeV1Schema,{resourceKind:'record',actions:['read'],resourceOwnerId:'principal-u'}),
    create(WorkScopeV1Schema,{resourceKind:'note',actions:['read'],resourceIds:['n1'],resourceOwnerId:'principal-u'}),
    create(WorkScopeV1Schema,{resourceKind:'plain',actions:['read']}),
  ];
  const claims = read(context);
  assert.ok(!claims.allows('record','read') && !claims.allows('record','read','r1') && !claims.allows('note','read','n1'), 'target: the owner-blind allows admits an owner-selected scope');
  assert.equal(typeof claims.allowsOwned, 'function', 'target: claims have no allowsOwned(kind, action, resourceId, ownerId)');
  for (const [kind, resource, owner, allowed] of [
    ['record','r1','principal-u',true], ['record','r1','principal-v',false], ['record','r1','',false],
    ['note','n1','principal-u',true], ['note','n2','principal-u',false], ['note','n1','principal-v',false],
    ['record','','principal-u',true], ['note','','principal-u',false],
    ['plain','p1','principal-u',true],
  ]) assert.equal(claims.allowsOwned(kind,'read',resource,owner), allowed, `${kind} ${resource} ${owner}`);
});
