// The solution principal (conformance RunSolutionPrincipalTarget), read in
// TypeScript: the owner-blind allows refuses an owner-selected scope,
// allowsOwned admits a resource only for its owner, the hop's identity leaves
// owner-selected scopes out, and a chain dropping or changing the owner is refused.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { KeysResponseSchema, PublicKeySchema, WorkContextV1Schema, WorkScopeV1Schema } from '@codefly-dev/authority-client';
import { authenticateClaims, identityOf, trustFromKeys, Unauthenticated } from '@codefly-dev/authority-client/work-context';

const fixtures = JSON.parse(readFileSync(new URL('../../testdata/claims.json',import.meta.url),'utf8'));
const encode = bytes => Buffer.from(bytes).toString('base64url');
const signer = createPrivateKey({key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), Buffer.alloc(32)]), format: 'der', type: 'pkcs8'});
const publicKey = Buffer.from(signer.export({format:'jwk'}).x,'base64url');
const body = name => fromBinary(WorkContextV1Schema, Buffer.from(fixtures.find(f=>f.name===name).token.split('.')[0],'base64url'));
const signed = context => { const payload = toBinary(WorkContextV1Schema,context); return encode(payload)+'.'+encode(sign(null,payload,signer)); };
const trustFor = context => trustFromKeys(create(KeysResponseSchema,{issuer:context.issuer,keys:[create(PublicKeySchema,{keyId:context.keyId,algorithm:'Ed25519',publicKey})]}), ()=>(Number(context.notBeforeUnix)+1)*1000);
const stamped = token => ({'x-codefly-work-context':token,'x-codefly-hop-proof':'test-proof','x-codefly-hop-context':createHash('sha256').update(token).digest('hex')});
const read = context => authenticateClaims(stamped(signed(context)), context.audience, trustFor(context));
const scope = fields => create(WorkScopeV1Schema, fields);

// The owner-selected rows (allows refusing, allowsOwned admitting only the
// owner) are testdata/claims.json's "owner-selected" entry, run by
// work-context.test.mjs on the same rows as the Go and Python readers.

test('the hop identity never reads an owner-selected scope as the whole kind', () => {
  const context = body('session');
  context.authorityScopes = [scope({resourceKind:'record',actions:['read'],resourceOwnerId:'principal-u'})];
  assert.ok(!identityOf(context).scopes.includes('record:read'));
});

for (const [name, last, ok] of [
  ['narrowed within the owner', {resourceIds:['r1'],resourceOwnerId:'principal-u'}, true],
  ['the owner dropped', {}, false],
  ['the owner changed', {resourceOwnerId:'principal-v'}, false],
]) {
  test(`a chain hop: ${name}`, () => {
    const context = body('delegated');
    const owned = () => scope({resourceKind:'record',actions:['read'],resourceOwnerId:'principal-u'});
    context.authorityScopes = [owned()];
    for (const actor of context.actorChain) actor.grantedScopes = [owned()];
    context.actorChain.at(-1).grantedScopes = [scope({resourceKind:'record',actions:['read'],...last})];
    if (ok) read(context);
    else assert.throws(() => read(context), e => e instanceof Unauthenticated);
  });
}
