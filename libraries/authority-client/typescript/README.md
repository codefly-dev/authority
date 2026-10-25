# Authority TypeScript client

Codefly generates the RPC bindings exported by `@codefly-dev/authority-client`.
The handwritten, non-verifying claims reader has a separate public export:

```ts
import { readClaims } from '@codefly-dev/authority-client/work-context';

const claims = readClaims(boundToken);
// Compare claims.audience to the delivered module audience.
const allowed = claims.allows(resourceKind, action, exactResourceID);
```

The input must already be bound by a trusted integration. This package supplies
no TypeScript hop reader; readable claims are not proof of authentication. The
projection verifies neither signatures, current time, live revisions nor replay.
A warning-mode hop can bind a context the authority refused. Preserve the
integration's authentication and the module's audience, installed-definition,
ownership and live resource-visibility checks.

`claims.scopes` contains frozen copies of the final actor's grants, or the owner's
when no actor exists. Empty final grants stay empty. Each scope is evaluated
independently. An omitted/empty resource ID asks for the whole kind; a restricted
grant cannot satisfy it. Whole-kind grants include named IDs. No wildcard or
admin implication, prefix/pattern match or cross-scope action/ID merging occurs.

`UnreadableContext` names malformed/oversized envelopes, noncanonical base64url,
wrong signature length, unreadable protobuf, absent audience, unknown fields and
noncanonical protobuf bytes. This is a projection through the generated schema,
not Core's structural validator. Go also applies Core Decode's stronger schema
and attenuation checks. Shared Core-produced fixtures prove equal audience,
effective scope and exact-resource answers across the three language readers.

Run `npm ci --ignore-scripts` and `npm test`. Tests import the built public package
exports, including the generated schema. No running SaaS, service or provider is
needed. Test signatures and fixed-clock fixtures are not live credentials.

The generator owns `src/`, including its index. The helper lives at the package
root; preserved `package.json`/`tsconfig.json` scaffolds export and compile it
alongside generated bindings. Never edit the generated index to add this helper.
