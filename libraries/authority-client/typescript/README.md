# Authority TypeScript client

Codefly generates the RPC bindings exported by `@codefly-dev/authority-client`.
The handwritten module-side check has a separate public export:

```ts
import { authenticateClaims, trustFromKeys } from '@codefly-dev/authority-client/work-context';

const trust = trustFromKeys(await authority.keys({}));   // the interface's published keys
const claims = authenticateClaims(requestHeaders, proof, audience, trust); // throws Unauthenticated
const allowed = claims.allows(resourceKind, action, exactResourceID);
```

It requires exactly one proof, token and digest and checks the SHA-256 binding,
then, in Core's order: canonical decode, issuer, the Ed25519 signature under the
published key the token names, the audience is this module, and not-before and
expiry within Core's 30-second skew. Core's structural and attenuation rules are
not reproduced; they constrain what the authority signs. Re-fetch the keys when a
token names a key id the trust does not hold. Do not send the proof to a browser.

`claims.scopes` contains frozen copies of the final actor's grants, or the owner's
when no actor exists. Each scope is evaluated independently; an omitted resource
ID asks for the whole kind; no wildcard or admin implication occurs.

Run `npm ci --ignore-scripts` and `npm test`. Tests import the built public package
exports, including the generated schema. No running SaaS, service or provider is
needed. Test signatures and fixed-clock fixtures are not live credentials.

The generator owns `src/`, including its index. The helper lives at the package
root; preserved `package.json`/`tsconfig.json` scaffolds export and compile it
alongside generated bindings. Never edit the generated index to add this helper.
