# Authority conformance

`Run` exercises the published authority, composition, installation and session
interfaces over a host's gRPC connection. It uses descriptors, so the host can
link its own generated package. Both the local authority and Accounts must run
the same suite against their actual providers.

Required fixture omissions fail. They are fixture failures, not evidence that a
host implements the behaviour. Missing interface fields fail, just like missing fixtures. Expiry always waits past Core's clock skew; `SlowChecks` remains only for
source compatibility. Refusal assertions check the public code and named
reason; the comparison records the complete returned reason, including any
implementation prefix.

The local fixture contains Acme and Globex; Maya is a viewer, Remi an editor,
Alex an administrator, Dev the developer, Zoe a Globex administrator, and Omar
has no organization role. Omar's ops team does hold a Globex wiki installation
role, so the no-entitlement case uses the existing `fixture-no-roles` person.
An additional organization owner proves inventory access without the admin role.
Host fixtures map these behaviours to their own person and organization IDs;
providing different labels does not remove an obligation.

| Behaviour | Shared case / fixture |
| --- | --- |
| Delivered solution roles at their own audience, binding roots and children; no-role refusals; ceiling enforcement | `SolutionRoles`: a signed wiki viewer role grants Maya documents write, which she lacks independently. Replayed deliveries use deterministic authority-document bytes. |
| Rule A: current owner grants intersected with each target binding; canonical `<org>/<module>/<binding>` identity; named hop refusals | `Chain`, `ChildScopes`, and the individual binding-refusal cases |
| Enduring narrowing through two hops | `ChildScopes` and `ParentLimits`: stored delegations retain complete ceilings; parent action/resource limits and entirely dropped kinds remain capped across target changes. Multiple action/resource rows must not become a cross product. |
| Installation identity, installed caller, explicit organization, pending, active and revoked states | `InstalledSolution`, `InstalledCredential`, `Lifecycle` |
| Absent installation versus no entitlement | `FailedPrecondition` with the absent-installation reason versus `PermissionDenied` with the holds-nothing reason |
| Inventory access | Admin and owner allowed; ordinary member, anonymous and foreign-organization reads refused |
| Resource discovery and whole-kind policy admission | `Resources`, plus resource-limited method admission without widening resource authority |
| Delivered method policies and advisory | Signed methods cover required scopes, any checked caller, unmarked and missing methods; local-only `LocalAdvisory` returns the same checked context/revision and the exact refusal, and still rejects an invalid capability. |
| Solution route policy | Signed GET/POST routes distinguish `requires` from `any_checked_caller`, including template paths and an unknown route. |
| Delivery and installation lifecycle | Manifest/role ceilings, forward generation, mismatched signed documents, blocked acknowledgement, then team exposure |
| Session identity and display names | Current requires person and organization IDs plus nonempty `Session.person_display_name = 7` and `Session.organization_display_name = 8`. |
| Revocation and expiry | Revoked delegations and installations stop existing and fresh work; expired capabilities fail after skew. |

`Lifecycle.PauseInstall` pauses the host's real install step, and returns an
idempotent resume function. The suite starts Install concurrently, observes the
pending row through administrator List, proves it cannot issue or be exposed,
then resumes acknowledgement. `Lifecycle.Revoke` calls the host's existing
uninstall path. These hooks arrange state; the assertions use the public
interfaces. No synthetic issuer or parallel permission resolver is allowed.

The authority interface returns an advisory decision, not a hop stamp. The hop
transport additionally must preserve it while forwarding: the local hop's
`TestPermissivePolicyUsesTheAuthorityAdvisoryIdentity` checks the decision and
signed stamp round trip, and its proxy tests check forwarding. A shared Check
pass alone does not certify a deployed hop, browser, or SaaS provider.

Run locally from `modules/authority/services/local/code` with
`go test -race ./plugins/registry_test`. Accounts' runner and dependency setup
are documented in its `module/services/accounts/HOST_INTERFACE.md`. Use an
external Go modfile to select this checkout of the suite when the Accounts
checkout must remain read-only. Missing Accounts fixtures must be implemented
by that host; they must not be converted into skips here.
