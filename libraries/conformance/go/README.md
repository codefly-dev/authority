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

`UnexposedTeam` is a real team of the organization that `InstalledSolution`
does not reach when the run starts; the host's own fixture creates it or finds
one. The staleness probe exposes the installation to it to move the
organization's authority, so a host that validates team ids sees an id it
issued, never one the suite invents. A team the installation already reaches,
as a fixed id does on a second run against a long-lived authority, moves
nothing; the probe checks the installation's teams first and fails it as a
fixture error, never as missed staleness.

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

Empty workload organizations are required refusals when the module has multiple
active installing organizations or none, naming “must name the organization of
the work item”. `WorkloadOrganizations` supplies these two fixtures. Successful
single-organization inference remains a local convenience, not a shared promise.

## Target: solution principal (not yet part of `Run`)

`RunSolutionPrincipalTarget` specifies solution identity before any host
implements it. The model, in full, is the doc comment on
`SolutionPrincipalCase`. In short:

- an installed solution is a principal U of its organization: a stable UUID,
  reused by a reinstall, disabled by an uninstall, distinct per organization;
- the installation acting for itself is U, with the install request's role;
- the solution's roles are levels on U's data, and role names carry no rank;
  they are granted, revoked (both idempotent) and listed by an administrator
  of the installation's organization or a holder of that installation's
  installer role (`GrantRole`, `RevokeRole`, `ListRoleGrants`); a request
  naming another organization's installation is refused;
- a new grant leaves existing capabilities valid; a revoke, leaving a team or
  the organization, an uninstall or a withdrawn `owner_aware` invalidates them
  permanently; an uninstall clears the installation's role grants;
- a capability through the solution, a person's or U's own, is confined to U's
  data by owner-selected scopes (`WorkScopeV1.resource_owner_id`, field 4),
  issued only to audiences declaring owner-aware checking, solutions included;
- Check with a method admits an owner-selected scope by kind and action, and
  the module enforces owner == the resource's owner (`AllowsOwned`,
  `allows_owned`, `allowsOwned`);
- an existing resource owned by the organization or a person of it joins U
  only by `AuthorizeTransfer`, with the person's own admin on that resource
  and write on U's data through their current roles, read live.

The target deletes `GrantToTeam`, `team_ids` and `agent_principal_id`, and
changes the composition contract's text that the installing person holds the
installer role.

The suite first names what the published contract lacks and still carries,
then runs these cases, each making its own grants:

1. install creates the solution principal and its roles; a reinstall keeps its UUID; another organization's is another principal
2. the install request's role is the agent's, and no person's; the agent is confined to the principal's data (eight widening asks refused)
3. without a role on the solution a person is refused, naming the reason
4. a viewer reads exactly what the principal owns, and nothing a person, an installation or another principal owns
5. a route requiring the kind admits an owner-selected scope; the module enforces the owner
6. a capability through the solution is confined to the principal's data; the person's own grants never flow in (the store's kind and the solution's own kind)
7. every audience receiving owner-selected scopes declares owner-aware checking, solutions included (a person's root, a solution's child, the agent, and a module's hop)
8. withdrawing owner-aware checking refuses the owner-selected capabilities issued before, and re-declaring it revives none
9. a resource created through the solution is owned by its principal, the person its author
10. a role writes when its scopes hold write, whatever it is called; a viewer cannot
11. an administrator of the organization or the installation's installer grants, revokes and lists; anyone else (another organization's administrator, another installation's installer, a request naming another organization's installation), and every malformed grant, is refused by name; grants are idempotent
12. another installation's and another organization's members never reach the principal's data
13. a child never widens the owner, the actions or the ids it narrowed to
14. an existing resource joins the principal only by a transfer from the organization or its person, administered on that resource through the person's own grants, by a holder of write on the principal's data (fourteen named refusals)
15. revoking a person's role stops their access at once, theirs alone; their old capabilities stay dead after a re-grant
16. a team's role is its members' access; revoking it or leaving the team stops them at once; a direct grant survives the team's revoke
17. a person leaving the organization loses the solution's data at once
18. uninstalling disables the principal at once and its data stays owned; old capabilities (a person's, the agent's, a parent's children) stay dead after reinstall and re-grant

Library targets pin the modules' side: `libraries/hop/go`
`TestAnOwnerSelectedScopeNeverReadsAsTheWholeKind`,
`libraries/authority-client/go/workcontext`
`TestClaimsAdmitAnOwnerSelectedScopeOnlyForItsOwner` and
`TestScopesKeepTheirResourceOwner`,
`libraries/authority-client/python/tests/test_owner_target.py` and
`libraries/authority-client/typescript/tests/owner-target.test.mjs`.

### Run cases the target supersedes, and how one host passes both

Each asserts the earlier model while the published contract is the earlier
one, and the target's model once it carries `Installation.principal_id`
(`client.solutionPrincipal`):

| Run case | Under the target |
| --- | --- |
| `conformance.go` an installation acts for itself | its owner is `principal_id` (`installationPrincipal`) |
| `conformance.go` the permission matrix | a row at a solution audience asks within the owner the person holds there |
| `conformance.go` a callee refuses what does not verify (staleness) | the viewer's direct roles are revoked and restored exactly (`RevokeRole`), not a team exposure; the fixture viewer holds them only directly |
| `conformance.go` `applyManifest` | a solution delivery declares `owner_aware` |
| `solution_roles.go` [0] own audience, [1] consumed child, [2] binding root, [4] binding ceiling | owner-selected asks and scopes; the delivery declares `owner_aware` |
| `solution_roles.go` [3] no solution role | refused "holds no role" |
| `installation_chain.go` | the agent root's owner is U; every hop is owner-selected |
| `solution_tools.go` | the asks at the solution audience are owner-selected |
| `installation_lifecycle.go` exposure | a team's `GrantRole`, read back through `ListRoleGrants` |

A host fixture under the target grants roles with `GrantRole` (the
installing person holds no role unless granted, so a Matrix row such as the
installer publishing at a solution needs an explicit installer grant), and
declares `owner_aware` on the modules solutions consume.

Run everything with `AUTHORITY_TARGET=solution-principal`: from
`modules/authority/services/local/code`,
`go test ./plugins/registry_test -run SolutionPrincipal`; `go test ./...` in
`libraries/hop/go` and `libraries/authority-client/go`; `pytest` in
`libraries/authority-client/python`; `npm test` in
`libraries/authority-client/typescript`. Each target skips without it.
