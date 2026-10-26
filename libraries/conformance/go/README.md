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
`SolutionPrincipalCase`: an installed solution is a principal U of its
organisation (a stable UUID, reused by a reinstall, disabled by an uninstall,
distinct per organisation); the installation acting for itself is U, with the
install request's role; the solution's roles are levels on U's data, granted
and revoked by an organisation administrator or the solution's installer
(`GrantRole`, `RevokeRole`, `ListRoleGrants`); a capability through the
solution is confined to U's data, by owner-selected scopes
(`WorkScopeV1.resource_owner_id`, field 4), issued only to an audience that
declares owner-aware checking; an existing person- or organisation-owned
resource joins U only by `AuthorizeTransfer`, with the person's own admin on it
and at least editor on U. The target deletes `GrantToTeam`, `team_ids` and
`agent_principal_id`.

The suite first names what the published contract lacks and what it still
carries, then runs these cases, each making its own grants:

1. install creates the solution principal and its roles; a reinstall keeps its UUID; another organisation's is another principal
2. the install request's role is the agent's, and no person's: the owner and the organisation administrator hold no role (the agent's owner id is U; it needs its operation binding)
3. without a role on the solution a person is refused, naming the reason
4. a viewer reads exactly what the principal owns (root, child, Check, `ListResources` with owner, owner with ids), and nothing a person, an installation, the organisation or another principal owns
5. a capability through the solution is confined to the principal's data; the person's own grants never flow in
6. owner-selected scopes are issued only to an audience that checks owners
7. a resource created through the solution is owned by its principal, the person its author
8. an editor writes and a viewer cannot, each by name
9. an organisation administrator or the solution's installer grants; anyone else, and every malformed grant, is refused by name
10. another installation's and another organisation's members never reach the principal's data
11. a child never widens the owner, the actions or the ids it narrowed to
12. an existing resource joins the principal only by a transfer from a person or the organisation, administered through the person's own grants, by an editor of the principal (and nine named refusals)
13. revoking a person's role stops their access at once, theirs alone; their old capabilities stay dead after a re-grant
14. a team's role is its members' access; revoking it or leaving the team stops them at once; old capabilities stay dead after a re-grant
15. a person leaving the organisation loses the solution's data at once
16. uninstalling disables the principal at once and its data stays owned; old capabilities stay dead after reinstall and re-grant

Two library targets pin the modules' side: `libraries/hop/go`
`TestAnOwnerSelectedScopeNeverReadsAsTheWholeKind` (the stamp never flattens an
owner-selected scope into a whole-kind one, and owner-blind `Allows` refuses
it) and `libraries/authority-client/go/workcontext`
`TestClaimsAdmitAnOwnerSelectedScopeOnlyForItsOwner` (`AllowsOwned` takes the
resource's owner; owner and ids both match).

When the target joins `Run`, it supersedes Run's `GrantToTeam`/`team_ids`
steps (the installation lifecycle's exposure, the callee-staleness probe's
grant), and Run reads the installation's acting principal through
`installationPrincipal`, so one host passes both.

Run everything with `AUTHORITY_TARGET=solution-principal`: from
`modules/authority/services/local/code`,
`go test ./plugins/registry_test -run SolutionPrincipal`, and `go test ./...`
in `libraries/hop/go` and `libraries/authority-client/go`. Each skips without it.
