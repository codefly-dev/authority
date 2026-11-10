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
| Installation-owned role scopes: a role scope limited to what the installation owns, created through verified installation provenance with `create` on the whole kind, or recorded after the existing `AuthorizeTransfer` policy authorizes the change of owner; admin-only attachment, missing personal admin, unknown current owners, and an id another installation owns are refused by name; a viewer reads its installation's resources only, is refused another's with a named reason, and a narrowed child never widens; a detached resource leaves its owner and may be attached again | `InstallationResources`: two installed solutions, A (the viewer's) and B, each serving its own kind, a store module serving the shared kind, and two existing unowned resources; the suite delivers all three modules |
| A solution's roles and permissions are identical on every host | `solutionDeclaration` (no host fixture beyond `UnentitledToken`): the suite delivers `conformance-declared` (an installer, two roles reaching `conformance-declared-store` through its binding, an attached-only role and a role covering no operation) and installs it as `AdminToken`. `ReviewOffer` must equal one golden offer on every host (host ids, the opaque digest and `tools_composed` left out); a grant of each role to `UnentitledToken` issues exactly its declared scopes within the ceiling, every other ceiling action refused; a redelivery narrowing two roles and withdrawing one changes both answers to exactly the new declaration and refuses the capabilities issued before it. A host that does not serve `OfferService` yet names why in `ReviewOfferNotServed`, which skips the offer comparison alone and fails once the host serves it. |
| A module page is installed by composition; its roles decide who is listed for it and who may use it | `modulePageRoles` (no host fixture beyond `UnentitledToken`, `ViewerToken` (a member of at least one team, its first `team_ids` entry is used), `AdminToken`, `OtherAdminToken` and `Audience`; the delivery workloads `conformance-page-module` and `conformance-headless-roles`; `PagePayload` when the host applies a page only from its prepared signed payload; `InstallModule` is called for it as for every module): the suite delivers a module whose core manifest declares a frontend with an installer and a viewer role and `installation_role: none`, serving its own kind and `ReadKind`; delivered, it is installed active at `Organization` and at `OtherAdminToken`'s organization, holding no standing authority; neither it nor `Audience` (a module without roles) is listed by `ListOffers`, and `ReviewOffer`, `Review` and `Install` refuse both `NotFound` naming composition; installed, nobody is listed for it or entitled at it; the viewer role granted to `ViewerToken`'s team lists it in that member's `ListHeld` with `[viewer]` and issues exactly its scope, and the revoke unlists it; granted to `UnentitledToken`, it is listed and issues exactly its scope, owner-blind, and `ListResources` answers by that role (every resource), nothing once revoked; `ViewerToken` holds no role there, its organization's read on `ReadKind` included; an undeclared role is refused; a redelivery adding a role keeps the installation, the grant and the capability, and the new role is grantable; a module declaring roles and no page is refused; redelivered without roles, the installation stays, the earlier capability is refused, the holder is no longer listed, and `ViewerToken`'s organization roles decide again (`ReadKind` read). |
| Consent covers what a role reaches through the solution | `reachConsent` (no host fixture beyond `AdminToken` and `UnentitledToken`; the delivery workloads `conformance-reach` and `conformance-reach-store`; `DeliveryCredential("conformance-reach")` is the solution's actor for its hop to the store): the suite delivers a store with `Get` (read) and `Purge` (admin) and a solution whose editor reaches it through one binding; `Review` names a `reach_digest`; installed, the editor's reach at the store lists `Get` alone, `Get` is admitted through the solution and `Purge` refused; the store redelivered admitting `Purge` with write sets `upgrade_available` on the solution's installation, the holder's `ReviewOffer` still reads the approved reach (`Get`), the administrator's reads the delivered one (`Get`, `Purge`), `Purge` through the solution is refused naming the approved reach, to the holder and to the installation's own agent (its installer role, issued for the installation with `DeliveryCredential("conformance-reach")`), and an approval reviewed before is refused; a fresh `Review` and `Install` upgrade the same installation and `Purge` is admitted to both. The golden offers of `solutionDeclaration` render each role's reach too, and the install tamper cases include `reach_digest` (`INSTALLATION_APPROVAL_REACH_CHANGED`). |
| Installation identity, installed caller, explicit organization, pending, active and revoked states | `InstalledSolution`, `InstalledCredential`, `Lifecycle` |
| An installation survives delivery | `installationSurvivesDelivery` (no host fixture beyond `AdminToken` and `UnentitledToken`; the delivery workload `conformance-redelivered`): the suite delivers a solution, installs it as `AdminToken` and grants its viewer to `UnentitledToken`; a redelivery narrowing the viewer re-converges the installation (active, `approved_generation` advanced, revision moved, the grant kept, the earlier capability refused, a fresh `Install` refused as already installed); a redelivery adding a role and widening the viewer leaves it on its consent (`approved_generation` unchanged, `upgrade_available` true, the grant and the earlier capability kept, the holder issued exactly the approved viewer's scopes, the new role refused `NotFound`); a fresh `Review` and `Install` upgrade it in place (same id, active, `approved_generation` current, the grant kept, the earlier capability refused, the holder issued the delivered viewer's scopes, the new role grantable); a binding added, then widened (invoke read to read and write on `ReadKind` at `Audience`), each offers an upgrade the same way, and a binding cut back re-converges. |
| Absent installation versus no entitlement | `FailedPrecondition` with the absent-installation reason versus `PermissionDenied` with the holds-nothing reason |
| Inventory access | Admin and owner allowed; ordinary member, anonymous and foreign-organization reads refused |
| Resource discovery and whole-kind policy admission | `Resources`, plus resource-limited method admission without widening resource authority |
| Delivered method policies and advisory | Signed methods cover required scopes, any checked caller, unmarked and missing methods; local-only `LocalAdvisory` returns the same checked context/revision and the exact refusal, and still rejects an invalid capability. |
| Solution route policy | Signed GET/POST routes distinguish `requires` from `any_checked_caller`, including template paths and an unknown route. |
| Delivery and installation lifecycle | Manifest/role ceilings, forward generation, mismatched signed documents, blocked acknowledgement, then team exposure |
| Session identity and display names | Current requires person and organization IDs plus nonempty `Session.person_display_name = 7` and `Session.organization_display_name = 8`. Listed fixture people carry the same organization display name as their signed-in session through `FixturePerson.organization_display_name = 7`. |
| Revocation and expiry | Revoked delegations and installations stop existing and fresh work; expired capabilities fail after skew. |

`Lifecycle.PauseInstall` pauses the host's real install step, and returns an
idempotent resume function. The suite first removes administrator status after
Review and proves Install refuses that reviewed request at apply. After restoring
the role, it starts Install concurrently, observes the
pending row through administrator List, proves it cannot issue or be exposed,
then removes the approving administrator's live role while keeping their
membership and session. `Lifecycle.SetAdministrator(ctx, false)` performs that
host-store mutation; `true` restores the original roles. Acknowledgement must
return `PermissionDenied` naming the administrator requirement, issuance must
remain pending, and exposure and retries must be denied. Once restored, the
unchanged reviewed approval resumes to active. This exercises the existing
shared authority-core `Install` transaction recheck through each real host;
a local pass alone does not establish Accounts parity. `Lifecycle.Revoke` calls the host's existing
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

## Fixture rule: own sessions and modules that check owners (RBAC-4a)

A person's organization roles on their own session reach no owned kind of a
module that checks owners; they reach a kind it declares shared, and every kind
of a module that checks no owner. So a host's fixture puts each case that starts
from a person's own session (Audience/ReadKind, Chain, ChildScopes, Lookup,
Delegation, ParentLimits, Resources and the Matrix's allow rows) on modules that
check no owner or on shared kinds, and the cases that reach an installation's
data (SolutionRoles, InstallationChain, InstallationResources) on modules that
check owners. A Matrix deny row at a module that checks owners states the rule
for the host. ParentLimits refuses a fixture whose dropped kind the person does
not hold at the root, since its refusal would then prove nothing.

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
  permanently; an uninstall clears the installation's role grants, and an
  install never does;
- a capability through the solution, a person's or U's own, is confined to U's
  data by owner-selected scopes (`WorkScopeV1.resource_owner_id`, field 4),
  issued only to audiences declaring owner-aware checking, solutions included;
- Check with a method admits an owner-selected scope by kind and action, and
  the module enforces owner == the resource's owner (`AllowsOwned`,
  `allows_owned`, `allowsOwned`);
- an existing resource owned by the organization or a person of it joins U
  only by `AuthorizeTransfer`, with the person's own admin on that resource
  and write on U's data through their current roles, read live.

The contract has no `GrantToTeam`, `team_ids` or `agent_principal_id`, and the
installing person holds no role unless granted one.

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

The modules' side is no longer a target: the readers now honour owners and
their tests run by default. `libraries/hop/go` `owner_test.go` (the stamp never
flattens an owner-selected scope), `libraries/authority-client/go/workcontext`
`owner_test.go` (`AllowsOwned`, `Scopes()` keeps owners, a signed chain dropping
or changing the owner is refused), `libraries/authority-client/python/tests/test_owner.py`
and `libraries/authority-client/typescript/tests/owner.test.mjs` (the same in
Python and TypeScript, through the real decode path).

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

The local authority runs `Run` and `RunSolutionPrincipalTarget` with every
`go test ./plugins/registry_test` from `modules/authority/services/local/code`;
`Run`'s cases assert the same model the target does.

## Reviewed installation consent

`InstallationService/Review` returns the host's immutable target identity,
current generation, installation revision and authority-offer digest, for a
solution. A module, roles or not, is installed by composition and refused
`NotFound` here, by `Install` and by `OfferService`. The caller
reviews that offer, supplies a fresh UUID `operation_id`, and sends the unchanged
approval with `Install`. Review does not grant authority. An unchanged successful
retry returns the installation without repeating its install step; changed
inputs, a newer delivery, a changed revision or revocation refuse with a named
`INSTALLATION_APPROVAL_*` reason. A refusal requires a fresh review, not a retry
that silently substitutes current state.

The consent records the generation and offer digest approved
(`Installation.approved_generation`). A redelivery whose reviewed surface asks
nothing the approved one did not re-converges an active installation without a
click; one that asks more leaves it on its consent with
`Installation.upgrade_available` true, its holders holding what the approved
offer granted (a host keeps the approved declaration per target and
generation, `Tx.ApprovedModule`), until a fresh Review and Install on the same
installation approve the new offer in place: the install step runs again
(idempotent; the host converges the closure there), the grants are kept but
those of a role the approved offer no longer declares. A fresh approval of the
offer already approved is refused as already installed.

The lifecycle case reads Review through the published contract, checks missing
and mismatched approvals, preserves approval across acknowledgement, and checks
replay after revocation. The local core additionally rechecks the offer and
administrator in the transaction that acknowledges the install step. Its digest
covers the stored authority declarations, including roles, ceilings and bindings;
it is opaque to callers. Host-owned fixture setup stays on `InstallAsHost`.

`InstallationService.Current` is also required: an authenticated module reads its
own current installation without an administrator session. The suite checks
the returned association, namespace, invalid parent and foreign/missing workload
credentials. This is metadata only; the installation inventory remains admin-only.

`InstallationService.ListHeld` is required by the solution-principal target: a
member lists exactly the installations of A and B they hold a role on, directly
or through the team, with those roles; holding nothing, an administrator
included, is an empty list; a revoke or leaving the team drops one at once;
another organization's installation never appears, and a caller of another
organization is refused naming it (`held_installations.go`). A contract without
`ListHeld` fails that case alone.
