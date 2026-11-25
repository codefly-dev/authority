# local authority

The development implementation of the host interfaces, one process: it signs
fixture people in with their roles, issues and verifies Work Contexts, knows the
composition from the manifests the run delivers, and answers the installation,
artifact and access interfaces. The repository's [README](../../../../README.md) is the
story and the rules; this page is what the process keeps and where.

**A host over the core.** Every decision and every signature is the generic
authority core's (`libraries/authority-core/go`), over its in-memory store
(`memstore`): modules, installations, role grants, delegations, revisions and
issuance. This service keeps what a host owns: the fixture and its sign-in
tokens (`pkg/business/state` seeds the core's store from them), sessions,
workload attestation against the launcher's anchor, signed delivery
admission, method admission on `Check`, and approvals. The plugins translate
the wire to the core's calls (`pkg/business/issuer`, `plugins/installation`).

Request-facing installation methods require a person value and current stored
authority. Trusted fixture setup and teardown use the separate `InstallAsHost`
and `UninstallAsHost` methods; a missing or unauthenticated person never selects
host power. Module installations remain composition-owned after withdrawal.
Role calls answer as foreign when the caller is neither administrator nor a
holder of the installation's admin role, including for an installation in their
own organization.

Child issuance preserves the verified parent's workspace/project identifiers
and each prior actor's agent/organization identifiers while deriving the new
target's grants. These fields remain absent when the parent omitted them;
replaying an actor does not substitute the task's organization for that actor's.
The shared core's `TestChildPreservesVerifiedTaskAndActorProvenance` exercises
populated parents through its production minter, child issuance and Check over
two exchanges, including action/resource limits. The ordinary Issue request
does not originate these optional fields. This test does not establish a live
populated-parent fixture or cross-host conformance coverage.

| State | Where | Across a restart |
|---|---|---|
| who exists, what they hold, what is installed by fixture | `code/fixtures/<name>.yaml`, selected by the run | re-read: fixture, not state |
| the composition: each module's manifest, generation and bindings | memory, re-delivered by the run | re-delivered |
| sessions, delegations, installations and role grants made at runtime | memory (the core's `memstore`) | forgotten |
| **approvals**: a person's consent to one exact artifact for one installation | **the module's [store](../store/README.md)**, `approvals` table, when the run composes it; memory otherwise | **kept**: a run of the approved artifact is answered after a restart, and a revoked one stays refused |

**How it chooses.** `code/work.go` (`approvalsFor`) reads the store's
`postgres/read-write-connection` secret through the SDK. Delivered: approvals
are `pkg/infra/postgres`, as the runtime role `app_authority` (read, insert,
update, never delete), and the boot log says `approvals persist in the
authority's store`. Not delivered — `go test` through `pkg/business/testkit`, or
a run that selects the local authority without the store — approvals are
`state.MemoryApprovals`, and the boot log says so. A delivered connection that
does not answer refuses to boot: the store was composed, so a local authority that
forgot consent would be the wrong local authority. Both implementations pass
`pkg/business/approvalstest.Contract`.

**Tests.** `go test ./...` runs everything in memory. The Postgres suite
(`pkg/infra/postgres`) runs when `AUTHORITY_STORE_TEST_DATABASE_URL` names a
Postgres whose login may create databases: it creates one per test, applies the
store's migration and acts as `app_authority`; unset, it skips and says why.

```bash
AUTHORITY_STORE_TEST_DATABASE_URL='postgres://postgres:…@127.0.0.1:5432/postgres?sslmode=disable' go test ./...
```

Generated code (`pkg/gen`, `*_gen.go`, `main.go`) comes from `codefly generate`
and the agent; `work.go` and everything under `pkg/business`, `pkg/infra` and
`plugins` is written here.

## Where the fixture is served

The fixture's people sign in by a token the repository holds, so the fixture
is served only where that is meant, and nothing turns it on by default:

- the service starts only in the run named exactly `local`
  (`CODEFLY__ENVIRONMENT`, the one "local" signal it reads; `localRun`,
  `work.go`), never in a pod, and only on a fixture the run selected by name
  (`CODEFLY__FIXTURE`, which the environment's `fixture:` or `--fixture`
  delivers). An environment that selects none is refused by name rather than
  handed `local`;
- the session plugin lists fixture people and signs them in by fixture token
  only when it was told the run is one (`wiring.SetFixtureRun`, set after the
  checks above); otherwise `ListFixturePeople` and `SignIn` answer
  `FailedPrecondition`;
- an advisory `Check` is answered as advice in that run alone.

The edge and the hop's HTTP face bind the host the run resolved for them
(loopback on a developer's machine) and the wildcard only in a container.

## The setup read

Beside the installation interface the local authority serves
`host.installation.v1.OfferService` for the edge's setup page. It is an
administrator's read and grants nothing:

- `ListOffers`: the delivered solutions, which an administrator installs
  through `Review` and `Install`. A module is never offered, roles or not.
- `ReviewOffer`: one solution's roles, the composed operations each role's
  scopes cover (from the delivered authority documents), and the tools
  composed for those operations, read with its consent tuple in one
  transaction; with `roles_declared`, `page` (as the stored declaration knows
  it) and `closure` (every module the solution reaches, roles or not), so a
  host asks nothing per module.

Only a solution is installed by an administrator. Every module, with or
without roles, with or without a page, is installed by composition in every
organization where it is composed, holding no principal and no standing
authority; `Review`, `Install` and `ReviewOffer` refuse it `NOT_FOUND`, and a
person never uninstalls it. A module page's roles decide who may use it (its
page included): `GrantRole`, `RevokeRole`, `ListRoleGrants` and `ListHeld`
work on its composition installation as on a solution's, and a person is
issued at its audience only for a role held there. Its roles reach through its
bindings as a solution's do: a role may name what a binding consumes, and a
holder's hop through the page carries the role cut to the binding (never an
owner: a page has no principal); with a solution on the path, the solutions'
roles decide alone. A module that gains or
loses roles keeps its installation; the grants of a role a delivery stops
declaring end with that delivery, the others stay.

**A page's call goes through its target's binding.** One rule for every page,
a module page's or a solution's, the one its backend is held to: a person's
`Issue` naming `page_target` (set by the host's module edge, which knows the
page it serves) is issued, when that target declares a binding to the
audience, as the target's own hop over it (`IssueForPage`): the person's
capability at the target, then the binding, so they hold there their role on
the target cut to the binding, with the target as the actor. A module the
target declares no binding to is an edge on the person's own access, as an
`Issue` naming no page. That hop's one actor is the target, of kind `page`:
the person present on the page, which consent in person (an artifact's
`activate`) admits as it admits no other actor; any hop after it is a
module's again. Only the module edge names a page: the edge serves a page's
module calls at `/api/solutions/<alias>/proxy/_browser/<package.Service>/<Method>`
(the path a hosted page reaches them on), names the alias, keys its held
context on it, and presents its own workload credential (`module-identity`) as
the actor; an `Issue` naming a page with no actor or another workload's is
refused. The shared conformance suite holds both hosts to it.

**Roles name what they reach, through a binding; shared kinds go unselected.**
A solution's or module page's role may name what it serves and what its own
bindings consume, and, declared through one of its bindings (`RoleV1.through`,
from a role scope's `through:` in the module contract), what the modules that
binding reaches consume onward: a wiki user's role names the model's profiles
and the document store's read through its binding to the agent. Delivery holds
each reachable from its binding in the composition (`decide.Unreached`), at the
declaring module's own delivery, which is refused naming a kind its binding
reaches nowhere. A later delivery of a module the reach walks through (an
agent dropping a binding, or withdrawn) is never refused for it: the
installation reports it in `Installation.unreached` (journaled once per change
as `installation.reach_unreached`, then `installation.reach_restored`), grants
nothing there, as each hop narrows, and re-converges by itself once a delivery
reaches it again, asking the administrator nothing new for a reach its approved
declaration names. A walk that meets a module not yet composed waits for it.
A module page's installation is held at an approved reach exactly as a
solution's is: composition takes its consent receipt (`ConsentReceipt`
operation `composition`, journaled as `installation.reach_adopted` held by
composition) at the reach the page has when it is installed, or when a host
that installs modules starts. A delivery, of the page or of a module it
reaches, that widens what one of its roles reaches holds the installation at
the approved reach and offers an upgrade (`installation.upgrade_available`
naming what widened); no grant is revoked and none is widened. An
administrator, or a holder of the page's admin role on its installation,
approves the upgrade through `Review` and `Install`, as a solution's is
approved. A module may declare
kinds `shared` (the authority document's `shared_kinds`, from a scope
ceiling's `shared: true`): kinds no owner holds, such as a model's profiles. A
scope of one is issued unselected, even through a solution's binding; every
other kind keeps its owner selector, and a module that checks no owner still
receives no owner-selected scope.

**Consent covers reach.** Each role in `ReviewOffer` carries its `reach`: every
place a holder can cause an operation, as a static maximum computed by the
core from declarations alone (`decide.Reach`): on the solution itself (its
scopes and their confinement), through the solution's bindings and onward
through each reached module's bindings (what a person-owned hop can carry:
the role within what the module serves, cut to each binding and to the limits
the chain carries, as issuance cuts it), and on the holder's own session for
an edge the solution's page calls (no scopes: the holder's own grants decide
there). There is one row per module and way, its path a shortest witness.
The walk is a join fixed point: each module keeps one limit, the join of
every limit a chain can arrive with, and is walked again only when it grows,
so re-entries and self-bindings are counted and the cost stays polynomial
(milliseconds on dense compositions of 16 modules and 8 kinds). It starts
where a holder's chains can (at the solution, naming a binding there, or
from a delegation through a binding) and takes invoke and lookup hops apart.
Beside each role's reach, the consent records the reach of all the declared
roles held together; a person holding several roles is held to it, within
those roles' scopes. Each row records the policy of every declared method
of its module, each face of an operation its own, so a call is judged on
the approved policy of the face it uses. A recorded reach is trusted only when
its digest is the one the approval named. Each row lists the
operations its scopes are admitted to, one per operation (a Connect route
`POST /pkg.Service/Method` is the gRPC procedure). A binding's headless
scopes are its module acting for nobody: a hop for a person, a delegation or
an installation's agent never exercises them. `Review` hands `reach_digest` with the
consent tuple and `Install` refuses an approval whose reach moved
(`INSTALLATION_APPROVAL_REACH_CHANGED`). A delivery of any module that widens
an installed solution's reach (a method relaxed, a binding added or widened,
a module newly reachable) leaves its consent standing and sets
`upgrade_available`, though the solution did not change; until an
administrator approves, holders, delegations through the solution and the
installation's own agent hold the approved reach: a hop carries no more than
it lists, and a call to an operation it does not list is refused by name. A
consent recorded before reach was kept adopts, once, the reach it has
(journaled `installation.reach_adopted`), before the next delivery or when
the host starts (`ReconcileOrganizations`, or `AdoptLegacyReach`). A delivery that only narrows the reach
re-converges the consent without a click. The reach is an upper bound:
resources and owners are still checked at every call.

The tools come from the workspace group `runnable-bindings`, read through the
SDK as a tool caller reads it. Only Connect-callable bindings with a tool
exposure whose invoke and lookup scopes the role covers are listed, one per tool
name, Connect endpoint first. A run that composes no bindings says so
(`tools_composed: false`) rather than listing none. The local authority does not
declare the group: declaring it would give it authority bindings of its own.

## What a composition adds to the fixture

The embedded fixture (`code/fixtures/local.yaml`) says who exists and who
administers each organisation, in the authority's own vocabulary only: at
`acme`, `dana` (its administrator, and every target's admin), `carol` (every
target's user) and `bob` (no role anywhere); at `globex`, `zoe`, its one
administrator and the admin of every target there, who holds nothing of
Acme's and is the person a suite proves another organisation's refusal with.
A fragment names those ids and no others, and seats a person only on an
installation of their own organisation: a row seating `zoe` at `acme`, or
`dana` at `globex`, is refused by name. It
names no module's kinds, no solution and no stand-in module, and an
organisation role in it is a name: it decides administration and grants
nothing at any module. **A person reaches a module only through a role
(`admin`, `user`) on an installation**, so what a composition adds is who is
seated where, never a grant of a module's kinds to an organisation role. Its
part is a **fragment** of the workspace configuration document
`fixture-composition`:

- a module ships `configurations/<profile>/fixture-composition.yaml` in its own
  directory for what is its own (a module it stands in for), and nothing about
  any other module;
- a composition ships the same file in its own module's directory, for what
  only it knows: the installation of its solution, and who is seated on the
  roles of its page.

```yaml
schema: codefly.dev/authority/fixture-composition/v1
installations:  # installations of a solution the run composes, the fixture's own path
  # role: the installation's own (its agent's) role, omitted for a target that
  # declares it (installation_role, `none` included: the authority refuses a
  # role overriding the declaration); owner: who installed it, granted the
  # admin role; teams: each granted role on the installation (so a row
  # granting teams names it);
  # members: by declared role, who joins its `<target>-<role>` team.
  - {organization: acme, target: atlas, role: user, owner: dana, members: {user: [carol]}}
modules:        # a module the run supervises itself, until its own delivery
  - module: oracle
    kinds: [{kind: oracle.answers, actions: [read]}]
```

**The run merges them.** Before the local authority boots, `codefly run`
merges the fragment of every module the workspace composes into the
workspace's own `configurations/<profile>/fixture-composition.yaml`, which the
local authority reads (`codefly generate fixture-composition --env local` does
the same on its own). That file is generated: it says so in its first line and
is never committed. A hand-written one is never overwritten: `codefly generate`
refuses, and `codefly run` reads it as it stands and says that no module's
fragment is applied until it is deleted. The merge
rules are this repository's, in [`libraries/fixture-composition`](../../../../libraries/fixture-composition/go/README.md),
the one parser of the document:

- every statement has exactly one source: one installation (its organisation
  and target), one stand-in module. Two fragments stating the same one are
  refused naming both, even when they agree, so the fragment that owns a
  statement is the one a reader goes to. One **fragment** stating the same one
  twice is refused too;
- the result does not depend on the order fragments are found in.


The authority module's own fragment
(`modules/authority/configurations/local/fixture-composition.yaml`) is the
schema line alone, so a composition of the authority and nothing else boots
on the fixture alone.

**The same people on every target.** The fixture carries one row whose
target is `"*"`: it stands for every role-gated target the run composes (a
solution, a module page declaring roles), whatever the composition is. Each
role such a target declares goes to its conventional `<target>-<role>` team,
created in this host's directory and granted the role on the installation
through the core (`authority.GrantRoleTeamsAsHost`), and each person under
`members` joins the team of the role named, where the target declares it:
Carol the user, Dana the admin; Bob joins none, and is the person every page
refuses. The row installs
nothing — a module page is installed by composition, a solution by a row
naming it or by an administrator at the edge's setup page — and seats each
the moment it is active, after the fixture loads, after every delivery and
after every install (`pkg/business/state/teams.go`). A composition's row
naming a target is kept, and that target is seated the same way; its own
`members` join too. The boot log names each: `seats wiki at acme:
wiki-admin [dana] wiki-user [carol]`.

**The contract.** The `schema` line names the document's one schema. Its sections, and
the shipped fixture's organisation and person ids (`acme`, `dana`, `carol`,
`bob`), are a contract with every composing repository. The larger matrix
exists only in the test kit; a fragment naming a person or organisation absent
from the shipped fixture is refused at boot. The document has no `roles` section
([a fragment that still has one](../../../../libraries/fixture-composition/go/README.md)).

**What is refused.** Each of these refuses the merge or the boot by name and
changes nothing:
- an empty or null document, a section spelled `null`, an unknown field, or a
  schema other than the one above (the refusal says which to state);
- a `roles` section, whatever schema the document states: no organisation role
  is granted a module's kinds, and the refusal says where a person's reach is
  stated now (`installations: members`);
- a stand-in module with no kind, a kind with no action, a wildcard kind or
  action (`*`), a kind or action outside the grammar, surrounding whitespace
  included;
- an installation whose organisation, owner or members the fixture does not
  define, a row standing for every target that names a role or teams, and a
  member entry naming no role or nobody;
- two fragments stating the same installation or stand-in module.

The fixture itself is held to the same rule: a role in it that states `scopes`
or `generated` is refused by name.

The boot log names each effect, for example `the composition seats wiki at
acme: wiki-admin [dana] wiki-user [carol]`, or says that the composition adds
nothing. The local authority refuses to start in a pod.

## Permission diagnostics during local development

The fixture once generated a `developer` organisation role holding every
delivered kind and action. It is gone with every other organisation-role
grant: a developer reaches a module as anybody does, through a role on an
installation (the fixture seats Carol as `user` and Dana as `admin` on every
role-gated target a run composes).

Every successful composition delivery logs a sorted role × module-generation ×
method report over the roles each module itself declares. It names uncovered
requirements, and says of a module declaring no roles that it is reached through
a role on an installation that binds it, never an organisation role. These are diagnostics,
not a demand that every role may call every method. Static coverage still needs
valid identity, active installation, consent where required and resource checks.
An absent method policy remains a named local refusal; contradictory or malformed
policy is rejected when delivered. Offline deployment validation uses the same
policy validator in the delivery library, requiring explicit method declarations.

`go test -race ./...` in `code/` includes replacement/removal and fixture coverage
regressions. This does not qualify the production host or live browser journeys.

Person issuance sorts and deduplicates a copy of the session's team attribution
before signing. Fixture order therefore does not affect a module's ability to
consume the context; the original session remains unchanged. A role name implies no
grants: the test kit's composition
(`code/pkg/business/testkit/testdata/composition.yaml`) gives the Globex
administrator its collection read explicitly. Issuer regressions and the shared
fixture matrix cover that grant and a person who lacks it.

## Signed delivery lifecycle

The signed-carrier path retains Core's verified manifest and its paired authority
policy. Core decides host coordinate, domain continuity, generation replay and
terminal withdrawal; the local authority applies that decision and its permission
projection together. The host declares the `federation` workspace configuration
and reads `SOLUTION_HOST_COORDINATE` through the SDK. A carrier cannot select the
coordinate against which it is checked.

An identical replay returns the original receipt without advancing revisions or
reapplying grants. Changing, adding or removing the authority policy at the same
generation is refused. Every public composition call requires a signed carrier
and the authenticated delivery workload; unsigned manifests are refused before
any host operation, including pending fixture installations. Trusted fixture
setup uses the host-only state API and cannot overwrite a signed alias.

A workload must still be declared by the current signed manifest to obtain new
authority. Withdrawal removes the module and its principal, revokes its
installations and alias-scoped delegations, and retains a terminal binding record.
Repeating withdrawal has no additional effects. Pending fixture installation
work remains attached to its admitted delivery: replay resumes the same convergent
installation step after failure or cancellation. Completion is serialized per
binding, outside the state lock; a superseded or withdrawn attempt cannot
acknowledge an installation or expose it to teams. Cancellation does not undo
already-applied declarations or external installation effects.

**Compatibility limits.** Existing installation UUIDs remain stable. This process
explicitly refuses a new binding reusing an already-admitted alias, even after
withdrawal, and refuses renaming the alias of a binding. Supporting those
transitions requires an installation-identity migration that preserves existing
stored rows without transferring them to a replacement. Signed records and
tombstones currently live in memory: restart forgets them. This does not prove
anti-resurrection or persistent consumer-data isolation across changed bindings
and restarts. Full alias replacement, durable history and production accounts
parity remain unfinished; local lifecycle tests do not qualify those behaviors.

Installation-owned Issue verifies an explicitly supplied `organization_id`
against the installation's organization, as well as authenticating the installed
solution workload. Omitting the organization uses the installation's own tenant.
A pending installation cannot be granted to a team: its install step must first
acknowledge it. Shared conformance observes the pending state while that step is
blocked, then verifies exposure after acknowledgement and refusal after revocation.
See `libraries/conformance/go/README.md` for the complete host comparison contract.

**An installation survives delivery.** Its consent records the generation and
offer digest the administrator approved (`Installation.approved_generation`).
When a target is delivered again, the core compares the new reviewed surface,
what `Review` and `ReviewOffer` show (kind, each role and installation-owned
role with its scopes, each binding with its audience and scopes, each edge
dependency, the installation role selector, each method's policy), with the
one the consent approved. Asking nothing new (nothing added, nothing reaching
further, no standing authority asked, no method callable with less) re-converges
every active installation without a click: the consent advances to the new
generation, the revision moves so what was issued under the earlier
declaration ends, every role grant stays, and `installation.reconverged` is
journaled. Asking more leaves the installation on its consent, active with its
grants, with `upgrade_available` true and `installation.upgrade_available`
journaled naming what widened; an administrator approves it with a fresh
`Review` and `Install` on the same installation: its install step runs again
(idempotent; the host converges the closure there), then the installation,
active throughout, moves its consent, revision and agent role, keeps its
installer and its grants but those of a role the approved offer no longer
declares (`installation.upgraded`). Until then its holders hold what the
**approved** generation granted: issuance, `GrantRole` and a role holder's
`ReviewOffer` resolve from the declaration the consent approved, which the
store keeps per target and generation (`Tx.ApprovedModule`,
`Tx.PutApprovedModule`, written whenever a consent is taken or advances), never
from the delivered one. A consent already behind the delivered generation
cannot be proven to cover the next one and keeps offering its upgrade. A
consent recorded before its generation was kept approved an unknown offer: the
next delivery offers an upgrade once, naming that, and its holders hold the
delivered roles until one review settles it; a host that knows the approved
generation writes it, with the module at that generation, before its first
`ApplyModule` on the new core. Role grants end by `RevokeRole`, by an uninstall,
and, for a role the approved offer no longer declares, when the consent
advances (re-convergence or upgrade); an install never deletes one otherwise.

**What a host's store must keep** for this: the consent's approved generation
and digest on the installation, and the approved declaration per (target,
generation) for every generation an active consent names (one it no longer
names may be dropped). `libraries/authority-core/go/storetest` proves both.

Workloads name the organization of the work item. The local convenience of
omitting it works only for a sole active installing organization; it is not a
shared host requirement. Method admission checks kind/action while preserving
resource limits for the module's resource check. The hop refuses `ENFORCEMENT=warn`
unless the SDK identifies the environment as local; advisory conformance is
explicitly enabled only by the local runner. The service itself answers an
advisory Check as advice only when `CODEFLY__ENVIRONMENT` is exactly `local`
(`localRun`, `work.go`); otherwise the check is enforced and a refused method
is a refusal.

HTTP Check uses the concrete verb and canonical path, with literal precedence
and ambiguity refusal over the delivered manifest. Published Connect calls use
the protobuf procedure spelling; a dotted HTTP URL cannot borrow gRPC policy.

## Artifact consent admission

Approve, Authorize and Revoke check effective scope coverage against the target
installation's stored principal before accessing approvals. An owner-selected
capability cannot access another installation's consent. Module installations
without a solution principal require owner-unrestricted coverage. Artifact identities
must name that installation's host-defined namespace as their source.

The policy resource id is not established by the opaque identity subject or an
approval id. Resource-limited scopes are therefore refused with that reason;
consent requires the policy action over the installation owner's whole kind.
The shared scope algebra enforces both owner and resource restrictions.
