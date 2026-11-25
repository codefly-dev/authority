# scenario

Permission scenarios on a real composition, from a plain `go test`: the
services a scenario needs, started by Codefly (the SDK's dependency stack),
behind the **real local authority** on its fixture. A test acts as a fixture
person by name and calls what a page calls, through the authority's edge and
hop. Every verdict and every result is the composition's own: the authority's
issuance, the hop's admission of the method, the module's handler, and each
onward hop it makes in turn. Nothing here decides, and nothing stands in for
the authority or for a module. No cluster is involved, ever.

```go
var composed *scenario.Composition

func TestMain(m *testing.M) {
	os.Exit(scenario.Main(m, &composed, scenario.Options{
		Anchor:  "playground/modules/notes-playground/services/scenarios",
		Install: []string{"notes"},
	}))
}

func TestWhoReadsTheNotes(t *testing.T) {
	composed.Check(t, scenario.Row{Name: "read the notes",
		Call: scenario.Call{Page: "notes", Procedure: "notes.v1.NotesService/List"},
		Want: scenario.Want{"dana": scenario.Allow, "carol": scenario.Allow, "bob": scenario.Deny("holds no role on notes")}})
}
```

## The pieces

- **A composition is one anchor service**: a service that never runs, whose
  `service-dependencies` are what the run starts; the test process stands
  where it would. It depends on `authority/edge` (http) and `authority/local`
  (grpc), and on whatever the scenarios call. A composition whose host is
  another service names it: `Options.Host` (for SaaS Accounts,
  `{saas, accounts, connect}`, dialled with gRPC, which its Connect endpoint
  answers) and `Options.Edge`; the anchor then depends on those. The host
  must serve the fixture sign-in. `Composition.Address(module, service,
  endpoint)` is the address the run delivered for any endpoint the anchor
  depends on. `Main` starts it once per test
  package and tears it down; `Options` says what the run leaves out, the
  workspace values of this run alone, what Codefly generates per naming scope
  before the start, and the solutions the organisation's administrator
  installs (with the consent the authority reviews). `Seated` keeps the
  fixture's people on the named targets alone, for the whole run: the host
  seats them again on every installation after each install and delivery, so
  the harness withdraws what came back after every install it makes and
  before every call. With no `Seated`, the people hold their roles on every
  module's own page too, and a run does not show that a module is reached
  through the product's role alone.
- **`As(t, "carol")`** signs a fixture person in at the edge by the fixture's
  own token for them, read from the host (`ListFixturePeople`), never written
  down. A call carries their session and nothing else, as a browser's does.
- **`Call`** is a page's call (`Page` + `"<package.Service>/<Method>"`: the
  edge names the page to the authority, which issues through the page's
  binding), a call on the person's own session (no page), or a route
  (`"GET /v1/…"`). `Stream` reads a streamed answer.
- **`Outcome`** is what became of it: `Allowed` (it answered), `Admitted` (the
  authority and the hop let it through and the method refused the request for
  a reason of its own: an argument, a record, a state), `Denied` (refused for
  who makes it; the reason is the caller's own words for it), `Unserved` (the
  composition serves no such call to anyone), `Failed` (no verdict: the module
  did not answer, a 5xx, unavailable, a fault, a timeout, or the authority
  reaching no decision; it satisfies no expectation, `Admit` included).
  `Person.Do` states the exact rule. `Value("a.0.b")` and `Text` read the
  answer.
- **`Check`** runs a table: `Row` × the people it names, each a subtest. An
  expectation is `Allow`, `Admit` or `Deny("part of the reason")`, with
  `.And(func(Outcome) error)` for what the answer must hold. A refusal that
  names no reason fails whatever was expected.
- **The outsider** is the administrator of another organisation, who holds no
  role on any installation of the composition's own: on the local authority's
  fixture, Zoë of Globex. `scenario.Cast` names the shipped fixture by seat
  (`Admin` dana, `User` carol, `None` bob, `Outsider` zoe), and
  `composed.Outsider(t)` reads her from the host instead (the one
  administrator of an organisation that is not the administrator's own) and
  signs her in. A module page is installed at every organisation by
  composition and the fixture seats Zoë as its admin at Globex, so she calls
  the same page on her own seat and is answered her own organisation's rows;
  a solution she installs herself (`composed.Install(t, scenario.Cast.Outsider, "wiki")`).
  Two helpers hold a suite to tenant isolation:

  ```go
  // Each reads their own organisation's rows and none of the other's: both
  // ways, and only against rows that are really there.
  composed.Isolated(t, "list the notes", scenario.Call{Page: "notes", Procedure: "notes.v1.NotesService/List"},
  	scenario.Own{scenario.Cast.Admin: {danasNote}, scenario.Cast.Outsider: {zoesNote}})

  // Naming Acme's row, Zoë is refused or told it does not exist; never answered.
  composed.Check(t, scenario.Row{Name: "read Acme's note", Call: scenario.Call{Page: "notes", Procedure: "notes.v1.NotesService/Get", Request: map[string]string{"id": danasNote}},
  	Want: scenario.Want{scenario.Cast.Admin: scenario.Allow, scenario.Cast.Outsider: scenario.Withheld}})
  ```

  `Isolated` fails a read that is refused or answers nothing, and a table
  whose people are all of one organisation: neither shows isolation.
  `Withheld` is a refusal for who calls or the method's own Connect
  `not_found`; an answer, a refusal for another reason, an unserved call and
  a failure do not satisfy it. `Holds` and `HoldsNone` say what an answer
  carries, for `.And`. `Options.Administrator`, when omitted, is the one
  administrator of the organisation the fixture lists first, so Zoë never
  makes the setup ambiguous.
- **`PlanRows`** turns a product's role plan
  (`authority-core/go/roleplan`) into rows, so nothing is listed by hand:
  every procedure the plan's rows cover at the modules the page binds (read
  from their published contracts, `Published`), called as the admin, the user
  and a member with no role, and held to the plan's verdict: let through, or
  refused by the decision the plan names (no role on the product, the method
  policy naming the permission that is unmet, nothing held through the
  binding), so a refusal for another cause fails the row. A procedure open to
  any checked caller is called as each seat too: the member with no role is
  issued nothing from the page and is refused for it. This holds the
  plan's first hop to the real audience, which the plan's stand-in for it
  cannot: its real method policy, whether it checks owners, which kinds it
  shares, and that the composition routes the procedure at all. What a call
  does onward needs a real request, which a scenario's own rows give.

## What it costs

A start is the composition's own (one to three minutes for a dozen services
with their stores, on a laptop; a first start also builds them). The
scenarios are HTTP calls: a few hundred derived rows run in about a second.
One composition serves a whole test package.

## What it cannot see

A host other than the local authority (the fixture's people and the sign-in
by fixture token are its own); anything outside the composition, which a
scenario stubs only where the module that calls it lets a composition
configure a stand-in (a model gateway's recorded provider turns).

It builds on core's `sdk.WithNamedPorts`, `sdk.WithPrepare` and
`sdk.WithExcludedWorkspaceConfigurations`; until the core release that
carries them, build it in a Go workspace that names a checkout of core.
