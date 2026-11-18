# fixture-composition

The local authority's `fixture-composition` document (schema
`codefly.dev/authority/fixture-composition/v2`): its one parser and its merge
rules. The local authority reads the document with `Decode` and checks it
against its fixture; the run builds it with `Merge` from the fragment each
composed module ships next to its code, plus the composition's own
([what a composition adds to the fixture](../../../modules/authority/services/local/README.md#what-a-composition-adds-to-the-fixture)).

**The document grants no organisation role anything.** Organisation roles
decide administration only (members, teams, installations, grants); a person
reaches a module only through a role (`admin`, `user`) on an installation
([the decision](https://github.com/obin-ai/handbook/blob/main/decisions/organisation-roles-decide-administration-only.md)).
Schema v1 had a `roles` section that granted a module's kinds to an
organisation role; v2 has none. A fixture person who is to reach a module is
seated on a team of an installation that reaches it:

```yaml
schema: codefly.dev/authority/fixture-composition/v2
installations:
  # Seats people on the roles of one role-gated target the run composes.
  - organization: acme
    target: evaluation-playground
    owner: alice
    members: {admin: [dana], user: [carol]}
```

- `Decode` reads one versioned mapping and refuses, by name, everything that
  does not depend on the fixture: an empty or null document, a null section, an
  unknown field, another schema, a wildcard, a kind or action outside the
  grammar, a stand-in module with no kind, an installation with no target. A
  `roles` section, and schema v1 whatever it carries, are refused saying where
  a person's reach is stated now, so a fragment that granted an organisation
  role a module's kinds is never read as one that grants nothing.
- `Merge` reads each `Source` with `Decode` (an error names the source) and
  combines them. Every statement has exactly one source: one installation, one
  stand-in module. A second source stating one is `ErrConflict`, naming both
  sources, even when they agree; so is a second statement of it **within one
  document**, which `Decode` refuses. Sources are merged in the order of their
  names, so the result does not depend on the order they were found in.
- `Encode` writes YAML that `Decode` reads back unchanged.

**Moving a fragment from v1.** State the schema as v2 and delete `roles:`.
For each person who reached a module through one of those grants, name them
under `members` of an installation whose role reaches it: the playground's
page, the solution. A row naming a target seats its members on that target's
`<target>-<role>` teams; the fixture's own row with target `"*"` already seats
Carol as `user` and Dana as `admin` on every role-gated target.

`go test -race ./...` covers the refusal of a roles section and of schema v1,
the merge of two module fragments and a composition's own, each conflict, and
each refusal.
