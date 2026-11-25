# fixture-composition

The local authority's `fixture-composition` document (schema
`codefly.dev/authority/fixture-composition/v1`): its one parser and its merge
rules. The local authority reads the document with `Decode` and checks it
against its fixture; the run builds it with `Merge` from the fragment each
composed module ships next to its code, plus the composition's own
([what a composition adds to the fixture](../../../modules/authority/services/local/README.md#what-a-composition-adds-to-the-fixture)).

**The document grants no organisation role anything.** Organisation roles
decide administration only (members, teams, installations, grants); a person
reaches a module only through a role (`admin`, `user`) on an installation
([the decision](https://github.com/obin-ai/handbook/blob/main/decisions/organisation-roles-decide-administration-only.md)).
The document has no `roles` section. A fixture person who is to reach a module
is seated on a team of an installation that reaches it:

```yaml
schema: codefly.dev/authority/fixture-composition/v1
installations:
  # Seats people on the roles of one role-gated target the run composes.
  - organization: acme
    target: evaluation-playground
    owner: alice
    members: {admin: [dana], user: [carol]}
```

- `Decode` reads one mapping stating the schema and refuses, by name, everything that
  does not depend on the fixture: an empty or null document, a null section, an
  unknown field, another schema, a wildcard, a kind or action outside the
  grammar, a stand-in module with no kind, an installation with no target. A
  `roles` section is refused, whatever schema the document states, saying
  where a person's reach is stated now, so a fragment that granted an
  organisation role a module's kinds is never read as one that grants nothing.
  There is one schema: a document stating another is refused as unknown and
  told to state this one.
- `Merge` reads each `Source` with `Decode` (an error names the source) and
  combines them. Every statement has exactly one source: one installation, one
  stand-in module. A second source stating one is `ErrConflict`, naming both
  sources, even when they agree; so is a second statement of it **within one
  document**, which `Decode` refuses. Sources are merged in the order of their
  names, so the result does not depend on the order they were found in.
- `Encode` writes YAML that `Decode` reads back unchanged.

**A fragment that still has a `roles` section.** Delete `roles:`. For each
person who reached a module through one of those grants, name them
under `members` of an installation whose role reaches it: the playground's
page, the solution. A row naming a target seats its members on that target's
`<target>-<role>` teams; the fixture's own row with target `"*"` already seats
Carol as `user` and Dana as `admin` on every role-gated target.

`go test -race ./...` covers the refusal of a roles section and of an unknown schema,
the merge of two module fragments and a composition's own, each conflict, and
each refusal.
