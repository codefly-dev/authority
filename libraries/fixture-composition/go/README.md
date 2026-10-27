# fixture-composition

The local authority's `fixture-composition` document (schema
`codefly.dev/authority/fixture-composition/v1`): its one parser and its merge
rules. The local authority reads the document with `Decode` and checks it
against its fixture; the run builds it with `Merge` from the fragment each
composed module ships next to its code, plus the composition's own
([what a composition adds to the fixture](../../../modules/authority/services/local/README.md#what-a-composition-adds-to-the-fixture)).

- `Decode` reads one versioned mapping and refuses, by name, everything that
  does not depend on the fixture: an empty or null document, a null section, an
  unknown field, another schema, a wildcard, a kind or action outside the
  grammar, a malformed resource matcher, a role or stand-in module with no
  scope, an installation with no target or role.
- `Merge` reads each `Source` with `Decode` (an error names the source) and
  combines them. Every statement has exactly one source: a role's grant on one
  kind, one installation, one stand-in module. A second source stating one is
  `ErrConflict`, naming both sources, even when they agree. Sources are merged
  in the order of their names, so the result does not depend on the order they
  were found in.
- `Encode` writes YAML that `Decode` reads back unchanged.

`go test -race ./...` covers the merge of two module fragments and a
composition's own, each conflict, and each refusal.
