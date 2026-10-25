# Go hop library

`Outbound.ForModule(ctx, "", binding)` asks the authority for a Work Context
through the module's declared binding without supplying an organization. The
authority resolves the authenticated module's delivered tenant pin or its sole
active installing organization. The local authority has no tenant pin, so zero
or multiple active installing organizations are refused with a named reason.
The helper preserves that refusal and identifies the binding.

Pass an organization explicitly when the work already identifies one; it is
forwarded unchanged for the authority to check. The helper does not select a
tenant. `ErrNoOrganization` was removed because an empty organization is a valid
request to the authority. Successful calls carry the issued token in outgoing
gRPC metadata and preserve other outgoing metadata.

`IssueForParent` and `IssueForModule` are `ForParent`'s and `ForModule`'s issue
returned rather than carried, as an `Issued`: the token, when it expires, and
the Work Context the authority says it is for. A caller that holds an issued
context across calls (renewing it before it expires) or reads whom it was issued
for uses them; `Issued.Carry` puts it on a call's outgoing metadata exactly as
the `For*` methods do. `Scopes` narrows any issue to what is asked, within the
binding's ceiling. `FileCredential(path)` reads the workload credential from a
path resolved once, on every call; `RunCredential` is it at the path the run
names. A refusal keeps the authority's gRPC status in its chain (`errors.As`)
and names the binding.

Version note (2026-10-25): `Issued`, `IssueForParent`, `IssueForModule`,
`Scopes` and `FileCredential` are additive; every existing signature is
unchanged. Consumers pin this library by commit until it is tagged.

Validate this library with `go test -race ./...` and `go vet ./...` from this
directory. Issuer and shared conformance tests in the local authority exercise
the actual installation-based tenant resolution.
