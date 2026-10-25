# Go hop library

`Outbound.ForModule(ctx, organization, binding)` names the organization of the
work item. The local authority accepts an empty organization only when exactly
one organization has an active installation of the calling module. Zero or
multiple installing organizations are refused with a reason telling the caller
to name the organization of the work item. There is no delivered tenant pin.
The helper forwards the request and preserves the authority's refusal.

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
directory. Issuer unit tests in the local authority exercise
the actual installation-based tenant resolution.

The Go dependency now pins the shared hop-stamp validation introduced in
`9f04fc4`; standalone library tests therefore use the same digest check as the
service without needing an external workspace replacement.
