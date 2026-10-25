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

Validate this library with `go test -race ./...` and `go vet ./...` from this
directory. Issuer and shared conformance tests in the local authority exercise
the actual installation-based tenant resolution.
