# Vendored: the authority's method policy

`hop/v1/policy.proto` is a byte-for-byte copy of
`libraries/hop/proto/authority/hop/v1/policy.proto` in this repository, so the
console's proto can mark its methods with the option.

This is a stopgap. No Codefly library exports a proto yet, so a module cannot
import another's option through the CLI, and every module in the fleet copies
the option protos it uses by hand. The real fix, codefly-dev/cli#1130, is the
CLI importing a proto a library exports. Until then `code/vendored_test.go`
fails when this copy drifts from its source.
