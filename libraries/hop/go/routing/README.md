# Hop route selection

The published inventory selects a destination. For HTTP it returns the concrete
request's verb and path for authority Check; only a published Connect endpoint
selects a protobuf procedure. The authority's delivered manifest therefore keeps
literal-route precedence and ambiguity refusals even when inventories differ.

Non-canonical paths never match, including exact inventory entries. The HTTP
proxy also checks the original escaped path before deciding: dot segments,
repeated separators, escaped separators/dots and nested escapes are refused,
never normalized and forwarded under another operation's policy. HTTP upstreams
must be origins; they cannot add a path prefix after the authority check.


A declared Connect endpoint serves both Connect HTTP requests and gRPC calls at
its one resolved address. Both use the declared protobuf method's policy. When
one service publishes the same contract (package, version and digest) on both
its gRPC endpoint and its Connect endpoint, that is one destination: gRPC calls
for a procedure on both go to the Connect endpoint, and the gRPC endpoint serves
only procedures the Connect endpoint does not publish. Any other second claim on
a procedure is ambiguous and refused, naming both listeners: two services, two
endpoints of one transport, an HTTP route over a Connect procedure, or one
service's two endpoints under different contracts. Unknown methods, undeclared
audiences, unsafe destinations and transport refusals remain closed. The hop
dials using the shared host transport policy.
