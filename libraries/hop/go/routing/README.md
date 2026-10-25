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
