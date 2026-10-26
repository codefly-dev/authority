# store — the console's hop admission reservations

One table, `hop_admissions`, holding the nonce of every call the hop admitted
to the console. The console's verifier reserves a nonce when the call arrives,
before its body is read, and holds it until the handler has returned, so a
captured admission is refused the second time it is presented.

It is a store and not a set in the process because the guarantee has to hold
across every replica of the console and across a restart. The admission
contract asked for "a durable shared replay volume" instead, which Codefly does
not deliver: in practice that meant an absolute path to per-pod storage, which
looks identical to a shared mount and silently becomes a per-replica store,
letting a captured admission replay once per replica inside its window
(security review r164, B1). A module that has a store has somewhere atomic to
put a nonce, so the console composes one.

`INSERT ... ON CONFLICT (nonce) DO NOTHING` is the reservation: Postgres decides
the one winner among concurrent inserts, whichever replica they reach.
`libraries/hop/go/replaypg` is the adapter, and `replaypg.Migration` is the
table this service's migration carries; `code/store_test.go` asserts the two
have not drifted.

Reservations are retained to the admission's expiry plus the clock allowance,
and for as long as the call holding one runs (`active`), so the table does not
grow without bound: the console runs `replaypg.Store.Collect` on a schedule, and
it removes only finished reservations past their retention. Removing one is
safe because a reservation is refused, on the database's clock, once its
retention has passed, so a later delivery of a collected nonce can never
reserve it again. A console that stops while a call runs leaves that one row
held; nothing reopens admission. The service may update `active` and no other
column.

Its one reader is this module's `api`. The endpoint is private and the module
interface does not export it.
