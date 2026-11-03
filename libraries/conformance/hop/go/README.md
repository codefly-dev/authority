# Hop conformance

The authority suite (`../../go`) proves an authority: Issue, Check, Keys,
installations, delegations, roles. This target proves the other half of every
admitted call: the hop's stamp and the module-side verifier. The rule is the
one the authority suite states, applied to the admission path: **one contract
(`libraries/hop/README.md`), N implementations, one suite.** A hop or a
verifier is proved by passing this target, not by whoever wrote it. A change
that passes here and fails against a verifier a module ships is a bug here,
and no case is loosened so that an implementation passes.

The implementations today are the Go verifier (`libraries/hop/go`,
`hop.Verifier`), the Python verifier (`libraries/authority-client/python`,
`codefly_hop.Verifier`) and the TypeScript verifier
(`libraries/authority-client/typescript`, `Verifier`), and the one hop, in Go
(`hop.Stamp`, served by `modules/authority/services/hop`).

## The target has two halves

**`Run(t, Target)`**, this package. The cases that need a live authority and
more than one verifier: a rotation, a store two replicas share, a handler
holding its reservation, keys that cannot be read, a hop stripping what a
caller sent. It is built on `hoptest`, a real authority that signs Work
Contexts with a key of its own, answers `Keys` for them and for the hops it
publishes, and forwards a call exactly as the hop stamps it. It drives the
verifier under test through its public entry points alone; what it moves is the
hop's signing clock, the authority's, the window of an admission the hop's own
signer writes (`stamp.Signer.SignAt`, the one place that writes the signed
payload) and — for the one case judging a bound no wall clock reaches twice —
the verifier's clock, which every verifier takes at construction. So a case
that needs a window the hop would never sign, or an instant the run cannot wait
for, has one. A Go verifier plugs in as a `Target`:

```go
hopconformance.Run(t, hopconformance.Target{New: func(ctx context.Context, keys hop.KeySource, audience string, replay core.ReplayStore, now func() time.Time) (hopconformance.Verifier, error) {
	return hop.NewVerifier(ctx, keys, audience, replay, hop.Clock(now)) // or any other verifier
}})
```

`now` is nil in all but that one case, and a nil clock is the verifier's own
wall clock.

`conformance_test.go` runs it against `hop.Verifier`; CI runs this module like
every other (`.github/workflows/go.yml`). The module replaces
`libraries/hop/go` and `libraries/authority-client/go` with the checkout, as
the rest of the repository does: CI runs `go test` per module with no
workspace, so a pinned hop would mean the suite proved a published commit
rather than the tree it ships in. The dependency still runs one way — neither
library imports this suite — so neither depends on its own suite.

**`libraries/authority-client/testdata/stamps.json`**, the wire-level half.
Signed admissions on the wire, as the hop forwards them, each with the verdict
the contract names at a fixed clock: the module the verifier is, the procedure
it observes, its clock, the authority's `Keys` (or `null`, keys that cannot be
read), the call's metadata in order with repeats kept, whether it is admitted,
the refusal's code, the code a second delivery to another verifier on the same
store is refused with, and who the call is for when it is admitted. It is
written by the Go hop library's test (`libraries/hop/go/vectors_test.go`,
`TestTheStampVectorsAreGosVerdicts`) from cases that declare the contract's
verdict, and Go must reach that verdict; the file is regenerated, never edited:

```sh
cd libraries/hop/go && go test -run TestTheStampVectorsAreGosVerdicts -update-vectors .
```

Python (`tests/test_stamps.py`, through `verify` and `verify_async` alike) and
TypeScript (`tests/stamps.test.mjs`) replay the same file in CI
(`.github/workflows/clients.yml`) and must reach the same verdict, for the same
reason, reading the same identity, with no header value in the refusal. Every
admitted vector is delivered twice, to two verifiers on one store, and the
second delivery must be refused as `stamp_replayed`.

## What every verifier must pass

| Contract line | `Run` case | `stamps.json` | Python, beyond the vectors | TypeScript, beyond the vectors |
| --- | --- | --- | --- | --- |
| The proof is judged under the authority's published admission keys and under no other key; a stamp signed by an unpublished key is refused by name (`stamp_proof`) and starts no key read | a genuine stamp under the published admission key admits; a stamp signed by a key the authority does not publish is refused by name, and reads no keys | `admitted`, `signed by an unpublished key`, `no proof`, `a proof that is no signature`, `a proof with padding`, `a proof in three parts`, `a proof over another domain`, `a proof with six fields`, `a proof whose nonce is sixteen bytes`, `a proof whose nonce is upper-case hex`, `two proofs` | `test_a_verifier_takes_the_hops_key_from_the_authoritys_keys_alone`, `test_a_stamp_signed_by_an_unpublished_key_is_refused_by_name`, `test_a_call_without_the_proof_never_reads_the_keys` | a verifier takes the hop key from the authority keys alone; a stamp signed by an unpublished key is refused by name |
| Method and audience binding: a stamp for another procedure (`stamp_method`) or another module (`stamp_audience`) is refused, and the refusal does not consume the admission | a stamp for another procedure is refused, and the refusal does not consume the admission; a stamp for another module is refused | `signed for another procedure`, `observed without its leading slash`, `observed with an http verb before the procedure`, `no procedure observed`, `signed for another module` | `test_review_retargeting_and_replay_across_replicas`, `test_another_audience_and_an_expired_context_are_refused` | review probes: read stamp cannot retarget, cross audiences or replay across replicas |
| `Lifetime` (30 s) and `Skew` (2 s) bound issue and expiry only: issued up to the allowance ahead admits, further is `stamp_issued`; admissible until the allowance past expiry, then `stamp_window`; the signed span is capped at the lifetime exactly, whatever the allowance | an admission issued further ahead than the allowance is refused as issued, not as expired; an admission past its expiry and the allowance is refused; the signed span is capped at the lifetime, inside the window or not; an admission issued the allowance ahead, or spanning exactly the lifetime, admits; an admission is admissible for the allowance past its expiry, and refused at its end (both verdicts on one admission, at the verifier's injected clock) | `issued the allowance ahead`, `expired inside the allowance`, `issued further ahead than the allowance`, `expired by the allowance`, `a span longer than the lifetime`, `a span longer than the lifetime inside the window`, `expiring when issued`, `a negative issue instant` | `test_signed_admission_window_is_bounded`, `test_a_clock_difference_inside_the_allowance_still_admits`, `test_a_clock_difference_beyond_the_allowance_is_refused` | a clock difference inside the allowance still admits; beyond the allowance is refused as `stamp_issued` / `stamp_window`; expired stamps refuse before consumption |
| Token-digest binding (`x-codefly-hop-context` and the digest the proof signs): a swapped, forged or unsigned token under the stamp is `stamp_digest`; no token, or two, is `stamp_token` | the stamp binds the one Work Context the authority checked (eight cases) | `a swapped work context`, `a forged work context under a rewritten digest`, `a context digest disagreeing with the proof`, `no work context`, `two work contexts` | `test_a_token_the_authority_did_not_sign_is_refused_even_with_a_matching_digest`, `test_duplicate_proof_and_token_are_refused_before_consumption` | the stamp must bind the token under this run's proof; the reservation is taken before the work context and released on refusal |
| The advisory key is always refused (`stamp_advisory`), and the hop never signs an advisory refusal | an advisory refusal never admits; the hop never signs an advisory refusal | `an advisory refusal` | the vector alone (before it, no Python case refused the key) | the vector alone (before it, no TypeScript case refused the key) |
| A single-use admission is reserved before the keys are read, held until the handler returns, retained to expiry plus the allowance, refused across every verifier sharing the store (`stamp_replayed`); a refusal after the reservation keeps the nonce and ends the hold; an invalid stamp reserves nothing; a store that cannot answer refuses (`stamp_store`); a reservation the store judges past its retention is `stamp_window` | a single-use admission is held while its handler runs and refused across verifiers sharing the store; concurrent deliveries of one admission have one winner across verifiers; a call refused after its reservation keeps the nonce and ends its hold, and an invalid stamp reserves nothing; a store that cannot answer refuses admission, naming no backend failure; a reservation the store judges past its retention is refused on the window | the second delivery of every admitted vector (`replay`) | `test_a_second_delivery_of_one_admission_is_refused_while_and_after_the_first_runs`, `test_admit_async_holds_the_reservation_until_the_handler_returns`, `test_admit_releases_its_hold_however_the_handler_ends`, `test_the_reservation_is_taken_before_the_work_context_and_released_on_refusal`, `test_review_concurrent_replay_and_store_failure`, `test_async_replay_has_one_winner_across_replicas`, `test_a_reservation_is_retained_past_expiry_by_the_allowance`; `test_replaypg.py` over Postgres | a second delivery of one admission is refused while and after the first runs; concurrent replay has one winner and a failed store refuses admission; admit releases its hold however the handler ends; a reservation is retained past expiry by the allowance |
| A rotation's overlap admits both keys until the retiring one is withdrawn | a rotation's overlap admits both keys, and a verifier reading Keys after the retiring key is withdrawn refuses it | `signed by the retiring key during a rotation's overlap`, `signed by the retiring key after it is withdrawn` | `test_a_rotations_overlap_admits_both_keys_until_the_retiring_one_is_withdrawn` | a rotation overlap admits both keys until the retiring one is withdrawn |
| A verifier that cannot read `Keys`, or reads keys publishing no admission key, refuses rather than admits (`keys_unavailable`), naming no address; each key serves its own purpose only | a verifier that cannot read the authority's keys refuses rather than admits, naming no address; an authority that publishes no admission key admits nothing; a key is used for its own purpose only | `the authority's keys cannot be read`, `no admission key published`, `an admission key published under another purpose`, `signed by an admission key published among the work context keys`, `a work context signed by the hop's admission key` | `test_a_verifier_starts_before_the_authority_serves_keys`, `test_no_published_admission_key_refuses_every_call_and_says_why`, `test_a_key_is_used_for_its_own_purpose_only`, `test_a_call_on_keys_past_stale_is_refused_when_the_reread_fails` | a Verifier starts before the authority serves keys and refuses with a reason until it does; no published admission key refuses every call and says why; a key is used for its own purpose only |
| Who the call is for is read from the authenticated token, never from a stamp header alone (`stamp_identity`); an owner-selected or resource-limited scope is never widened to its kind | a stamp header the token does not bear out is refused (eight cases); an owner-selected scope never reads as the whole kind; a resource-limited scope is read from the claims, never widened to its kind | `a stamped tenant / scope / owner / actor the token does not bear out`, `a stamped identity header repeated`, `an owner-selected scope is not the whole kind`, and the `identity` of every admitted vector | `test_a_stamp_the_token_does_not_bear_out_is_refused`, `test_the_hop_fixture_authenticates_and_reads_as_go_reads_it`, `test_owner.py` | the Verifier reads the hop fixture as Go reads it; stamp failures retain distinct safe codes; `owner.test.mjs` |
| The Work Context under the stamp is authenticated by Core's rules: expired, misaddressed, forged, signed by an unpublished key or by the hop's key is refused by name, and a fresh stamp revives none of it | a fresh stamp does not revive an expired Work Context; a key is used for its own purpose only | `an expired work context under a fresh stamp`, `a work context for another module under a stamp for this one`, `a work context signed by the hop's admission key`, `a work context signed by a key the authority does not publish`, `a forged work context signature under a stamp over it`; and `vectors.json`, the bare-token verdicts | `test_bare_token_matches_shared_verdict`, `test_python_reaches_gos_verdict_on_every_shared_vector` | bare token matches shared verdict; shared vector, Go's verdict |
| The hop strips every stamp a caller sent, signs the exact procedure, the audience and the token's digest within the lifetime, caps the admission at the Work Context's expiry and stamps no expired one | the hop strips every stamp a caller sent before writing its own; the hop signs the exact procedure, the audience and the token's digest, within the lifetime; the hop caps an admission at the Work Context's expiry and stamps no expired one | the headers of every vector are what `hop.Stamp` writes | no hop | no hop |
| A verifier needs the authority's keys, an audience and a replay store; outside the run named exactly `local` it refuses a store that does not declare itself shared; every refusal is a stable code with fixed text | a verifier needs the authority's keys, an audience and a replay store; outside a local run a replay store that does not declare itself shared is refused, and one that does is admitted; every refusal carries a stable code with fixed text | construction-time: no vector | `test_a_verifier_needs_keys_and_an_audience`, `test_startup_requires_a_shared_store_outside_exactly_local`, `test_bare_token_stale_wait_async_and_safe_reasons` | startup requires a shared store outside exactly local; every named reason has distinct code and safe text |

## Stated gaps

These are what the target does not prove, named rather than skipped.

- **TypeScript ships no durable replay store.** A Node host supplies its own
  (`reserve`/`finish`/`consume`, `shared: true`); the vectors and
  `work-context.test.mjs` run on an in-memory store, so TypeScript's single-use
  admission is proved for the verifier's logic, not for a store across replicas
  and restarts. Go (`libraries/hop/go/replaypg`) and Python
  (`codefly_hop.replaypg`) prove the durable contract over a real Postgres in CI.
- **Python's durable store is async only.** `codefly_hop.replaypg.Store`
  implements `reserve_async`/`finish_async`; a synchronous handler needs a
  synchronous store of its own, which this repository does not ship.
- **There is one hop, in Go.** The hop-side cases run against `hop.Stamp`. A
  hop in another language is proved by a verifier that passed this target
  admitting what it writes: run its stamps through `hop.Verifier` with
  `hoptest` publishing its key, or add them to `stamps.json`.
- **The rotation case proves the read after the withdrawal, not the interval.**
  It proves that a verifier reading `Keys` after the retiring key is withdrawn
  refuses it; that a verifier re-reads within five minutes, retries at most
  every ten seconds and trusts unreadable keys for fifteen minutes at most is
  each implementation's own fixed-clock test
  (`libraries/hop/go/published_test.go`, `fixture_test.go`; `test_hop.py`;
  `work-context.test.mjs`). Readiness (`Ready`/`ready`) is not part of the
  target either.
- **The arrival instant is Go's.** That the window is judged and the nonce
  reserved when the call reaches the server, before its body is read
  (`Verifier.StatsHandler`), and that a second delivery held past collection is
  refused over the real transport and a real Postgres, is
  `libraries/hop/go/transport_postgres_test.go`, which needs
  `HOP_TEST_POSTGRES`. Python and TypeScript verify before the body by
  construction.

## Running

```sh
cd libraries/conformance/hop/go && go vet ./... && go test -race -count=1 ./...
cd libraries/hop/go && go test -run 'TestTheStampVectorsAreGosVerdicts|TestBareTokenSharedVectors' .
cd libraries/authority-client/python && uv run --no-project --with pytest --with-editable . pytest tests/test_stamps.py
cd libraries/authority-client/typescript && npm test
```
