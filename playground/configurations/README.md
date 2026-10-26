# The authority playground's configurations

The groups this run's services read: the edge's routes, the hop's modules, and
what the composed stores and the directory page ask for. They live here, not at
the repository root, because a module's checkout root provides its groups to
every workspace that composes it. The authority module provides none, so a
workspace composing it owns its edge and hop groups whole.

The hop's service-only signing seed and internal token are generated, never committed:

```bash
codefly config generate hop-signing SEED --service authority/hop
codefly config generate internal-auth CODEFLY_INTERNAL_TOKEN
```

Nothing else about the hop is configured here. The local authority derives the
public half of that seed and publishes it in `Keys` (`admission_keys`), which
every module behind the hop already reads, so no verification key is written by
hand ([hop admission migration](../../libraries/hop/README.md), "Delivering the
verification key").

No replay volume is configured here any more. Admission reservations live in the
console's own Postgres (`modules/console/services/store`), because Codefly
delivers a store and does not deliver a shared volume; an absolute path to
per-pod storage looks identical to a shared mount and silently becomes a
per-replica store. Outside a local run the verifier now refuses a store that
does not declare itself shared.

The old shared PROOF and warning mode cannot authorize calls.
