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

Deliver the derived public key and shared replay volume as described in the
[hop admission migration](../../libraries/hop/README.md). The old shared PROOF
and warning mode cannot authorize calls.
