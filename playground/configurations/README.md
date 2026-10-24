# The authority playground's configurations

The groups this run's services read: the edge's routes, the hop's modules, and
what the composed stores and the directory page ask for. They live here, not at
the repository root, because a module's checkout root provides its groups to
every workspace that composes it. The authority module provides none, so a
workspace composing it owns its edge and hop groups whole.

The run's proof and internal token are generated, never committed:

```bash
codefly config generate hop PROOF
codefly config generate internal-auth CODEFLY_INTERNAL_TOKEN
```
