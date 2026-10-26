# authority — agent instructions

This repo is the **host authority interface** and its development implementation,
the **local authority**. One sentence of responsibility: declare what a module or
solution calls on its host to be issued and checked authority, and provide the one
small process that implements it on a laptop. If a change makes that sentence need
another clause, it does not belong here.

- **Owns:** the interface declaration; the local authority service; later, the
  authority proto, verifier and conformance kit moved from core.
- **Never contains:** a second implementation of sign-in, minting or grant
  derivation (the local authority links the host's packages); a store the host does
  not also use; any solution, customer or business-line name; a route of the
  product frontend; anything the CLI should do (rendering, per-process launcher
  credentials).
- **Depends on today:** Core's Work Context authority/verifier, workload
  attestation and composition packages, plus this repo's libraries. The local
  service does not currently import module-saas-starter.

The local issuer now adapts requests to `libraries/authority-core/go`; its state
adapter supplies fixture roles and delivery data to that shared core. This does
not establish Accounts adoption or settle the host-package reuse requirement
above. Do not add a parallel resolver, infer that local tests prove SaaS parity,
or silently erase that obligation to match the implementation. Reconcile it with
the host owner.

Rules, governed by https://github.com/obin-ai/handbook/blob/main/concepts/boundaries.md
and the development contract at
https://github.com/obin-ai/handbook/blob/main/getting-started/development.md:

1. A playground is a composed service, never a hand-written dev server.
2. Generated code comes from `codefly generate`; never a local pipeline. Files
   ending in `_gen.go` and everything under `pkg/gen` are generated.
3. No address, port, DSN or credential is written down; the SDK resolves each one.
4. A technical change is run before it is proposed; a contract change (anything in
   `interfaces/`) is proposed in the handbook first.
5. Prove reuse before you build; the simplest thing that works; ~500 hand-written
   lines per change, stop and ask past 2,000.
6. `pkg/conformance` is the suite every implementation must pass, and core's
   conformance kit is a required test. A change that passes here and fails
   against `accounts` is a bug here.
