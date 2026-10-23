# authority — agent instructions

This repo is the **host authority interface** and its development implementation,
the **authority gateway**. One sentence of responsibility: declare what a module or
solution calls on its host to be issued and checked authority, and provide the one
small process that implements it on a laptop. If a change makes that sentence need
another clause, it does not belong here.

- **Owns:** the interface declaration; the authority gateway service; later, the
  authority proto, verifier and conformance kit moved from core.
- **Never contains:** a second implementation of sign-in, minting or grant
  derivation (the authority gateway links the host's packages); a store the host does
  not also use; any solution, customer or business-line name; a route of the
  product frontend; anything the CLI should do (rendering, per-process launcher
  credentials).
- **Depends on:** the host's authority packages (codefly-dev/module-saas-starter)
  and core's Work Context types until step 3 moves them here.

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
