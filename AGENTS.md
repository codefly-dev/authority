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
   against `accounts` is a bug here. The hop side has the same rule:
   `libraries/conformance/hop/go` and `testdata/stamps.json` are the suite every
   hop verifier (Go, Python, TypeScript) must pass, never loosened for one.

## How you build here

1. **What a person exercises is a composed service.** A playground is a service
   in this repo's own workspace, started by `codefly run service`, reaching its
   API through a declared dependency and an `${endpoint:…}` reference, with
   identities from `--fixture`. A surface with no backend is a story on
   fixtures. Never a hand-written dev server, a static page beside it, a
   launcher that passes an address between processes, or a demo container. A
   module that cannot be exercised without a host is a fixture gap filed
   against the CLI or the SDK, never a harness written here.
2. **Code generated from a contract comes from `codefly generate`** — `proto`,
   `client`, `contracts`, `runnables`, `runnable-bindings`. Never this repo's
   own generator pipeline, never a hand-written client for a contract that has
   one, never a local gate on hand-generated output. A missing language, plugin
   or flag is an issue against the CLI, named in the pull request.
3. **Never hardcode anything the system resolves.** No address, port, DSN,
   credential or host name is written down — not in code, configuration,
   tests, scripts, docs, or a command you type. Addresses come from
   `codefly.For(ctx)`, from `${endpoint:…}` in configuration, from the
   generated client in a frontend, and from the suite's resolver in a test;
   secrets from `codefly config generate`; a running service's address from
   `codefly endpoint`. A value the SDK or the CLI cannot resolve, or resolves
   wrong, is a bug in that tool to fix, not a value to type or copy from a
   log: typing it encodes something true on one machine for ten minutes, and
   it fails quietly.
4. **Local first, from the lowest level; no pull request until it is
   validated on an environment.** Every change climbs this ladder in order and
   is fixed at the first rung that fails: (1) unit tests; (2) composed tests
   with the Codefly SDK (`WithDependency`) and the local authority, so
   permissions are proven, not assumed; (3) this repo's playground, exercised
   in a browser; (4) the solution run locally (`codefly run`, authority dev
   mode, the fixture people); (5) a deploy to a non-production environment
   (a dev cell) built from the local branch — no CI, no merge, and the
   only push is the gitops promotion; (6) QA and validation there. Only then
   (7) the pull request — even for an approved release. A **product or
   contract change** — a boundary, a capability, a story's promise, a
   decision, a concept, a word, a gate — is still proposed first; a technical
   change is proposed, if a contract has to move at all, only after it runs.
   Integration tests driven from the API against a running environment are the
   next rung, being built.
5. **No cluster tests.** No test — CI job, workflow step, make target, script
   or build-tagged suite — starts k3s, k3d, kind, minikube or any Kubernetes
   cluster. Authorization and admission are proven in-process against the
   authority core; a deployment is validated by `codefly run` and a hosted dev
   cell, never by a test.

