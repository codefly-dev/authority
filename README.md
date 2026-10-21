# authority

**What we are doing.** Making it certain that the small gateway a developer runs
on a laptop and the real gateway in the host implement the same authority
contract, so a laptop refuses exactly where a cell refuses.

This repository holds two things, and only these two:

1. **The host authority interface** (`interfaces/authority/interface.codefly.yaml`):
   a Codefly interface declaring what a module or solution calls on the host that
   runs it. Issue a Work Context for a person, an installation or a module's own
   binding; re-address, derive a child, renew; check a revision live; the current
   installation. The host's `accounts` service implements it in full. A module
   depends on the interface, never on a service.
2. **The mini gateway** (`modules/authority/services/gateway`): the development
   implementation. One process that signs in fixture people with their roles,
   issues and verifies Work Contexts, knows the composition from the rendered
   manifests, and holds the fixture installations in memory. No accounts
   service, no stores, no platform frontend. Running a solution locally is the
   solution, the modules it consumes, and this.

**What keeps the mini gateway from being a second authority.** It links the same
packages `accounts` uses to sign in, mint and derive a module's grant from its
manifest, and the conformance kit runs against both implementations in one test.
It is a profile of the host, not a reimplementation. If a package of `accounts`
cannot be linked without its store, the package is split in the host; nothing is
copied here.

**Order of work.**

1. Declare the interface from the host's existing messages (this commit).
2. Build the mini gateway against it.
3. Move the authority proto, verifier and conformance kit out of `codefly-dev/core`
   into this repository, field numbers unchanged, fixtures proving identical bytes.

Never the third step first: nine Go modules import core's authority packages today
and a move before the interface is one more round of version skew.

**Where the thinking is.** The Platform Authority Primer (decisions 6 and 7) and the
handbook proposal that will carry them. Run it with `codefly run` from the module.
