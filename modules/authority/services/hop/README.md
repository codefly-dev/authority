# hop

The door in front of a module: it lets through only a call the authority
checked, stamped with who it is for. The decision is `pkg/business/decide`, the
local proxy face is `pkg/infra/proxy`, and the stamp a module reads is
`libraries/hop/go`. The repository README's section on the hop says how to run
it and what each refusal answers.
