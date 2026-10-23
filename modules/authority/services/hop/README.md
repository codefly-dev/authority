# hop

The door in front of a module: it lets through only a call the authority
checked and that holds what its method declares, stamped with who it is for.
The decision is `pkg/business/decide`, the module's declarations are read by
`pkg/infra/policy`, the local proxy face is `pkg/infra/proxy`, and the stamp and
the declaration a module uses are `libraries/hop`. The repository README's
section on the hop says how to run it and what each refusal answers.
