package roleplan

import (
	"fmt"

	modulecontract "github.com/codefly-dev/core/contracts/module"
)

// Published is Product.Callees for a product whose roles include bundles other
// modules publish (core's module contract `includes`): each module's bundles
// answered from its own published contract, read by core's reader, so the plan
// holds the product to the one declaration of what those modules' screens
// call, never a copy. It answers no call's requirement: a product whose
// bindings name calls supplies a reader of its callees' method policies.
func Published(contracts ...[]byte) (modulecontract.Callees, error) {
	out := published{}
	for _, raw := range contracts {
		contract, err := modulecontract.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("roleplan: a published contract: %w", err)
		}
		out[contract.Principal] = contract
	}
	return out, nil
}

type published map[string]*modulecontract.Contract

// Bundle implements modulecontract.Bundles.
func (p published) Bundle(module, name string) ([]modulecontract.CeilingScope, error) {
	contract, ok := p[module]
	if !ok {
		return nil, fmt.Errorf("%s publishes no contract this plan reads", module)
	}
	return contract.Bundle(name)
}

// Requires implements modulecontract.Callees: no call is answered here.
func (published) Requires(audience, call string) ([]string, error) {
	return nil, fmt.Errorf("roleplan: no method declarations of %s are read for %s", audience, call)
}
