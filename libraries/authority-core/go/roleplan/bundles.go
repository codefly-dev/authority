package roleplan

import (
	"fmt"

	modulecontract "github.com/codefly-dev/core/contracts/module"
)

// Published is Product.Callees for a product whose roles include bundles other
// modules publish (core's module contract `includes`): each module's bundles
// answered from its own published contract, read by core's reader, so the plan
// holds the product to the one declaration of what those modules' screens
// call, never a copy.
//
// A bundle may include another module's (robin's `run` includes the model
// gateway's `infer`), which no contract holds alone, so the contracts are read
// together through core's resolver of published contracts
// (modulecontract.PublishedContracts), the one that follows an include into
// the contract of the module publishing it. Hand in the contract of every
// module a role's includes reach, directly or through another bundle: one that
// is missing is refused naming the module and the contracts that were read. A
// single contract still answers the bundles it holds whole.
//
// It answers no call's requirement: a product whose bindings name calls
// supplies a reader of its callees' method policies.
func Published(contracts ...[]byte) (modulecontract.Callees, error) {
	parsed := make([]*modulecontract.Contract, 0, len(contracts))
	for _, raw := range contracts {
		contract, err := modulecontract.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("roleplan: a published contract: %w", err)
		}
		parsed = append(parsed, contract)
	}
	return published{modulecontract.PublishedContracts(parsed...)}, nil
}

// published is Callees over core's resolver, whose Bundle is
// modulecontract.Bundles.
type published struct{ modulecontract.Publishers }

// Requires implements modulecontract.Callees: no call is answered here.
func (published) Requires(audience, call string) ([]string, error) {
	return nil, fmt.Errorf("roleplan: no method declarations of %s are read for %s", audience, call)
}
