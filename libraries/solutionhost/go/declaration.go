package solutionhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// What a module's contract declares to its host — the authority block of its
// signed manifest and the authority's document beside it — is rendered by the
// authority library (authority-core's declare), which owns that document. Core
// keeps what every reader of a contract shares: the composition's values a
// contract resolves against, and the refusal of a retired file.

// RetiredRolesFileName is the declaration a solution shipped beside its
// solution manifest before core's module contract carried roles. Nothing reads
// it; a unit still shipping one is refused naming it, so a role is never
// dropped in silence.
const RetiredRolesFileName = "roles.codefly.yaml"

// RefuseRetiredRoles refuses the module at dir when it still ships the retired
// roles declaration, saying where its contents now belong. An empty dir ships
// nothing.
func RefuseRetiredRoles(dir string) error {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, RetiredRolesFileName)
	_, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	}
	return fmt.Errorf("%s is no longer read: a unit's own kinds and its roles are declared in its %s, as scope_ceilings and roles (core's module contract); move them there and delete %s", path, modulecontract.FileName, RetiredRolesFileName)
}

// Resolver resolves a contract against a composition's configurations (every
// information as supplied, ConfigurationValues), for the environment class
// being delivered to, reading a callee's method declarations from callees
// when a binding names calls (nil when none does).
func Resolver(infos []*basev0.ConfigurationInformation, class string, callees modulecontract.Callees) func(*modulecontract.Contract) (*modulecontract.Resolved, error) {
	return func(contract *modulecontract.Contract) (*modulecontract.Resolved, error) {
		options := []modulecontract.ResolveOption{modulecontract.WithEnvironmentClass(class)}
		if callees != nil {
			options = append(options, modulecontract.WithCallees(callees))
		}
		return contract.Resolve(ConfigurationValues(infos), options...)
	}
}

// ConfigurationValues are a composition's configurations as the values a
// contract's slots resolve from: a group's records exactly as supplied, across
// every information that contributes to the group — every record, in both
// spellings of a key, a key supplied twice, a key classified public here and
// secret there — and nothing decided, since selecting among them is core's
// resolution, never a provider's (modulecontract.Values).
func ConfigurationValues(infos []*basev0.ConfigurationInformation) modulecontract.Values {
	return configurationValues(infos)
}

type configurationValues []*basev0.ConfigurationInformation

// Records implements modulecontract.Values.
func (infos configurationValues) Records(group string) ([]modulecontract.Record, error) {
	var records []modulecontract.Record
	for _, info := range infos {
		if info.GetName() != group {
			continue
		}
		for _, value := range info.GetConfigurationValues() {
			records = append(records, modulecontract.Record{Key: value.GetKey(), Value: value.GetValue(), Secret: value.GetSecret()})
		}
	}
	return records, nil
}
