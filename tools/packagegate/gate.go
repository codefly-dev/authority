// Package packagegate holds every module of this repository to the package a
// run delivers it under. A run admits each module that has a module-identity
// service, the host's own excepted, and names that admission by the module's
// package manifest: a module without one stops every module behind it before
// start ("declares no package manifest, so it names no release"). The manifest,
// the API contract catalog and the contract files must agree, and the contracts
// must be what `codefly generate contracts` would write from the services'
// sources today. Every method a host fronting the module receives declares
// the policy the hop enforces, so a host that consumes the policies (one that
// implements codefly.dev/composition) accepts the module.
package packagegate

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/codefly-dev/core/composition"
	"github.com/codefly-dev/core/standards"
	"gopkg.in/yaml.v3"
)

// Check reports what keeps the module at dir from being delivered as the
// package it declares; nil when nothing does.
func Check(dir string) error {
	identities, err := identityServices(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, composition.PackageManifestFileName)); errors.Is(err, fs.ErrNotExist) {
		if len(identities) == 0 {
			return nil
		}
		return fmt.Errorf("services %v declare module-identity, so a run admits the module, and it ships no %s to name its release", identities, composition.PackageManifestFileName)
	}
	manifest, err := composition.LoadPackageManifest(dir)
	if err != nil {
		return err
	}
	catalog, err := composition.LoadAPIContractCatalog(dir)
	if err != nil {
		return err
	}
	if catalog.Package != manifest.ID || catalog.Version != manifest.Version {
		return fmt.Errorf("the contract catalog names %s@%s and the package manifest %s@%s; run `codefly generate contracts`", catalog.Package, catalog.Version, manifest.ID, manifest.Version)
	}
	if err := composition.ValidatePackageAPIContracts(dir, manifest, catalog); err != nil {
		return err
	}
	var stale []error
	for _, endpoint := range catalog.Endpoints {
		if err := fresh(dir, endpoint); err != nil {
			stale = append(stale, fmt.Errorf("contract %s/%s is stale, run `codefly generate contracts`: %w", endpoint.Service, endpoint.Endpoint, err))
		}
	}
	if err := errors.Join(stale...); err != nil {
		return err
	}
	missing, err := undeclared(dir, manifest, catalog, identities)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return undeclaredError(missing)
	}
	return nil
}

// fresh compares a contract with the sources `codefly generate contracts`
// writes it from: a protobuf contract carries a copy of its service's proto
// tree beside the descriptor set, an OpenAPI contract is the service's
// document.
func fresh(dir string, endpoint composition.APIContractEndpoint) error {
	service := filepath.Join(dir, "services", endpoint.Service)
	contract := filepath.Join(dir, filepath.FromSlash(endpoint.Path))
	switch endpoint.Kind {
	case composition.APIContractKindProtobuf:
		return sameTree(filepath.Join(service, "proto"), filepath.Join(filepath.Dir(contract), "proto"))
	case composition.APIContractKindOpenAPI:
		return sameFile(filepath.Join(service, filepath.FromSlash(standards.OpenAPIPath)), contract)
	}
	return fmt.Errorf("unknown contract kind %q", endpoint.Kind)
}

func sameTree(source, copied string) error {
	want, err := tree(source)
	if err != nil {
		return err
	}
	got, err := tree(copied)
	if err != nil {
		return err
	}
	var differ []error
	for name, content := range want {
		if other, ok := got[name]; !ok {
			differ = append(differ, fmt.Errorf("%s is missing from %s", name, copied))
		} else if !bytes.Equal(content, other) {
			differ = append(differ, fmt.Errorf("%s differs from %s", path.Join(copied, name), path.Join(source, name)))
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			differ = append(differ, fmt.Errorf("%s is no longer in %s", path.Join(copied, name), source))
		}
	}
	return errors.Join(differ...)
}

func tree(root string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(file string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(root, file)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)], err = os.ReadFile(file)
		return err
	})
	return files, err
}

func sameFile(source, copied string) error {
	want, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	got, err := os.ReadFile(copied)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("%s differs from %s", copied, source)
	}
	return nil
}

// identityServices lists the module's services that declare module-identity.
func identityServices(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "services", "*", "service.codefly.yaml"))
	if err != nil {
		return nil, err
	}
	var identities []string
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var service struct {
			ModuleIdentity bool `yaml:"module-identity"`
		}
		if err := yaml.Unmarshal(data, &service); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if service.ModuleIdentity {
			identities = append(identities, filepath.Base(filepath.Dir(file)))
		}
	}
	return identities, nil
}
